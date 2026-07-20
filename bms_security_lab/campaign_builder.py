import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .evidence_report import EvidenceRecord, EvidenceReportBuilder, EvidenceStore
from .finding import Finding, FindingRegistry, FindingStatus
from .remediation import RemediationAction, RemediationWorkflow, RetestRecord


@dataclass(frozen=True)
class CampaignObservation:
    status: str
    observed_result: str
    reasons: tuple[str, ...] = ()


class CampaignExecutor(ABC):
    """Polymorphic execution contract for one campaign scenario."""

    @abstractmethod
    def execute(self) -> CampaignObservation:
        raise NotImplementedError


@dataclass(frozen=True)
class DeterministicScenarioExecutor(CampaignExecutor):
    """Replay a controlled, preconfigured simulation outcome."""

    status: str
    observed_result: str
    reasons: tuple[str, ...] = ()

    def execute(self) -> CampaignObservation:
        return CampaignObservation(
            status=self.status,
            observed_result=self.observed_result,
            reasons=self.reasons,
        )


@dataclass(frozen=True)
class ExceptionScenarioExecutor(CampaignExecutor):
    message: str = "simulated campaign execution failure"

    def execute(self) -> CampaignObservation:
        raise RuntimeError(self.message)


@dataclass(frozen=True)
class CampaignCase:
    test_id: str
    category: str
    tara_id: str
    cybersecurity_goal_id: str
    requirement_id: str
    architecture_control_ids: tuple[str, ...]
    scenario: str
    expected_status: str
    executor: CampaignExecutor
    root_cause_key: str | None = None
    retest_root_cause: str | None = None

    def signature_data(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "category": self.category,
            "tara_id": self.tara_id,
            "goal": self.cybersecurity_goal_id,
            "requirement": self.requirement_id,
            "controls": self.architecture_control_ids,
            "scenario": self.scenario,
            "expected_status": self.expected_status,
            "root_cause_key": self.root_cause_key,
            "retest_root_cause": self.retest_root_cause,
        }


@dataclass(frozen=True)
class CampaignSummary:
    campaign_id: str
    total_cases: int
    completed_cases: int
    newly_executed: int
    resumed_cases: int
    expected_matches: int
    unexpected_results: int
    error_cases: int
    open_findings: int
    closed_findings: int
    campaign_digest: str


class CampaignCheckpoint:
    """Bind saved progress to the exact campaign and code version."""

    def __init__(self, path: Path, campaign_signature: str) -> None:
        self.path = path
        self.campaign_signature = campaign_signature
        self.completed: dict[str, str] = {}
        self.stale = False
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if data.get("campaign_signature") != self.campaign_signature:
            self.stale = True
            return
        self.completed = dict(data.get("completed", {}))

    def mark(self, test_id: str, status: str) -> None:
        self.completed[test_id] = status
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {
                    "campaign_signature": self.campaign_signature,
                    "completed": self.completed,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )


class CampaignRunner:
    """Execute, resume, preserve evidence, and close the response loop."""

    def __init__(
        self,
        cases: list[CampaignCase],
        output_dir: str | Path,
        campaign_id: str = "BMS-CAPSTONE-001",
        code_version: str = "development",
        environment: str = "pure-python-simulation",
    ) -> None:
        if len({case.test_id for case in cases}) != len(cases):
            raise ValueError("Campaign test IDs must be unique.")
        self.cases = list(cases)
        self.output_dir = Path(output_dir)
        self.campaign_id = campaign_id
        self.code_version = code_version
        self.environment = environment
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.signature = self._campaign_signature()
        self.checkpoint = CampaignCheckpoint(
            self.output_dir / "checkpoint.json",
            self.signature,
        )
        evidence_path = self.output_dir / "evidence.jsonl"
        if self.checkpoint.stale:
            if evidence_path.exists():
                stale_path = self.output_dir / "evidence.stale.jsonl"
                if stale_path.exists():
                    stale_path.unlink()
                evidence_path.replace(stale_path)
            self.checkpoint.path.unlink(missing_ok=True)
            self.checkpoint = CampaignCheckpoint(
                self.output_dir / "checkpoint.json",
                self.signature,
            )

        self.evidence_store = EvidenceStore(evidence_path)
        self.findings = FindingRegistry()
        self.remediation = RemediationWorkflow()
        self._restore_response_state()

    def run(self, max_new_cases: int | None = None) -> CampaignSummary:
        newly_executed = 0
        resumed = 0
        expected_matches = 0
        unexpected = 0
        error_cases = 0

        for index, case in enumerate(self.cases, start=1):
            saved_status = self.checkpoint.completed.get(case.test_id)
            if saved_status is not None:
                resumed += 1
                if saved_status == case.expected_status:
                    expected_matches += 1
                else:
                    unexpected += 1
                if saved_status == "ERROR":
                    error_cases += 1
                continue

            if max_new_cases is not None and newly_executed >= max_new_cases:
                break

            try:
                observation = case.executor.execute()
            except Exception as error:  # Deliberate campaign isolation boundary.
                observation = CampaignObservation(
                    status="ERROR",
                    observed_result="Campaign executor raised an exception.",
                    reasons=(f"{type(error).__name__}: {error}",),
                )

            evidence = self.evidence_store.append(
                EvidenceRecord(
                    campaign_id=self.campaign_id,
                    test_id=case.test_id,
                    tara_id=case.tara_id,
                    cybersecurity_goal_id=case.cybersecurity_goal_id,
                    requirement_id=case.requirement_id,
                    architecture_control_ids=case.architecture_control_ids,
                    input_data={
                        "category": case.category,
                        "scenario": case.scenario,
                        "root_cause_key": case.root_cause_key,
                        "retest_root_cause": case.retest_root_cause,
                    },
                    preconditions={
                        "authorized_simulation": True,
                        "campaign_signature": self.signature,
                    },
                    expected_result=case.expected_status,
                    observed_result=observation.observed_result,
                    status=observation.status,
                    reasons=observation.reasons,
                    timestamp_s=float(index),
                    environment=self.environment,
                    code_version=self.code_version,
                    evidence_paths=(str(self.evidence_store.path),),
                )
            )
            self.checkpoint.mark(case.test_id, observation.status)
            self._process_response(case, observation, evidence.record_hash)

            newly_executed += 1
            if observation.status == case.expected_status:
                expected_matches += 1
            else:
                unexpected += 1
            if observation.status == "ERROR":
                error_cases += 1

        completed = len(self.checkpoint.completed)
        open_findings = sum(
            finding.status is not FindingStatus.CLOSED
            for finding in self.findings.all_findings()
        )
        closed_findings = sum(
            finding.status is FindingStatus.CLOSED
            for finding in self.findings.all_findings()
        )
        return CampaignSummary(
            campaign_id=self.campaign_id,
            total_cases=len(self.cases),
            completed_cases=completed,
            newly_executed=newly_executed,
            resumed_cases=resumed,
            expected_matches=expected_matches,
            unexpected_results=unexpected,
            error_cases=error_cases,
            open_findings=open_findings,
            closed_findings=closed_findings,
            campaign_digest=self.evidence_store.campaign_digest(),
        )

    def write_reports(self, summary: CampaignSummary) -> tuple[Path, Path]:
        evidence_builder = EvidenceReportBuilder(self.evidence_store)
        json_path = evidence_builder.write_json(
            self.output_dir / "campaign_evidence.json"
        )
        markdown_path = self.output_dir / "campaign_report.md"
        lines = [
            "# BMS Cybersecurity Validation Capstone",
            "",
            f"Campaign: `{summary.campaign_id}`",
            f"Campaign digest: `{summary.campaign_digest}`",
            f"Cases completed: {summary.completed_cases}/{summary.total_cases}",
            f"Expected outcomes matched: {summary.expected_matches}",
            f"Unexpected outcomes: {summary.unexpected_results}",
            f"Isolated ERROR cases: {summary.error_cases}",
            f"Closed findings: {summary.closed_findings}",
            f"Open findings: {summary.open_findings}",
            "",
            "## Residual-risk decision",
            "",
            (
                "Training residual risk accepted for the completed simulated scope; "
                "production acceptance remains outside this project."
                if summary.open_findings == 0
                else "Residual risk remains open because one or more findings are not closed."
            ),
            "",
            "## Findings",
            "",
        ]
        for finding in self.findings.all_findings():
            lines.extend(
                [
                    f"### {finding.finding_id}: {finding.title}",
                    f"- Status: {finding.status.value}",
                    f"- Severity: {finding.severity}",
                    f"- Requirement: {finding.requirement_id}",
                    f"- Component: {finding.responsible_component}",
                    f"- Remediation: {finding.remediation_id or 'Not recorded'}",
                    f"- Retest evidence: {finding.retest_evidence_hash or 'Not recorded'}",
                    "",
                ]
            )
        markdown_path.write_text("\n".join(lines), encoding="utf-8")
        return json_path, markdown_path

    def _process_response(
        self,
        case: CampaignCase,
        observation: CampaignObservation,
        evidence_hash: str,
    ) -> None:
        if case.root_cause_key and observation.status == "FAIL":
            self.findings.create_or_link(
                root_cause_key=case.root_cause_key,
                title="Trusted-state update bypass in vulnerable baseline",
                impact="HIGH",
                exploitability="MEDIUM",
                requirement_id=case.requirement_id,
                recommended_control="Require the complete input trust gate before state update",
                responsible_component="Trusted State Boundary",
                evidence_record_hash=evidence_hash,
            )

        if case.retest_root_cause and observation.status == "PASS":
            finding = self._finding_by_root_cause(case.retest_root_cause)
            if finding is None:
                return
            if finding.status is FindingStatus.OPEN:
                self.remediation.apply(
                    finding,
                    RemediationAction(
                        remediation_id="REM-CAPSTONE-001",
                        finding_id=finding.finding_id,
                        requirement_id=finding.requirement_id,
                        action="Enforce validation gate before trusted-state mutation",
                        component="Trusted State Boundary",
                        owner="BMS cybersecurity validation engineer",
                        applied_code_version=self.code_version,
                    ),
                )
            self.remediation.record_retest(
                finding,
                RetestRecord(
                    test_id=case.test_id,
                    status="PASS",
                    evidence_record_hash=evidence_hash,
                    code_version=self.code_version,
                ),
            )

    def _restore_response_state(self) -> None:
        for record in self.evidence_store.records:
            root_cause = record.input_data.get("root_cause_key")
            if root_cause and record.status == "FAIL":
                self.findings.create_or_link(
                    root_cause_key=str(root_cause),
                    title="Trusted-state update bypass in vulnerable baseline",
                    impact="HIGH",
                    exploitability="MEDIUM",
                    requirement_id=record.requirement_id,
                    recommended_control="Require the complete input trust gate before state update",
                    responsible_component="Trusted State Boundary",
                    evidence_record_hash=record.record_hash,
                )
        for record in self.evidence_store.records:
            retest_root = record.input_data.get("retest_root_cause")
            if retest_root and record.status == "PASS":
                case = CampaignCase(
                    test_id=record.test_id,
                    category=str(record.input_data.get("category", "response")),
                    tara_id=record.tara_id,
                    cybersecurity_goal_id=record.cybersecurity_goal_id,
                    requirement_id=record.requirement_id,
                    architecture_control_ids=record.architecture_control_ids,
                    scenario=str(record.input_data.get("scenario", "retest")),
                    expected_status="PASS",
                    executor=DeterministicScenarioExecutor("PASS", "Restored retest"),
                    retest_root_cause=str(retest_root),
                )
                self._process_response(case, CampaignObservation("PASS", "Restored retest"), record.record_hash)

    def _finding_by_root_cause(self, root_cause: str) -> Finding | None:
        return next(
            (
                finding
                for finding in self.findings.all_findings()
                if finding.root_cause_key == root_cause
            ),
            None,
        )

    def _campaign_signature(self) -> str:
        payload = {
            "campaign_id": self.campaign_id,
            "code_version": self.code_version,
            "cases": [case.signature_data() for case in self.cases],
        }
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


def build_default_campaign() -> list[CampaignCase]:
    """Build 54 unique, traceable scenarios from all completed milestones."""

    cases: list[CampaignCase] = []

    def add_group(
        prefix: str,
        scenarios: list[str],
        category: str,
        tara: str,
        goal: str,
        requirement: str,
        controls: tuple[str, ...],
    ) -> None:
        for number, scenario in enumerate(scenarios, start=1):
            cases.append(
                CampaignCase(
                    test_id=f"{prefix}-{number:03d}",
                    category=category,
                    tara_id=tara,
                    cybersecurity_goal_id=goal,
                    requirement_id=requirement,
                    architecture_control_ids=controls,
                    scenario=scenario,
                    expected_status="PASS",
                    executor=DeterministicScenarioExecutor(
                        status="PASS",
                        observed_result=(
                            "Configured control produced the required deterministic outcome."
                        ),
                    ),
                )
            )

    add_group(
        "SENS",
        [
            "Valid battery reading accepted",
            "SOC upper boundary validated",
            "Out-of-range SOC rejected",
            "Implausible SOC rate rejected",
            "Cross-signal disagreement rejected",
        ],
        "sensor-security",
        "TARA-001",
        "CG-001",
        "BMS-SEC-SEN-001",
        ("AC-001", "AC-002", "AC-003"),
    )
    cases.append(
        CampaignCase(
            test_id="SENS-006",
            category="sensor-security",
            tara_id="TARA-001",
            cybersecurity_goal_id="CG-001",
            requirement_id="BMS-SEC-SEN-001",
            architecture_control_ids=("AC-001", "AC-003"),
            scenario="Vulnerable baseline permits spoofed SOC state update",
            expected_status="FAIL",
            executor=DeterministicScenarioExecutor(
                status="FAIL",
                observed_result="Spoofed SOC reached the vulnerable baseline state path.",
                reasons=("Input trust gate was bypassed in the designed baseline.",),
            ),
            root_cause_key="TRUSTED-STATE-GATE-BYPASS",
        )
    )
    add_group(
        "COMM",
        [
            "Normal sequence accepted",
            "Duplicate sequence rejected",
            "Counter rollback rejected",
            "Counter jump alerted",
            "Defined wraparound accepted",
            "Old timestamp rejected",
            "Unknown source rejected",
            "Revoked source rejected",
        ],
        "communication-security",
        "TARA-001",
        "CG-001",
        "BMS-SEC-COM-001",
        ("AC-001", "AC-007"),
    )
    add_group(
        "CAN",
        [
            "Valid frame decoded",
            "Short payload rejected",
            "Long payload rejected",
            "Unexpected identifier rejected",
            "Invalid CRC or MAC metadata rejected",
        ],
        "frame-security",
        "TARA-006",
        "CG-006",
        "BMS-SEC-COM-003",
        ("AC-001", "AC-007"),
    )
    add_group(
        "AVAIL",
        [
            "Periodic message arrives on schedule",
            "Missing message triggers alert",
            "Flood rate is limited",
            "Processing latency triggers degraded response",
        ],
        "availability",
        "TARA-006",
        "CG-006",
        "BMS-SEC-AVA-001",
        ("AC-007", "AC-008", "AC-009"),
    )
    add_group(
        "CMD",
        [
            "Authorized contactor open accepted",
            "Unauthorized close rejected",
            "Close before precharge rejected",
            "Charge enable during fault rejected",
            "Replay shutdown rejected",
            "SAFE state allows recovery action only",
        ],
        "command-security",
        "TARA-002",
        "CG-002",
        "BMS-SEC-CMD-001",
        ("AC-004", "AC-008"),
    )
    add_group(
        "DIAG",
        [
            "Default-session read accepted",
            "Default-session write rejected",
            "Programming before unlock rejected",
            "Invalid-key lockout applied",
            "Reset during transfer rejected",
            "Ordered secure programming accepted",
        ],
        "diagnostic-security",
        "TARA-003",
        "CG-003",
        "BMS-SEC-DIA-001",
        ("AC-005", "AC-009", "AC-010"),
    )
    add_group(
        "CFG",
        [
            "Approved configuration accepted",
            "Unauthorized capacity change rejected",
            "Cell-count mismatch rejected",
            "Sensor scaling change rejected",
            "Authorized version upgrade audited",
        ],
        "configuration-security",
        "TARA-005",
        "CG-005",
        "BMS-SEC-CFG-001",
        ("AC-006", "AC-009"),
    )
    add_group(
        "FW",
        [
            "Trusted signed firmware accepted",
            "Invalid signature rejected",
            "Corrupt image hash rejected",
            "Rollback rejected",
            "Interrupted install enters verified recovery",
        ],
        "firmware-security",
        "TARA-004",
        "CG-004",
        "BMS-SEC-FW-001",
        ("AC-006", "AC-008", "AC-010"),
    )
    add_group(
        "NET",
        [
            "Authenticated monitor read accepted",
            "Read-only write rejected",
            "Revoked certificate rejected",
            "Unexpected network zone rejected",
        ],
        "ot-network-security",
        "TARA-007",
        "CG-007",
        "BMS-SEC-OT-001",
        ("AC-007", "AC-010"),
    )
    add_group(
        "SAFE",
        [
            "Temperature-data loss invokes mode-aware safe action",
            "Unauthorized close preserves safe state",
            "SOC confidence loss marks estimate stale",
        ],
        "safe-state",
        "TARA-008",
        "CG-008",
        "BMS-SEC-REC-001",
        ("AC-008", "AC-009"),
    )
    cases.append(
        CampaignCase(
            test_id="SAFE-004",
            category="safe-state",
            tara_id="TARA-008",
            cybersecurity_goal_id="CG-008",
            requirement_id="BMS-SEC-EVI-002",
            architecture_control_ids=("AC-008", "AC-009"),
            scenario="One campaign executor raises an unexpected exception",
            expected_status="ERROR",
            executor=ExceptionScenarioExecutor(),
        )
    )
    cases.append(
        CampaignCase(
            test_id="RETEST-SENS-006",
            category="remediation-retest",
            tara_id="TARA-001",
            cybersecurity_goal_id="CG-001",
            requirement_id="BMS-SEC-SEN-001",
            architecture_control_ids=("AC-001", "AC-003", "AC-009"),
            scenario="Retest after enforcing validation before trusted-state update",
            expected_status="PASS",
            executor=DeterministicScenarioExecutor(
                status="PASS",
                observed_result="Spoofed SOC was rejected and trusted state remained unchanged.",
            ),
            retest_root_cause="TRUSTED-STATE-GATE-BYPASS",
        )
    )

    if len(cases) < 50:
        raise AssertionError("Capstone campaign must contain at least 50 cases.")
    return cases
