import json

from .evidence_report import EvidenceRecord, EvidenceReportBuilder, EvidenceStore
from .finding import FindingRegistry, FindingStatus
from .remediation import RemediationAction, RemediationWorkflow, RetestRecord


def record(test_id: str, status: str, observed: str) -> EvidenceRecord:
    return EvidenceRecord(
        campaign_id="BMS-CAMPAIGN-001",
        test_id=test_id,
        tara_id="TARA-001",
        cybersecurity_goal_id="CG-001",
        requirement_id="BMS-SEC-SEN-001",
        architecture_control_ids=("AC-001", "AC-003"),
        input_data={"soc_percent": 145.0},
        preconditions={"mode": "simulation"},
        expected_result="Reject invalid SOC",
        observed_result=observed,
        status=status,
        reasons=("SOC is outside configured range.",) if status == "FAIL" else (),
        timestamp_s=100.0,
        environment="pure-python",
        code_version="test-sha",
        evidence_paths=("evidence/input.json",),
    )


def test_passing_test_creates_complete_evidence_record(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    stored = store.append(record("EVID-001", "PASS", "Valid input accepted"))
    assert stored.record_hash
    assert stored.previous_record_hash == "GENESIS"
    assert stored.tara_id == "TARA-001"
    assert stored.architecture_control_ids == ("AC-001", "AC-003")
    assert store.verify_chain() is True


def test_failed_spoofing_test_creates_finding(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    evidence = store.append(record("EVID-002", "FAIL", "Spoofed SOC rejected"))
    registry = FindingRegistry()
    finding = registry.create_or_link(
        root_cause_key="SOC-INPUT-VALIDATION",
        title="Spoofed SOC accepted by vulnerable baseline",
        impact="HIGH",
        exploitability="MEDIUM",
        requirement_id=evidence.requirement_id,
        recommended_control="Validate before trusted state update",
        responsible_component="Input Trust Gate",
        evidence_record_hash=evidence.record_hash,
    )
    assert finding.status is FindingStatus.OPEN
    assert finding.severity == "HIGH"
    assert evidence.record_hash in finding.evidence_record_hashes


def test_duplicate_failure_links_to_existing_finding(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    first = store.append(record("EVID-003-A", "FAIL", "First occurrence"))
    second = store.append(record("EVID-003-B", "FAIL", "Duplicate occurrence"))
    registry = FindingRegistry()
    finding_one = registry.create_or_link(
        "SOC-ROOT-CAUSE",
        "SOC validation weakness",
        "HIGH",
        "MEDIUM",
        first.requirement_id,
        "Input validation",
        "BMS validator",
        first.record_hash,
    )
    finding_two = registry.create_or_link(
        "SOC-ROOT-CAUSE",
        "SOC validation weakness",
        "HIGH",
        "MEDIUM",
        second.requirement_id,
        "Input validation",
        "BMS validator",
        second.record_hash,
    )
    assert finding_one is finding_two
    assert len(registry.all_findings()) == 1
    assert len(finding_one.evidence_record_hashes) == 2


def test_remediation_does_not_close_finding_before_retest(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    evidence = store.append(record("EVID-004", "FAIL", "Weakness reproduced"))
    finding = FindingRegistry().create_or_link(
        "ROOT",
        "Validation weakness",
        "HIGH",
        "MEDIUM",
        evidence.requirement_id,
        "Add guard",
        "validator.py",
        evidence.record_hash,
    )
    remediation = RemediationAction(
        remediation_id="REM-001",
        finding_id=finding.finding_id,
        requirement_id=finding.requirement_id,
        action="Reject unvalidated state update",
        component="validator.py",
        owner="security-engineer",
        applied_code_version="fixed-sha",
    )
    RemediationWorkflow().apply(finding, remediation)
    assert finding.status is FindingStatus.REMEDIATED_PENDING_RETEST


def test_passing_retest_closes_finding_with_evidence(tmp_path) -> None:
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    failure = store.append(record("EVID-005-A", "FAIL", "Weakness reproduced"))
    retest_evidence = store.append(record("EVID-005-B", "PASS", "Fix verified"))
    finding = FindingRegistry().create_or_link(
        "ROOT",
        "Validation weakness",
        "HIGH",
        "MEDIUM",
        failure.requirement_id,
        "Add guard",
        "validator.py",
        failure.record_hash,
    )
    workflow = RemediationWorkflow()
    workflow.apply(
        finding,
        RemediationAction(
            remediation_id="REM-002",
            finding_id=finding.finding_id,
            requirement_id=finding.requirement_id,
            action="Implement complete input gate",
            component="validator.py",
            owner="security-engineer",
            applied_code_version="fixed-sha",
        ),
    )
    workflow.record_retest(
        finding,
        RetestRecord(
            test_id="EVID-005-B",
            status="PASS",
            evidence_record_hash=retest_evidence.record_hash,
            code_version="fixed-sha",
        ),
    )
    assert finding.status is FindingStatus.CLOSED
    assert finding.retest_evidence_hash == retest_evidence.record_hash


def test_report_generation_after_restart_retains_prior_evidence(tmp_path) -> None:
    path = tmp_path / "evidence.jsonl"
    original = EvidenceStore(path)
    original.append(record("EVID-006-A", "PASS", "First result"))
    original.append(record("EVID-006-B", "FAIL", "Second result"))
    digest_before = original.campaign_digest()

    reloaded = EvidenceStore(path)
    assert len(reloaded.records) == 2
    assert reloaded.verify_chain() is True
    assert reloaded.campaign_digest() == digest_before

    builder = EvidenceReportBuilder(reloaded)
    json_path = builder.write_json(tmp_path / "report.json")
    markdown_path = builder.write_markdown(tmp_path / "report.md")
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["campaign_digest"] == digest_before
    assert report["record_count"] == 2
    assert "EVID-006-B" in markdown_path.read_text(encoding="utf-8")
