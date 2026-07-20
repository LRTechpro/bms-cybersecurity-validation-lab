from dataclasses import dataclass, field
from enum import Enum


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    REMEDIATED_PENDING_RETEST = "REMEDIATED_PENDING_RETEST"
    CLOSED = "CLOSED"


@dataclass
class Finding:
    finding_id: str
    root_cause_key: str
    title: str
    severity: str
    impact: str
    exploitability: str
    requirement_id: str
    recommended_control: str
    responsible_component: str
    status: FindingStatus = FindingStatus.OPEN
    evidence_record_hashes: list[str] = field(default_factory=list)
    remediation_id: str | None = None
    retest_evidence_hash: str | None = None


class FindingRegistry:
    """Create one finding per root cause and link duplicate failures."""

    def __init__(self) -> None:
        self._findings_by_root_cause: dict[str, Finding] = {}

    def create_or_link(
        self,
        root_cause_key: str,
        title: str,
        impact: str,
        exploitability: str,
        requirement_id: str,
        recommended_control: str,
        responsible_component: str,
        evidence_record_hash: str,
    ) -> Finding:
        finding = self._findings_by_root_cause.get(root_cause_key)
        if finding is None:
            finding = Finding(
                finding_id=f"FND-{len(self._findings_by_root_cause) + 1:03d}",
                root_cause_key=root_cause_key,
                title=title,
                severity=self._severity(impact, exploitability),
                impact=impact,
                exploitability=exploitability,
                requirement_id=requirement_id,
                recommended_control=recommended_control,
                responsible_component=responsible_component,
            )
            self._findings_by_root_cause[root_cause_key] = finding

        if evidence_record_hash not in finding.evidence_record_hashes:
            finding.evidence_record_hashes.append(evidence_record_hash)
        return finding

    def all_findings(self) -> tuple[Finding, ...]:
        return tuple(self._findings_by_root_cause.values())

    @staticmethod
    def _severity(impact: str, exploitability: str) -> str:
        impact_level = impact.upper()
        feasibility = exploitability.upper()
        if impact_level == "HIGH" and feasibility in {"HIGH", "MEDIUM"}:
            return "HIGH"
        if impact_level in {"HIGH", "MEDIUM"} and feasibility != "LOW":
            return "MEDIUM"
        return "LOW"
