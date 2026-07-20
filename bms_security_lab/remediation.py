from dataclasses import dataclass

from .finding import Finding, FindingStatus


@dataclass(frozen=True)
class RemediationAction:
    remediation_id: str
    finding_id: str
    requirement_id: str
    action: str
    component: str
    owner: str
    applied_code_version: str


@dataclass(frozen=True)
class RetestRecord:
    test_id: str
    status: str
    evidence_record_hash: str
    code_version: str


class RemediationWorkflow:
    """Keep findings open until a new linked retest passes."""

    def apply(
        self,
        finding: Finding,
        remediation: RemediationAction,
    ) -> None:
        if remediation.finding_id != finding.finding_id:
            raise ValueError("Remediation does not reference this finding.")
        if remediation.requirement_id != finding.requirement_id:
            raise ValueError("Remediation requirement does not match finding.")
        if not remediation.owner.strip() or not remediation.action.strip():
            raise ValueError("Remediation action and owner are required.")

        finding.remediation_id = remediation.remediation_id
        finding.status = FindingStatus.REMEDIATED_PENDING_RETEST

    def record_retest(
        self,
        finding: Finding,
        retest: RetestRecord,
    ) -> None:
        if finding.status is not FindingStatus.REMEDIATED_PENDING_RETEST:
            raise ValueError("Finding must be remediated before retest closure.")
        if retest.status == "PASS":
            finding.status = FindingStatus.CLOSED
            finding.retest_evidence_hash = retest.evidence_record_hash
        else:
            finding.status = FindingStatus.OPEN
            finding.retest_evidence_hash = retest.evidence_record_hash
