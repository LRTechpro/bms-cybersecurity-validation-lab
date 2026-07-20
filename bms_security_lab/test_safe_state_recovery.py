from dataclasses import dataclass

from .recovery_manager import RecoveryManager
from .safe_state import OperatingMode, SafeAction, SafeStateController
from .test_runner import TestRunner


@dataclass
class FakeResult:
    status: str


class FakeCase:
    def __init__(self, test_id: str, status: str = "PASS", raises: bool = False) -> None:
        self.test_id = test_id
        self.status = status
        self.raises = raises

    def run(self) -> FakeResult:
        if self.raises:
            raise RuntimeError("simulated validator failure")
        return FakeResult(self.status)


class MemoryCheckpoint:
    def __init__(self) -> None:
        self.statuses: dict[str, str] = {}

    def get_status(self, test_id: str) -> str | None:
        return self.statuses.get(test_id)

    def mark_completed(self, test_id: str, status: str) -> None:
        self.statuses[test_id] = status


def test_validator_exception_is_isolated_and_campaign_continues() -> None:
    checkpoint = MemoryCheckpoint()
    runner = TestRunner(
        test_cases=[
            FakeCase("SAFE-001-A", raises=True),
            FakeCase("SAFE-001-B", status="PASS"),
        ],
        checkpoint_store=checkpoint,
    )
    results = runner.run_all()
    assert results == [("SAFE-001-A", "ERROR"), ("SAFE-001-B", "PASS")]
    assert "SAFE-001-A" in runner.errors


def test_loss_of_critical_temperature_data_records_safe_actions() -> None:
    decision = SafeStateController().decide(
        "CRITICAL_TEMPERATURE_DATA_LOSS",
        OperatingMode.DRIVING,
        prior_soc_percent=60.0,
    )
    assert SafeAction.PRESERVE_COOLING in decision.actions
    assert SafeAction.LIMIT_POWER in decision.actions
    assert SafeAction.PRESERVE_EVIDENCE in decision.actions


def test_unauthorized_close_request_keeps_system_safe() -> None:
    decision = SafeStateController().decide(
        "UNAUTHORIZED_CONTACTOR_CLOSE",
        OperatingMode.PARKED,
    )
    assert SafeAction.BLOCK_STATE_UPDATE in decision.actions
    assert SafeAction.REQUEST_CONTACTOR_OPEN in decision.actions


def test_soc_confidence_loss_marks_estimate_stale_without_restoring_it() -> None:
    decision = SafeStateController().decide(
        "SOC_CONFIDENCE_LOSS",
        OperatingMode.DRIVING,
        prior_soc_percent=72.0,
    )
    assert decision.soc_valid is False
    assert decision.prior_soc_for_audit == 72.0
    assert SafeAction.MARK_SOC_STALE in decision.actions
    assert SafeAction.LIMIT_POWER in decision.actions
    assert SafeAction.REQUEST_CONTACTOR_OPEN not in decision.actions


def test_unauthenticated_recovery_request_fails() -> None:
    decision = RecoveryManager().request_recovery(
        actor="unknown",
        role="service",
        authenticated=False,
        conditions_clear=True,
        evidence_preserved=True,
    )
    assert decision.status == "FAIL"
    assert decision.transition_allowed is False


def test_authorized_recovery_after_conditions_clear_passes() -> None:
    manager = RecoveryManager()
    decision = manager.request_recovery(
        actor="authorized-tech",
        role="service",
        authenticated=True,
        conditions_clear=True,
        evidence_preserved=True,
    )
    assert decision.status == "PASS"
    assert decision.transition_allowed is True
    assert manager.events == ["RECOVERY_AUTHORIZED:authorized-tech"]
