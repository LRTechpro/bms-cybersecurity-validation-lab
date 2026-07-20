from .diagnostic_model import (
    DiagnosticRequest,
    DiagnosticService,
    DiagnosticSession,
)
from .diagnostic_validator import DiagnosticValidator


def req(
    service: DiagnosticService,
    timestamp_s: float = 1.0,
    role: str = "service",
    authenticated: bool = True,
    target_session: DiagnosticSession | None = None,
    key_valid: bool | None = None,
) -> DiagnosticRequest:
    return DiagnosticRequest(
        service=service,
        role=role,
        timestamp_s=timestamp_s,
        authenticated=authenticated,
        target_session=target_session,
        key_valid=key_valid,
    )


def enter_programming_and_unlock(validator: DiagnosticValidator) -> None:
    assert validator.process_request(
        req(
            DiagnosticService.SESSION_CONTROL,
            target_session=DiagnosticSession.PROGRAMMING,
        )
    ).status == "PASS"
    assert validator.process_request(
        req(DiagnosticService.SECURITY_ACCESS, key_valid=True)
    ).status == "PASS"


def test_read_allowed_data_in_default_session_passes() -> None:
    result = DiagnosticValidator().process_request(
        req(DiagnosticService.READ_DATA, role="monitor")
    )
    assert result.status == "PASS"


def test_write_configuration_in_default_session_fails() -> None:
    result = DiagnosticValidator().process_request(
        req(DiagnosticService.WRITE_CONFIGURATION)
    )
    assert result.status == "FAIL"


def test_programming_request_before_security_unlock_fails() -> None:
    validator = DiagnosticValidator()
    validator.process_request(
        req(
            DiagnosticService.SESSION_CONTROL,
            target_session=DiagnosticSession.PROGRAMMING,
        )
    )
    result = validator.process_request(req(DiagnosticService.REQUEST_DOWNLOAD))
    assert result.status == "FAIL"
    assert any("unlock" in reason.lower() for reason in result.reasons)


def test_repeated_invalid_keys_activate_lockout() -> None:
    validator = DiagnosticValidator(max_failed_attempts=3, lockout_duration_s=30)
    for second in (1.0, 2.0, 3.0):
        result = validator.process_request(
            req(
                DiagnosticService.SECURITY_ACCESS,
                timestamp_s=second,
                key_valid=False,
            )
        )
    assert result.status == "FAIL"
    assert any("lockout" in reason.lower() for reason in result.reasons)
    locked = validator.process_request(
        req(DiagnosticService.READ_DATA, timestamp_s=4.0)
    )
    assert locked.status == "FAIL"


def test_reset_during_update_transfer_fails() -> None:
    validator = DiagnosticValidator()
    enter_programming_and_unlock(validator)
    assert validator.process_request(
        req(DiagnosticService.REQUEST_DOWNLOAD)
    ).status == "PASS"
    result = validator.process_request(req(DiagnosticService.ECU_RESET))
    assert result.status == "FAIL"
    assert any("active update" in reason.lower() for reason in result.reasons)


def test_correct_secure_programming_sequence_passes() -> None:
    validator = DiagnosticValidator()
    enter_programming_and_unlock(validator)
    sequence = (
        DiagnosticService.REQUEST_DOWNLOAD,
        DiagnosticService.TRANSFER_DATA,
        DiagnosticService.TRANSFER_EXIT,
        DiagnosticService.VERIFY_IMAGE,
        DiagnosticService.ECU_RESET,
    )
    results = [validator.process_request(req(service)) for service in sequence]
    assert all(result.status == "PASS" for result in results)


def test_out_of_order_programming_service_fails() -> None:
    validator = DiagnosticValidator()
    enter_programming_and_unlock(validator)
    result = validator.process_request(req(DiagnosticService.TRANSFER_DATA))
    assert result.status == "FAIL"
    assert result.response_code == "NRC-0x24"
