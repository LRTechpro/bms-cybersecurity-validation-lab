from .command_model import BMSOperatingState, CommandRequest, CommandType
from .command_validator import CommandValidator


CONTROL_SOURCE = 0x200
SENSOR_SOURCE = 0x180


def make_validator() -> CommandValidator:
    return CommandValidator(
        permissions_by_source={
            CONTROL_SOURCE: set(CommandType),
            SENSOR_SOURCE: {CommandType.OPEN_CONTACTOR},
        }
    )


def request(
    command_type: CommandType,
    source_id: int = CONTROL_SOURCE,
    counter: int = 1,
    authenticated: bool = True,
    value: float | None = None,
) -> CommandRequest:
    return CommandRequest(
        command_type=command_type,
        source_id=source_id,
        sequence_counter=counter,
        authenticated=authenticated,
        timestamp_s=10.0,
        requested_value=value,
    )


def test_authorized_contactor_open_in_fault_passes() -> None:
    result = make_validator().validate(
        request(CommandType.OPEN_CONTACTOR),
        BMSOperatingState.FAULT,
        now_s=10.5,
    )
    assert result.status == "PASS"


def test_unauthorized_contactor_close_fails() -> None:
    result = make_validator().validate(
        request(CommandType.CLOSE_CONTACTOR, source_id=SENSOR_SOURCE),
        BMSOperatingState.PRECHARGE,
        now_s=10.5,
        precharge_complete=True,
    )
    assert result.status == "FAIL"
    assert any("not authorized" in reason for reason in result.reasons)


def test_close_before_precharge_fails() -> None:
    result = make_validator().validate(
        request(CommandType.CLOSE_CONTACTOR),
        BMSOperatingState.OFF,
        now_s=10.5,
    )
    assert result.status == "FAIL"
    assert any("precharge" in reason.lower() for reason in result.reasons)


def test_clear_fault_from_sensor_source_fails() -> None:
    result = make_validator().validate(
        request(CommandType.CLEAR_FAULT, source_id=SENSOR_SOURCE),
        BMSOperatingState.FAULT,
        now_s=10.5,
    )
    assert result.status == "FAIL"


def test_replayed_shutdown_command_fails() -> None:
    validator = make_validator()
    first = request(CommandType.OPEN_CONTACTOR, counter=5)
    assert validator.validate(first, BMSOperatingState.ACTIVE, 10.5).status == "PASS"
    validator.record_executed(first)
    replay = request(CommandType.OPEN_CONTACTOR, counter=5)
    result = validator.validate(replay, BMSOperatingState.ACTIVE, 10.6)
    assert result.status == "FAIL"
    assert any("duplicate" in reason.lower() for reason in result.reasons)


def test_safe_state_allows_only_safe_commands() -> None:
    validator = make_validator()
    blocked = validator.validate(
        request(CommandType.CLOSE_CONTACTOR),
        BMSOperatingState.SAFE,
        now_s=10.5,
        precharge_complete=True,
    )
    recovery = validator.validate(
        request(CommandType.REQUEST_RECOVERY, counter=2),
        BMSOperatingState.SAFE,
        now_s=10.5,
    )
    assert blocked.status == "FAIL"
    assert recovery.status == "PASS"


def test_validator_does_not_mutate_freshness_before_execution() -> None:
    validator = make_validator()
    command = request(CommandType.OPEN_CONTACTOR, counter=8)
    assert validator.validate(command, BMSOperatingState.ACTIVE, 10.5).status == "PASS"
    assert validator.validate(command, BMSOperatingState.ACTIVE, 10.5).status == "PASS"
