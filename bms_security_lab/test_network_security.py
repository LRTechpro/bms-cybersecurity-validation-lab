from .modbus_model import (
    ClientSession,
    ModbusFunction,
    ModbusRequest,
    NetworkZone,
)
from .network_validator import NetworkValidator, RolePolicy


def make_validator() -> NetworkValidator:
    return NetworkValidator(
        role_policies={
            "monitor": RolePolicy(
                allowed_functions=frozenset(
                    {ModbusFunction.READ_HOLDING_REGISTERS}
                ),
                allowed_zones=frozenset({NetworkZone.MONITORING}),
            ),
            "operator": RolePolicy(
                allowed_functions=frozenset(
                    {
                        ModbusFunction.READ_HOLDING_REGISTERS,
                        ModbusFunction.WRITE_SINGLE_REGISTER,
                    }
                ),
                allowed_zones=frozenset({NetworkZone.CONTROL}),
            ),
            "service": RolePolicy(
                allowed_functions=frozenset(ModbusFunction),
                allowed_zones=frozenset({NetworkZone.SERVICE}),
            ),
        },
        readable_ranges=((0, 199),),
        writable_ranges=((100, 119),),
        denied_limit=3,
        denied_window_s=10.0,
    )


def read_request(timestamp_s: float = 1.0) -> ModbusRequest:
    return ModbusRequest(
        function=ModbusFunction.READ_HOLDING_REGISTERS,
        start_address=10,
        quantity=2,
        timestamp_s=timestamp_s,
    )


def write_request(timestamp_s: float = 1.0) -> ModbusRequest:
    return ModbusRequest(
        function=ModbusFunction.WRITE_SINGLE_REGISTER,
        start_address=100,
        quantity=1,
        timestamp_s=timestamp_s,
        values=(25,),
    )


def test_authenticated_monitor_reads_allowed_registers() -> None:
    session = ClientSession(
        client_id="monitor-1",
        role="monitor",
        zone=NetworkZone.MONITORING,
        authenticated=True,
    )
    assert make_validator().validate(session, read_request()).status == "PASS"


def test_read_only_client_write_fails() -> None:
    session = ClientSession(
        client_id="monitor-1",
        role="monitor",
        zone=NetworkZone.MONITORING,
        authenticated=True,
    )
    result = make_validator().validate(session, write_request())
    assert result.status == "FAIL"
    assert any("function" in reason.lower() for reason in result.reasons)


def test_unauthenticated_session_fails() -> None:
    session = ClientSession(
        client_id="monitor-1",
        role="monitor",
        zone=NetworkZone.MONITORING,
        authenticated=False,
    )
    result = make_validator().validate(session, read_request())
    assert result.status == "FAIL"
    assert any("authenticated" in reason.lower() for reason in result.reasons)


def test_revoked_client_certificate_fails() -> None:
    session = ClientSession(
        client_id="operator-1",
        role="operator",
        zone=NetworkZone.CONTROL,
        authenticated=True,
        certificate_revoked=True,
    )
    result = make_validator().validate(session, write_request())
    assert result.status == "FAIL"
    assert any("revoked" in reason.lower() for reason in result.reasons)


def test_unexpected_network_zone_fails() -> None:
    session = ClientSession(
        client_id="operator-1",
        role="operator",
        zone=NetworkZone.UNTRUSTED,
        authenticated=True,
    )
    result = make_validator().validate(session, write_request())
    assert result.status == "FAIL"
    assert any("zone" in reason.lower() for reason in result.reasons)


def test_invalid_register_range_fails() -> None:
    session = ClientSession(
        client_id="operator-1",
        role="operator",
        zone=NetworkZone.CONTROL,
        authenticated=True,
    )
    request = ModbusRequest(
        function=ModbusFunction.WRITE_SINGLE_REGISTER,
        start_address=999,
        quantity=1,
        timestamp_s=1.0,
        values=(10,),
    )
    result = make_validator().validate(session, request)
    assert result.status == "FAIL"
    assert any("range" in reason.lower() for reason in result.reasons)


def test_repeated_denied_requests_trigger_alert_and_rate_limit() -> None:
    validator = make_validator()
    session = ClientSession(
        client_id="abusive-client",
        role="monitor",
        zone=NetworkZone.MONITORING,
        authenticated=True,
    )
    results = [
        validator.validate(session, write_request(timestamp_s=timestamp))
        for timestamp in (1.0, 2.0, 3.0)
    ]
    assert results[-1].status == "FAIL"
    assert results[-1].rate_limited is True
    assert results[-1].alert is True
