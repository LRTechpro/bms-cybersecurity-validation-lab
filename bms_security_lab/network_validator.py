from dataclasses import dataclass

from .modbus_model import (
    ClientSession,
    ModbusFunction,
    ModbusRequest,
    NetworkZone,
)


@dataclass(frozen=True)
class NetworkDecision:
    requirement_id: str
    status: str
    reasons: tuple[str, ...]
    rate_limited: bool = False
    alert: bool = False


@dataclass(frozen=True)
class RolePolicy:
    allowed_functions: frozenset[ModbusFunction]
    allowed_zones: frozenset[NetworkZone]


class NetworkValidator:
    """Enforce identity, role, zone, function, range, and denial rate."""

    REQUIREMENT_ID = "BMS-SEC-OT-001"

    def __init__(
        self,
        role_policies: dict[str, RolePolicy],
        readable_ranges: tuple[tuple[int, int], ...],
        writable_ranges: tuple[tuple[int, int], ...],
        denied_limit: int = 3,
        denied_window_s: float = 10.0,
    ) -> None:
        if denied_limit < 1 or denied_window_s <= 0:
            raise ValueError("Denial-rate policy must be positive.")
        self.role_policies = dict(role_policies)
        self.readable_ranges = readable_ranges
        self.writable_ranges = writable_ranges
        self.denied_limit = denied_limit
        self.denied_window_s = denied_window_s
        self._denied_times_by_client: dict[str, list[float]] = {}
        self.audit_events: list[str] = []

    def validate(
        self,
        session: ClientSession,
        request: ModbusRequest,
    ) -> NetworkDecision:
        reasons: list[str] = []

        if not session.authenticated:
            reasons.append("Client session is not authenticated.")
        if session.certificate_revoked:
            reasons.append("Client certificate is revoked.")

        policy = self.role_policies.get(session.role)
        if policy is None:
            reasons.append("Client role is unknown.")
        else:
            if session.zone not in policy.allowed_zones:
                reasons.append("Client network zone is not authorized for the role.")
            if request.function not in policy.allowed_functions:
                reasons.append("Modbus function is not authorized for the role.")

        selected_ranges = (
            self.writable_ranges
            if request.function.is_write
            else self.readable_ranges
        )
        if not self._range_is_allowed(
            request.start_address,
            request.quantity,
            selected_ranges,
        ):
            reasons.append("Requested register range is not authorized.")

        if reasons:
            rate_limited = self._record_denial(
                session.client_id,
                request.timestamp_s,
            )
            self.audit_events.append(
                f"DENY:{session.client_id}:{request.function.value}:"
                f"{request.start_address}"
            )
            return NetworkDecision(
                requirement_id=self.REQUIREMENT_ID,
                status="FAIL",
                reasons=tuple(reasons),
                rate_limited=rate_limited,
                alert=rate_limited,
            )

        self.audit_events.append(
            f"ALLOW:{session.client_id}:{request.function.value}:"
            f"{request.start_address}"
        )
        return NetworkDecision(
            requirement_id=self.REQUIREMENT_ID,
            status="PASS",
            reasons=(),
        )

    @staticmethod
    def _range_is_allowed(
        start_address: int,
        quantity: int,
        allowed_ranges: tuple[tuple[int, int], ...],
    ) -> bool:
        end_address = start_address + quantity - 1
        return any(
            allowed_start <= start_address
            and end_address <= allowed_end
            for allowed_start, allowed_end in allowed_ranges
        )

    def _record_denial(self, client_id: str, now_s: float) -> bool:
        recent = self._denied_times_by_client.setdefault(client_id, [])
        minimum_time = now_s - self.denied_window_s
        recent[:] = [timestamp for timestamp in recent if timestamp >= minimum_time]
        recent.append(now_s)
        return len(recent) >= self.denied_limit
