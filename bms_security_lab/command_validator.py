from dataclasses import dataclass

from .command_model import BMSOperatingState, CommandRequest, CommandType


@dataclass(frozen=True)
class CommandDecision:
    """Validation decision kept separate from command execution."""

    requirement_id: str
    status: str
    reasons: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return self.status == "PASS"


class CommandValidator:
    """Require trust, freshness, permission, and state preconditions."""

    REQUIREMENT_ID = "BMS-SEC-CMD-001"

    def __init__(
        self,
        permissions_by_source: dict[int, set[CommandType]],
        max_message_age_s: float = 2.0,
        max_power_limit_kw: float = 350.0,
    ) -> None:
        if max_message_age_s < 0 or max_power_limit_kw <= 0:
            raise ValueError("Command limits must be positive.")
        self._permissions = {
            source_id: set(commands)
            for source_id, commands in permissions_by_source.items()
        }
        self.max_message_age_s = max_message_age_s
        self.max_power_limit_kw = max_power_limit_kw
        self._last_counter_by_source: dict[int, int] = {}

    def validate(
        self,
        request: CommandRequest,
        state: BMSOperatingState,
        now_s: float,
        precharge_complete: bool = False,
    ) -> CommandDecision:
        reasons: list[str] = []

        if now_s < request.timestamp_s:
            reasons.append("Command timestamp is in the future.")
        elif now_s - request.timestamp_s > self.max_message_age_s:
            reasons.append("Command is stale.")

        if not request.authenticated:
            reasons.append("Command source is not authenticated.")

        allowed_commands = self._permissions.get(request.source_id)
        if allowed_commands is None:
            reasons.append(f"Unknown command source 0x{request.source_id:X}.")
        elif request.command_type not in allowed_commands:
            reasons.append(
                f"Source 0x{request.source_id:X} is not authorized for "
                f"{request.command_type.value}."
            )

        last_counter = self._last_counter_by_source.get(request.source_id)
        if last_counter is not None and request.sequence_counter <= last_counter:
            reasons.append("Command sequence counter is duplicate or out of order.")

        reasons.extend(
            self._state_reasons(
                request=request,
                state=state,
                precharge_complete=precharge_complete,
            )
        )

        if (
            request.command_type is CommandType.SET_POWER_LIMIT
            and (
                request.requested_value is None
                or not 0 <= request.requested_value <= self.max_power_limit_kw
            )
        ):
            reasons.append("Requested power limit is outside the allowed range.")

        return CommandDecision(
            requirement_id=self.REQUIREMENT_ID,
            status="FAIL" if reasons else "PASS",
            reasons=tuple(reasons),
        )

    def record_executed(self, request: CommandRequest) -> None:
        """Advance freshness state only after validated execution."""
        self._last_counter_by_source[request.source_id] = request.sequence_counter

    @staticmethod
    def _state_reasons(
        request: CommandRequest,
        state: BMSOperatingState,
        precharge_complete: bool,
    ) -> list[str]:
        reasons: list[str] = []
        command = request.command_type

        if state is BMSOperatingState.SAFE:
            safe_allowed = {
                CommandType.OPEN_CONTACTOR,
                CommandType.REQUEST_RECOVERY,
            }
            if command not in safe_allowed:
                reasons.append("Command is not permitted while the BMS is SAFE.")

        if command is CommandType.CLOSE_CONTACTOR:
            if state is not BMSOperatingState.PRECHARGE or not precharge_complete:
                reasons.append("Contactor close requires completed precharge.")

        if command in {
            CommandType.ENABLE_CHARGE,
            CommandType.ENABLE_DISCHARGE,
        } and state in {BMSOperatingState.FAULT, BMSOperatingState.SAFE}:
            reasons.append("Charge or discharge enable is blocked in FAULT or SAFE.")

        if command is CommandType.CLEAR_FAULT and state is not BMSOperatingState.FAULT:
            reasons.append("Fault clear requires the FAULT state.")

        if command is CommandType.ENTER_SERVICE and state not in {
            BMSOperatingState.OFF,
            BMSOperatingState.FAULT,
        }:
            reasons.append("Service mode entry requires OFF or FAULT state.")

        return reasons
