from dataclasses import dataclass
from enum import Enum


class BMSOperatingState(str, Enum):
    """Explicit simulated operating states for command guards."""

    OFF = "OFF"
    PRECHARGE = "PRECHARGE"
    ACTIVE = "ACTIVE"
    CHARGING = "CHARGING"
    FAULT = "FAULT"
    SERVICE = "SERVICE"
    SAFE = "SAFE"


class CommandType(str, Enum):
    """High-impact commands evaluated by the control security gate."""

    OPEN_CONTACTOR = "OPEN_CONTACTOR"
    CLOSE_CONTACTOR = "CLOSE_CONTACTOR"
    ENABLE_CHARGE = "ENABLE_CHARGE"
    ENABLE_DISCHARGE = "ENABLE_DISCHARGE"
    SET_POWER_LIMIT = "SET_POWER_LIMIT"
    CLEAR_FAULT = "CLEAR_FAULT"
    ENTER_SERVICE = "ENTER_SERVICE"
    RESET = "RESET"
    REQUEST_RECOVERY = "REQUEST_RECOVERY"


@dataclass(frozen=True)
class CommandRequest:
    """Immutable command input; validation never executes the command."""

    command_type: CommandType
    source_id: int
    sequence_counter: int
    authenticated: bool
    timestamp_s: float
    requested_value: float | None = None

    def __post_init__(self) -> None:
        if self.source_id < 0:
            raise ValueError("Source ID must be zero or greater.")
        if self.sequence_counter < 0:
            raise ValueError("Sequence counter must be zero or greater.")
        if self.timestamp_s < 0:
            raise ValueError("Timestamp must be zero or greater.")
