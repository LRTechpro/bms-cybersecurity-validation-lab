from dataclasses import dataclass
from enum import Enum


class DiagnosticSession(str, Enum):
    DEFAULT = "DEFAULT"
    EXTENDED = "EXTENDED"
    PROGRAMMING = "PROGRAMMING"
    SUPPLIER = "SUPPLIER"


class DiagnosticService(str, Enum):
    READ_DATA = "READ_DATA"
    WRITE_CONFIGURATION = "WRITE_CONFIGURATION"
    SESSION_CONTROL = "SESSION_CONTROL"
    SECURITY_ACCESS = "SECURITY_ACCESS"
    REQUEST_DOWNLOAD = "REQUEST_DOWNLOAD"
    TRANSFER_DATA = "TRANSFER_DATA"
    TRANSFER_EXIT = "TRANSFER_EXIT"
    VERIFY_IMAGE = "VERIFY_IMAGE"
    ECU_RESET = "ECU_RESET"
    CLEAR_FAULT = "CLEAR_FAULT"


@dataclass(frozen=True)
class DiagnosticRequest:
    """One modeled diagnostic request; no live ECU traffic is produced."""

    service: DiagnosticService
    role: str
    timestamp_s: float
    authenticated: bool = True
    target_session: DiagnosticSession | None = None
    key_valid: bool | None = None

    def __post_init__(self) -> None:
        if self.timestamp_s < 0:
            raise ValueError("Timestamp must be zero or greater.")
        if not self.role.strip():
            raise ValueError("Diagnostic role cannot be empty.")


@dataclass
class DiagnosticState:
    """Mutable service state kept separate from immutable requests."""

    session: DiagnosticSession = DiagnosticSession.DEFAULT
    security_unlocked: bool = False
    failed_unlock_attempts: int = 0
    lockout_until_s: float = 0.0
    programming_step: int = 0
    update_transfer_active: bool = False
