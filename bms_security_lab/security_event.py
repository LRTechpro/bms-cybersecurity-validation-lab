from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class EventSeverity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50


@dataclass(frozen=True)
class SecurityEvent:
    """One structured security-relevant observation."""

    timestamp_s: float
    asset_id: str
    source_id: str
    event_type: str
    severity: EventSeverity
    related_test_id: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp_s < 0:
            raise ValueError("Event timestamp must be zero or greater.")
        for value in (
            self.asset_id,
            self.source_id,
            self.event_type,
            self.related_test_id,
        ):
            if not value.strip():
                raise ValueError("Security event identity fields cannot be empty.")
