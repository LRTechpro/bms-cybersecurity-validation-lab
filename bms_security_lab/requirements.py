from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityRequirement:
    requirement_id: str
    title: str
    description: str
    expected_behavior: str
    severity: str


SENSOR_SPOOFING_REQUIREMENT = SecurityRequirement(
    requirement_id="REQ-BMS-SPOOF-001",
    title="Reject implausible battery sensor data",
    description=(
        "The BMS shall detect and reject sensor readings "
        "outside configured physical limits."
    ),
    expected_behavior=(
        "Flag the reading, prevent it from updating trusted state, "
        "and create an audit record."
    ),
    severity="High",
)