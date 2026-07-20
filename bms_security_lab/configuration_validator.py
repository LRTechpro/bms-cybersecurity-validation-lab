from dataclasses import asdict, dataclass

from .configuration_model import BMSConfiguration


@dataclass(frozen=True)
class ConfigurationDecision:
    requirement_id: str
    status: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class ConfigurationAuditEvent:
    actor: str
    timestamp_s: float
    previous_version: int
    new_version: int
    previous_values: dict[str, object]
    new_values: dict[str, object]


class ConfigurationValidator:
    """Validate configuration independently from firmware authorization."""

    REQUIREMENT_ID = "BMS-SEC-CFG-001"

    def __init__(
        self,
        approved_hashes_by_version: dict[int, str],
        expected_hardware_profile: str,
        expected_cell_count: int,
        expected_current_sensor_scale: float,
        capacity_range_ah: tuple[float, float] = (1.0, 1000.0),
        scale_tolerance: float = 0.0001,
    ) -> None:
        self._approved_hashes = dict(approved_hashes_by_version)
        self.expected_hardware_profile = expected_hardware_profile
        self.expected_cell_count = expected_cell_count
        self.expected_current_sensor_scale = expected_current_sensor_scale
        self.capacity_range_ah = capacity_range_ah
        self.scale_tolerance = scale_tolerance
        self.audit_events: list[ConfigurationAuditEvent] = []

    def validate(self, configuration: BMSConfiguration) -> ConfigurationDecision:
        reasons: list[str] = []

        if configuration.content_hash != configuration.computed_hash():
            reasons.append("Configuration content hash does not match its values.")

        approved_hash = self._approved_hashes.get(configuration.version)
        if approved_hash is None:
            reasons.append("Configuration version is not approved.")
        elif approved_hash != configuration.content_hash:
            reasons.append("Configuration hash is not approved for this version.")

        if configuration.hardware_profile != self.expected_hardware_profile:
            reasons.append("Configuration hardware profile is incompatible.")

        if configuration.cell_count != self.expected_cell_count:
            reasons.append("Configuration cell count does not match hardware.")

        if abs(
            configuration.current_sensor_scale
            - self.expected_current_sensor_scale
        ) > self.scale_tolerance:
            reasons.append("Current sensor scaling is not approved.")

        minimum_capacity, maximum_capacity = self.capacity_range_ah
        if not minimum_capacity <= configuration.battery_capacity_ah <= maximum_capacity:
            reasons.append("Battery capacity is outside the configured range.")

        if (
            configuration.minimum_cell_voltage_v <= 0
            or configuration.maximum_cell_voltage_v
            <= configuration.minimum_cell_voltage_v
        ):
            reasons.append("Cell-voltage threshold relationship is inconsistent.")

        return ConfigurationDecision(
            requirement_id=self.REQUIREMENT_ID,
            status="FAIL" if reasons else "PASS",
            reasons=tuple(reasons),
        )

    def apply_authorized_upgrade(
        self,
        previous: BMSConfiguration,
        proposed: BMSConfiguration,
        actor: str,
        timestamp_s: float,
    ) -> ConfigurationDecision:
        reasons: list[str] = []
        if not actor.strip():
            reasons.append("Authorized actor identity is required.")
        if timestamp_s < 0:
            reasons.append("Timestamp must be zero or greater.")
        if proposed.version <= previous.version:
            reasons.append("Configuration upgrade must increase the version.")

        validation = self.validate(proposed)
        reasons.extend(validation.reasons)

        if reasons:
            return ConfigurationDecision(
                requirement_id="BMS-SEC-CFG-002",
                status="FAIL",
                reasons=tuple(reasons),
            )

        self.audit_events.append(
            ConfigurationAuditEvent(
                actor=actor,
                timestamp_s=timestamp_s,
                previous_version=previous.version,
                new_version=proposed.version,
                previous_values=asdict(previous),
                new_values=asdict(proposed),
            )
        )
        return ConfigurationDecision(
            requirement_id="BMS-SEC-CFG-002",
            status="PASS",
            reasons=(),
        )
