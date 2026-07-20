import hashlib
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class BMSConfiguration:
    """Versioned immutable calibration data with a deterministic content hash."""

    configuration_id: str
    version: int
    hardware_profile: str
    battery_capacity_ah: float
    cell_count: int
    current_sensor_scale: float
    minimum_cell_voltage_v: float
    maximum_cell_voltage_v: float
    content_hash: str

    def __post_init__(self) -> None:
        if not self.configuration_id.strip() or not self.hardware_profile.strip():
            raise ValueError("Configuration identity and hardware profile are required.")
        if self.version < 1:
            raise ValueError("Configuration version must be at least 1.")

    def canonical_payload(self) -> bytes:
        """Return stable bytes for integrity verification."""
        data = {
            "battery_capacity_ah": self.battery_capacity_ah,
            "cell_count": self.cell_count,
            "configuration_id": self.configuration_id,
            "current_sensor_scale": self.current_sensor_scale,
            "hardware_profile": self.hardware_profile,
            "maximum_cell_voltage_v": self.maximum_cell_voltage_v,
            "minimum_cell_voltage_v": self.minimum_cell_voltage_v,
            "version": self.version,
        }
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def computed_hash(self) -> str:
        return hashlib.sha256(self.canonical_payload()).hexdigest()

    @classmethod
    def create(
        cls,
        configuration_id: str,
        version: int,
        hardware_profile: str,
        battery_capacity_ah: float,
        cell_count: int,
        current_sensor_scale: float,
        minimum_cell_voltage_v: float,
        maximum_cell_voltage_v: float,
    ) -> "BMSConfiguration":
        provisional = cls(
            configuration_id=configuration_id,
            version=version,
            hardware_profile=hardware_profile,
            battery_capacity_ah=battery_capacity_ah,
            cell_count=cell_count,
            current_sensor_scale=current_sensor_scale,
            minimum_cell_voltage_v=minimum_cell_voltage_v,
            maximum_cell_voltage_v=maximum_cell_voltage_v,
            content_hash="",
        )
        return cls(
            configuration_id=configuration_id,
            version=version,
            hardware_profile=hardware_profile,
            battery_capacity_ah=battery_capacity_ah,
            cell_count=cell_count,
            current_sensor_scale=current_sensor_scale,
            minimum_cell_voltage_v=minimum_cell_voltage_v,
            maximum_cell_voltage_v=maximum_cell_voltage_v,
            content_hash=provisional.computed_hash(),
        )
