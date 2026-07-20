from abc import ABC, abstractmethod
from dataclasses import dataclass

from bms_security_lab.requirements import SENSOR_SPOOFING_REQUIREMENT
from bms_security_lab.sensor_reading import BatterySensorReading




@dataclass(frozen=True)
class ValidationResult:
    requirement_id: str
    status: str
    reasons: tuple[str, ...]


class Validator(ABC):
    @abstractmethod
    def validate_sensor_reading(
        self,
        reading: BatterySensorReading,
    ) -> ValidationResult:
        pass    


class BMSValidator(Validator):
    """Validates received battery-monitoring data."""

    SOC_MIN = 0.0
    SOC_MAX = 100.0

    VOLTAGE_MIN = 0.0
    VOLTAGE_MAX = 1000.0

    CURRENT_MIN = -1000.0
    CURRENT_MAX = 1000.0

    TEMPERATURE_MIN = -40.0
    TEMPERATURE_MAX = 85.0

    def validate_sensor_reading(
        self,
        reading: BatterySensorReading,
    ) -> ValidationResult:
        reasons: list[str] = []

        if not self.SOC_MIN <= reading.soc_percent <= self.SOC_MAX:
            reasons.append(
                f"SOC {reading.soc_percent}% is outside the valid range."
            )

        if not self.VOLTAGE_MIN <= reading.pack_voltage_v <= self.VOLTAGE_MAX:
            reasons.append(
                f"Voltage {reading.pack_voltage_v} V is outside the valid range."
            )

        if not self.CURRENT_MIN <= reading.pack_current_a <= self.CURRENT_MAX:
            reasons.append(
                f"Current {reading.pack_current_a} A is outside the valid range."
            )

        if not (
            self.TEMPERATURE_MIN
            <= reading.max_temperature_c
            <= self.TEMPERATURE_MAX
        ):
            reasons.append(
                f"Temperature {reading.max_temperature_c} C "
                "is outside the valid range."
            )

        status = "FAIL" if reasons else "PASS"

        return ValidationResult(
            requirement_id=SENSOR_SPOOFING_REQUIREMENT.requirement_id,
            status=status,
            reasons=tuple(reasons),
        )    

class AuthenticationValidator(Validator):
    """Checks whether a sensor reading is authenticated."""

    def validate_sensor_reading(
        self,
        reading: BatterySensorReading,
    ) -> ValidationResult:

        if reading.authenticated:
            return ValidationResult(
                requirement_id="REQ-BMS-AUTH-001",
                status="PASS",
                reasons=(),
            )

        return ValidationResult(
            requirement_id="REQ-BMS-AUTH-001",
            status="FAIL",
            reasons=("Sensor reading is not authenticated.",),
        )