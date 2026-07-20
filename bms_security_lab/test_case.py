from dataclasses import dataclass

from bms_security_lab.sensor_reading import BatterySensorReading
from bms_security_lab.validator import ValidationResult, Validator


@dataclass(frozen=True)
class ValidationTestCase:
    test_id: str
    reading: BatterySensorReading
    validator: Validator

    def run(self) -> ValidationResult:
        return self.validator.validate_sensor_reading(self.reading)