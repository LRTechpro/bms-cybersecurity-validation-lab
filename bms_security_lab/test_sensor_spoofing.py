# Import Python's built-in unit-testing framework.
import unittest

# Import the object that represents one BMS sensor message.
from bms_security_lab.sensor_reading import BatterySensorReading

# Import the class that checks whether sensor values are acceptable.
from bms_security_lab.validator import BMSValidator


# Create a group of related sensor-spoofing tests.
# unittest.TestCase provides the testing features and assertions.
class TestSensorSpoofing(unittest.TestCase):

    # setUp runs automatically before every test method.
    def setUp(self) -> None:
        # Create a fresh validator for each test.
        self.validator = BMSValidator()

    # Test names must begin with "test_" for unittest to discover them.
    def test_valid_sensor_reading_passes(self) -> None:
        # Create a normal BMS sensor-reading object.
        reading = BatterySensorReading(
            soc_percent=65.0,
            pack_voltage_v=720.0,
            pack_current_a=40.0,
            max_temperature_c=35.0,
            source_id=0x180,
            sequence_counter=1,
            authenticated=True,
        )

        # Send the reading to the validator.
        result = self.validator.validate_sensor_reading(reading)

        # Confirm that a normal reading passes.
        self.assertEqual(result.status, "PASS")

        # Confirm that no failure reasons were recorded.
        self.assertEqual(result.reasons, ())

    def test_spoofed_soc_is_rejected(self) -> None:
        # Create an invalid reading with an impossible SOC of 145%.
        reading = BatterySensorReading(
            soc_percent=145.0,
            pack_voltage_v=720.0,
            pack_current_a=40.0,
            max_temperature_c=35.0,
            source_id=0x180,
            sequence_counter=2,
            authenticated=True,
        )

        # Validate the spoofed reading.
        result = self.validator.validate_sensor_reading(reading)

        # Confirm that the validator rejects it.
        self.assertEqual(result.status, "FAIL")

        # Confirm that the expected reason was recorded.
        self.assertIn(
            "SOC 145.0% is outside the valid range.",
            result.reasons,
        )

    def test_invalid_voltage_is_rejected(self) -> None:
        # Create an invalid reading with negative pack voltage.
        reading = BatterySensorReading(
            soc_percent=65.0,
            pack_voltage_v=-50.0,
            pack_current_a=40.0,
            max_temperature_c=35.0,
            source_id=0x180,
            sequence_counter=3,
            authenticated=True,
        )

        # Validate the abnormal reading.
        result = self.validator.validate_sensor_reading(reading)

        # Confirm that the test fails validation.
        self.assertEqual(result.status, "FAIL")

        # Confirm that the voltage failure reason was recorded.
        self.assertIn(
            "Voltage -50.0 V is outside the valid range.",
            result.reasons,
        )


# Run the tests when this file is executed directly.
if __name__ == "__main__":
    unittest.main()