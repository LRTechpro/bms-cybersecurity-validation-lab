# Import Python's built-in unit-testing framework.
import unittest

# Import the BMS objects used by the sensor-spoofing tests.
from .sensor_reading import BatterySensorReading
from .spoofing_demo import apply_reading_if_valid
from .trusted_state import TrustedBMSState
from .validator import BMSValidator


class TestSensorSpoofing(unittest.TestCase):
    """Test sensor validation and trusted-state protection."""

    def setUp(self) -> None:
        # Create a fresh validator before each test.
        self.validator = BMSValidator()

    def _make_phase4_reading(
        self,
        soc_percent: float,
        sequence_counter: int,
    ) -> BatterySensorReading:
        """Create consistent test data while changing only SOC."""

        # All other values stay constant for a controlled comparison.
        return BatterySensorReading(
            soc_percent=soc_percent,
            pack_voltage_v=720.0,
            pack_current_a=40.0,
            max_temperature_c=35.0,
            source_id=0x180,
            sequence_counter=sequence_counter,
            authenticated=True,
        )

    def test_valid_sensor_reading_passes(self) -> None:
        # Create a normal BMS sensor reading.
        reading = BatterySensorReading(
            soc_percent=65.0,
            pack_voltage_v=720.0,
            pack_current_a=40.0,
            max_temperature_c=35.0,
            source_id=0x180,
            sequence_counter=1,
            authenticated=True,
        )

        # Validate the normal reading.
        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.reasons, ())

    def test_spoofed_soc_is_rejected(self) -> None:
        # Create an impossible SOC value.
        reading = BatterySensorReading(
            soc_percent=145.0,
            pack_voltage_v=720.0,
            pack_current_a=40.0,
            max_temperature_c=35.0,
            source_id=0x180,
            sequence_counter=2,
            authenticated=True,
        )

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "FAIL")
        self.assertIn(
            "SOC 145.0% is outside the valid range.",
            result.reasons,
        )

    def test_invalid_voltage_is_rejected(self) -> None:
        # Create a reading with an invalid negative pack voltage.
        reading = BatterySensorReading(
            soc_percent=65.0,
            pack_voltage_v=-50.0,
            pack_current_a=40.0,
            max_temperature_c=35.0,
            source_id=0x180,
            sequence_counter=3,
            authenticated=True,
        )

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "FAIL")
        self.assertIn(
            "Voltage -50.0 V is outside the valid range.",
            result.reasons,
        )

    def test_phase4_legitimate_soc_updates_trusted_state(self) -> None:
        # Arrange: begin with trusted SOC at 75%.
        state = TrustedBMSState(soc_percent=75.0)
        reading = self._make_phase4_reading(
            soc_percent=82.0,
            sequence_counter=1,
        )

        # Act: validate and apply the legitimate reading.
        status = apply_reading_if_valid(
            state,
            reading,
            self.validator,
        )

        # Assert: valid data updates trusted state.
        self.assertEqual(status, "PASS")
        self.assertEqual(state.get_soc(), 82.0)

    def test_phase4_spoofed_soc_does_not_update_trusted_state(
        self,
    ) -> None:
        # Arrange: begin with an accepted trusted SOC.
        state = TrustedBMSState(soc_percent=82.0)
        reading = self._make_phase4_reading(
            soc_percent=145.0,
            sequence_counter=2,
        )

        # Act: submit an SOC value above the valid range.
        status = apply_reading_if_valid(
            state,
            reading,
            self.validator,
        )

        # Assert: rejected data cannot change trusted state.
        self.assertEqual(status, "FAIL")
        self.assertEqual(state.get_soc(), 82.0)

    def test_phase4_negative_soc_does_not_update_trusted_state(
        self,
    ) -> None:
        # Arrange: create an SOC value below the valid range.
        state = TrustedBMSState(soc_percent=82.0)
        reading = self._make_phase4_reading(
            soc_percent=-1.0,
            sequence_counter=3,
        )

        # Act: validate the negative SOC value.
        status = apply_reading_if_valid(
            state,
            reading,
            self.validator,
        )

        # Assert: trusted state remains unchanged.
        self.assertEqual(status, "FAIL")
        self.assertEqual(state.get_soc(), 82.0)

    def test_phase4_soc_boundaries_are_accepted(self) -> None:
        # Arrange: create readings at both exact SOC boundaries.
        state = TrustedBMSState(soc_percent=50.0)

        lower_boundary = self._make_phase4_reading(
            soc_percent=0.0,
            sequence_counter=4,
        )
        upper_boundary = self._make_phase4_reading(
            soc_percent=100.0,
            sequence_counter=5,
        )

        # Act: validate and apply both boundary readings.
        lower_status = apply_reading_if_valid(
            state,
            lower_boundary,
            self.validator,
        )
        upper_status = apply_reading_if_valid(
            state,
            upper_boundary,
            self.validator,
        )

        # Assert: both exact boundaries pass.
        self.assertEqual(lower_status, "PASS")
        self.assertEqual(upper_status, "PASS")
        self.assertEqual(state.get_soc(), 100.0)


# Run the tests when this file is executed directly.
if __name__ == "__main__":
    unittest.main()