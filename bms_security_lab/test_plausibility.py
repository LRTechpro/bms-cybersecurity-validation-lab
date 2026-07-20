# Import Python's built-in testing framework.
import unittest

# Import the Phase 5 objects being tested.
from .plausibility_validator import PlausibilityValidator
from .sensor_history import SensorHistory
from .sensor_reading import BatterySensorReading


class TestPlausibilityValidator(unittest.TestCase):
    """Test realistic but physically inconsistent sensor changes."""

    def setUp(self) -> None:
        # Create fresh history and validator objects for every test.
        self.history = SensorHistory()
        self.validator = PlausibilityValidator(self.history)

    def _make_reading(
        self,
        soc_percent: float,
        pack_current_a: float = 10.0,
        pack_voltage_v: float = 720.0,
        max_temperature_c: float = 25.0,
        sequence_counter: int = 1,
    ) -> BatterySensorReading:
        """Create a consistent sensor reading for Phase 5 tests."""

        return BatterySensorReading(
            soc_percent=soc_percent,
            pack_voltage_v=pack_voltage_v,
            pack_current_a=pack_current_a,
            max_temperature_c=max_temperature_c,
            source_id=0x180,
            sequence_counter=sequence_counter,
            authenticated=True,
        )

    def _record_previous_reading(
        self,
        reading: BatterySensorReading,
        timestamp_s: float = 0.0,
    ) -> None:
        """Place one accepted reading into sensor history."""

        self.history.record_accepted_reading(
            reading,
            timestamp_s,
        )

    def test_first_reading_passes_without_history(self) -> None:
        # The first reading has no earlier value for comparison.
        reading = self._make_reading(
            soc_percent=48.0,
        )

        result = self.validator.validate_sensor_reading(
            reading,
            timestamp_s=0.0,
        )

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.reasons, ())

    def test_normal_soc_change_passes(self) -> None:
        # Store a legitimate starting point.
        previous = self._make_reading(
            soc_percent=48.0,
            sequence_counter=1,
        )
        self._record_previous_reading(previous)

        # SOC increases by only 1% during one second.
        current = self._make_reading(
            soc_percent=49.0,
            sequence_counter=2,
        )

        result = self.validator.validate_sensor_reading(
            current,
            timestamp_s=1.0,
        )

        self.assertEqual(result.status, "PASS")

        # The caller records history only after validation passes.
        if result.status == "PASS":
            self.history.record_accepted_reading(
                current,
                timestamp_s=1.0,
            )

        self.assertEqual(
            self.history.get_previous_reading(),
            current,
        )

    def test_large_soc_jump_fails(self) -> None:
        # Establish an accepted SOC of 48%.
        previous = self._make_reading(
            soc_percent=48.0,
            sequence_counter=1,
        )
        self._record_previous_reading(previous)

        # The new value is numerically valid but changes too quickly.
        manipulated = self._make_reading(
            soc_percent=88.0,
            sequence_counter=2,
        )

        result = self.validator.validate_sensor_reading(
            manipulated,
            timestamp_s=1.0,
        )

        self.assertEqual(result.status, "FAIL")
        self.assertTrue(
            any(
                "SOC changed at" in reason
                for reason in result.reasons
            )
        )

    def test_fast_temperature_rise_fails(self) -> None:
        # Begin with a normal temperature.
        previous = self._make_reading(
            soc_percent=48.0,
            max_temperature_c=25.0,
            sequence_counter=1,
        )
        self._record_previous_reading(previous)

        # Temperature rises by 15 degrees in one second.
        manipulated = self._make_reading(
            soc_percent=48.0,
            max_temperature_c=40.0,
            sequence_counter=2,
        )

        result = self.validator.validate_sensor_reading(
            manipulated,
            timestamp_s=1.0,
        )

        self.assertEqual(result.status, "FAIL")
        self.assertTrue(
            any(
                "Temperature changed at" in reason
                for reason in result.reasons
            )
        )

    def test_current_direction_conflict_fails(self) -> None:
        # Begin with an accepted SOC of 48%.
        previous = self._make_reading(
            soc_percent=48.0,
            sequence_counter=1,
        )
        self._record_previous_reading(previous)

        # SOC rises while negative current indicates discharge.
        manipulated = self._make_reading(
            soc_percent=49.0,
            pack_current_a=-10.0,
            sequence_counter=2,
        )

        result = self.validator.validate_sensor_reading(
            manipulated,
            timestamp_s=1.0,
        )

        self.assertEqual(result.status, "FAIL")
        self.assertIn(
            "SOC increased while current indicated discharge.",
            result.reasons,
        )

    def test_failed_reading_does_not_replace_history(self) -> None:
        # Store the last accepted reading.
        previous = self._make_reading(
            soc_percent=48.0,
            sequence_counter=1,
        )
        self._record_previous_reading(previous)

        # Submit a manipulated reading that should fail.
        manipulated = self._make_reading(
            soc_percent=88.0,
            sequence_counter=2,
        )

        result = self.validator.validate_sensor_reading(
            manipulated,
            timestamp_s=1.0,
        )

        # Do not record rejected data.
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(
            self.history.get_previous_reading(),
            previous,
        )
        self.assertEqual(
            self.history.get_previous_timestamp_s(),
            0.0,
        )


# Allow the file to run through Python's unittest module.
if __name__ == "__main__":
    unittest.main()