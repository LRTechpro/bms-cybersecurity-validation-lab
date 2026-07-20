# Import Python's built-in unit-testing framework.
import unittest

# Import the Phase 7 objects used by these tests.
from .replay_validator import ReplayValidator
from .sensor_reading import BatterySensorReading


class TestReplayValidator(unittest.TestCase):
    """Test sequence-counter and timestamp freshness protection."""

    def setUp(self) -> None:
        # Create a fresh validator before every test.
        self.validator = ReplayValidator(max_counter=255)

    def _make_reading(
        self,
        sequence_counter: int,
        source_id: int = 0x180,
    ) -> BatterySensorReading:
        """Create a normal reading with a selected counter and source."""

        return BatterySensorReading(
            soc_percent=65.0,
            pack_voltage_v=720.0,
            pack_current_a=20.0,
            max_temperature_c=35.0,
            source_id=source_id,
            sequence_counter=sequence_counter,
            authenticated=True,
        )

    def test_counter_one_then_two_passes(self) -> None:
        # Arrange: create the first message from the sensor source.
        first = self._make_reading(sequence_counter=1)

        # Act: validate the first message.
        first_result = self.validator.validate_sensor_reading(
            first,
            timestamp_s=1.0,
        )

        # Record freshness state only after the message passes.
        if first_result.status == "PASS":
            self.validator.record_accepted_reading(
                first,
                timestamp_s=1.0,
            )

        # Create the next correctly ordered message.
        second = self._make_reading(sequence_counter=2)

        second_result = self.validator.validate_sensor_reading(
            second,
            timestamp_s=2.0,
        )

        # Assert: normal sequence progression passes.
        self.assertEqual(first_result.status, "PASS")
        self.assertEqual(second_result.status, "PASS")

    def test_repeated_counter_fails_as_duplicate(self) -> None:
        # Arrange: establish counter 2 as the last accepted message.
        accepted = self._make_reading(sequence_counter=2)
        self.validator.record_accepted_reading(
            accepted,
            timestamp_s=2.0,
        )

        # Act: submit the same counter again.
        duplicate = self._make_reading(sequence_counter=2)

        result = self.validator.validate_sensor_reading(
            duplicate,
            timestamp_s=3.0,
        )

        # Assert: an exact counter replay is rejected.
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(
            any(
                "Duplicate sequence counter" in reason
                for reason in result.reasons
            )
        )

        # Rejected data must not replace accepted freshness state.
        self.assertEqual(
            self.validator.get_last_counter(0x180),
            2,
        )

    def test_counter_moving_backward_fails(self) -> None:
        # Arrange: establish counter 5 as the accepted value.
        accepted = self._make_reading(sequence_counter=5)
        self.validator.record_accepted_reading(
            accepted,
            timestamp_s=5.0,
        )

        # Act: submit an older counter value.
        out_of_order = self._make_reading(sequence_counter=4)

        result = self.validator.validate_sensor_reading(
            out_of_order,
            timestamp_s=6.0,
        )

        # Assert: backward sequence movement is rejected.
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(
            any(
                "Out-of-order sequence counter" in reason
                for reason in result.reasons
            )
        )

    def test_old_timestamp_with_new_counter_fails(self) -> None:
        # Arrange: establish counter 1 at timestamp 10.
        accepted = self._make_reading(sequence_counter=1)
        self.validator.record_accepted_reading(
            accepted,
            timestamp_s=10.0,
        )

        # Act: use the correct next counter with an older timestamp.
        stale = self._make_reading(sequence_counter=2)

        result = self.validator.validate_sensor_reading(
            stale,
            timestamp_s=9.0,
        )

        # Assert: a stale timestamp is rejected independently.
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(
            any(
                "Stale timestamp" in reason
                for reason in result.reasons
            )
        )

    def test_maximum_counter_wraps_to_zero(self) -> None:
        # Arrange: establish the maximum counter as accepted.
        maximum = self._make_reading(sequence_counter=255)
        self.validator.record_accepted_reading(
            maximum,
            timestamp_s=10.0,
        )

        # Act: submit zero as the next counter under wraparound policy.
        wrapped = self._make_reading(sequence_counter=0)

        result = self.validator.validate_sensor_reading(
            wrapped,
            timestamp_s=11.0,
        )

        # Assert: 255 to 0 is the one permitted backward transition.
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.reasons, ())


# Run the tests when this file is executed directly.
if __name__ == "__main__":
    unittest.main()