# Import Python's built-in unit-testing framework.
import unittest

# Import the Phase 6 validator and supporting BMS objects.
from .cross_signal_validator import CrossSignalValidator
from .sensor_reading import BatterySensorReading
from .trusted_state import TrustedBMSState


class TestCrossSignalValidator(unittest.TestCase):
    """Test cross-signal and redundant-source consistency rules."""

    def setUp(self) -> None:
        # Create a fresh validator before every test.
        self.validator = CrossSignalValidator()

    def _make_reading(
        self,
        source_id: int,
        soc_percent: float = 60.0,
        pack_voltage_v: float = 720.0,
        pack_current_a: float = 20.0,
        max_temperature_c: float = 35.0,
        sequence_counter: int = 1,
    ) -> BatterySensorReading:
        """Create a configurable authenticated BMS reading."""

        return BatterySensorReading(
            soc_percent=soc_percent,
            pack_voltage_v=pack_voltage_v,
            pack_current_a=pack_current_a,
            max_temperature_c=max_temperature_c,
            source_id=source_id,
            sequence_counter=sequence_counter,
            authenticated=True,
        )

    def test_consistent_soc_and_voltage_pass(self) -> None:
        # Mid-range SOC and voltage do not violate configured relationships.
        reading = self._make_reading(source_id=0x180)

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.reasons, ())

    def test_low_soc_with_high_voltage_fails(self) -> None:
        # Each value is numerically valid, but the combination is suspicious.
        reading = self._make_reading(
            source_id=0x180,
            soc_percent=15.0,
            pack_voltage_v=780.0,
        )

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "FAIL")
        self.assertTrue(
            any("Low SOC" in reason for reason in result.reasons)
        )

    def test_high_soc_with_low_voltage_fails(self) -> None:
        reading = self._make_reading(
            source_id=0x180,
            soc_percent=90.0,
            pack_voltage_v=620.0,
        )

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "FAIL")
        self.assertTrue(
            any("High SOC" in reason for reason in result.reasons)
        )

    def test_redundant_sources_within_tolerance_pass(self) -> None:
        primary = self._make_reading(source_id=0x180)
        redundant = self._make_reading(
            source_id=0x181,
            soc_percent=61.0,
            pack_voltage_v=724.0,
            pack_current_a=25.0,
            max_temperature_c=36.0,
        )

        result = self.validator.validate_redundant_sources(
            primary,
            redundant,
        )

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.reasons, ())

    def test_redundant_soc_mismatch_fails(self) -> None:
        primary = self._make_reading(
            source_id=0x180,
            soc_percent=60.0,
        )
        manipulated = self._make_reading(
            source_id=0x181,
            soc_percent=75.0,
        )

        result = self.validator.validate_redundant_sources(
            primary,
            manipulated,
        )

        self.assertEqual(result.status, "FAIL")
        self.assertTrue(
            any(
                "Redundant SOC difference" in reason
                for reason in result.reasons
            )
        )

    def test_multiple_redundant_mismatches_are_reported(self) -> None:
        # One execution should expose every inconsistent measurement.
        primary = self._make_reading(source_id=0x180)
        manipulated = self._make_reading(
            source_id=0x181,
            soc_percent=70.0,
            pack_voltage_v=680.0,
            pack_current_a=-20.0,
            max_temperature_c=45.0,
        )

        result = self.validator.validate_redundant_sources(
            primary,
            manipulated,
        )

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(len(result.reasons), 4)

    def test_same_source_cannot_claim_redundancy(self) -> None:
        primary = self._make_reading(source_id=0x180)
        duplicate_source = self._make_reading(source_id=0x180)

        result = self.validator.validate_redundant_sources(
            primary,
            duplicate_source,
        )

        self.assertEqual(result.status, "FAIL")
        self.assertIn(
            "Redundant readings must come from different source IDs.",
            result.reasons,
        )

    def test_inconsistent_pair_does_not_update_trusted_state(self) -> None:
        # Trusted state begins with the last accepted SOC.
        state = TrustedBMSState(soc_percent=60.0)
        primary = self._make_reading(
            source_id=0x180,
            soc_percent=65.0,
        )
        manipulated_redundant = self._make_reading(
            source_id=0x181,
            soc_percent=85.0,
        )

        result = self.validator.validate_complete_relationships(
            primary,
            manipulated_redundant,
        )

        # The controlling gate updates state only after a complete PASS.
        if result.status == "PASS":
            state.update_soc(primary.soc_percent)

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(state.get_soc(), 60.0)


if __name__ == "__main__":
    unittest.main()
