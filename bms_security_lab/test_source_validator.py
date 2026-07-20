# Import Python's built-in unit-testing framework.
import unittest

# Import the Phase 8 policy and validator objects.
from .authorization_policy import AuthorizationPolicy
from .sensor_reading import BatterySensorReading
from .source_validator import SourceValidator


class TestSourceValidator(unittest.TestCase):
    """Test source identity, authentication, and authorization."""

    def setUp(self) -> None:
        # Source 0x180 may publish sensor data.
        # Source 0x181 is known but has no sensor-data permission.
        self.policy = AuthorizationPolicy(
            known_source_ids={0x180, 0x181},
            permissions_by_source={
                0x180: {"sensor_data"},
                0x181: {"diagnostic_data"},
            },
        )
        self.validator = SourceValidator(
            policy=self.policy,
            required_action="sensor_data",
        )

    def _make_reading(
        self,
        source_id: int,
        authenticated: bool = True,
    ) -> BatterySensorReading:
        """Create a normal reading while varying source trust fields."""

        return BatterySensorReading(
            soc_percent=65.0,
            pack_voltage_v=720.0,
            pack_current_a=20.0,
            max_temperature_c=35.0,
            source_id=source_id,
            sequence_counter=1,
            authenticated=authenticated,
        )

    def test_known_authenticated_authorized_source_passes(self) -> None:
        # The expected source is known, authenticated, and authorized.
        reading = self._make_reading(source_id=0x180)

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.reasons, ())

    def test_unknown_source_fails(self) -> None:
        # An unrecognized identity must fail before other trust checks.
        reading = self._make_reading(source_id=0x999)

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "FAIL")
        self.assertIn(
            "Unknown source ID 0x999.",
            result.reasons,
        )

    def test_unauthenticated_source_fails(self) -> None:
        # A recognized source still fails when authentication is absent.
        reading = self._make_reading(
            source_id=0x180,
            authenticated=False,
        )

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "FAIL")
        self.assertIn(
            "Source ID 0x180 is not authenticated.",
            result.reasons,
        )

    def test_known_but_unauthorized_source_fails(self) -> None:
        # Source 0x181 is known but lacks sensor-data permission.
        reading = self._make_reading(source_id=0x181)

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "FAIL")
        self.assertIn(
            "Source ID 0x181 is not authorized for action "
            "'sensor_data'.",
            result.reasons,
        )

    def test_revoked_source_fails(self) -> None:
        # Revocation overrides authentication and previous permission.
        self.policy.revoke_source(0x180)
        reading = self._make_reading(source_id=0x180)

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "FAIL")
        self.assertIn(
            "Source ID 0x180 is revoked.",
            result.reasons,
        )

    def test_restored_source_can_pass_again(self) -> None:
        # Restoring a known source makes its original permission active again.
        self.policy.revoke_source(0x180)
        self.policy.restore_source(0x180)
        reading = self._make_reading(source_id=0x180)

        result = self.validator.validate_sensor_reading(reading)

        self.assertEqual(result.status, "PASS")


if __name__ == "__main__":
    unittest.main()
