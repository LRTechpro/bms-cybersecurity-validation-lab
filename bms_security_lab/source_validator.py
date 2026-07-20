# Import the authorization policy used to evaluate each source.
from .authorization_policy import AuthorizationPolicy

# Import the received sensor-reading object.
from .sensor_reading import BatterySensorReading

# Import the shared validator contract and result object.
from .validator import ValidationResult, Validator


class SourceValidator(Validator):
    """Validate source identity, authentication, and authorization."""

    REQUIREMENT_ID = "BMS-SEC-COM-002"

    def __init__(
        self,
        policy: AuthorizationPolicy,
        required_action: str = "sensor_data",
    ) -> None:
        # Store the policy object used to make trust decisions.
        self.policy = policy

        # Store the action this validator expects the source to perform.
        self.required_action = required_action.strip()
        if not self.required_action:
            raise ValueError("Required action cannot be empty.")

    def validate_sensor_reading(
        self,
        reading: BatterySensorReading,
    ) -> ValidationResult:
        """Evaluate identity, revocation, authentication, and permission."""

        source_id = reading.source_id
        reasons: list[str] = []

        # Evaluate trust in a deliberate order so the failure is specific.
        if not self.policy.is_known_source(source_id):
            reasons.append(
                f"Unknown source ID 0x{source_id:X}."
            )
        elif self.policy.is_revoked(source_id):
            reasons.append(
                f"Source ID 0x{source_id:X} is revoked."
            )
        elif not reading.authenticated:
            reasons.append(
                f"Source ID 0x{source_id:X} is not authenticated."
            )
        elif not self.policy.is_authorized(
            source_id,
            self.required_action,
        ):
            reasons.append(
                f"Source ID 0x{source_id:X} is not authorized "
                f"for action '{self.required_action}'."
            )

        status = "FAIL" if reasons else "PASS"

        return ValidationResult(
            requirement_id=self.REQUIREMENT_ID,
            status=status,
            reasons=tuple(reasons),
        )
