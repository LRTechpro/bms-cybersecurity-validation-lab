# Import the sensor-reading object being validated.
from .sensor_reading import BatterySensorReading

# Import the shared validation contract and result object.
from .validator import ValidationResult, Validator


class ReplayValidator(Validator):
    """Detect duplicate, stale, and out-of-order sensor messages."""

    REQUIREMENT_ID = "BMS-SEC-COM-001"

    def __init__(
        self,
        max_counter: int = 255,
    ) -> None:
        # The counter wraps to zero after reaching this value.
        if max_counter < 1:
            raise ValueError(
                "Maximum sequence counter must be at least 1."
            )

        self.max_counter = max_counter

        # Store the last accepted counter separately for each source.
        self._last_counter_by_source: dict[int, int] = {}

        # Store the last accepted timestamp separately for each source.
        self._last_timestamp_by_source: dict[int, float] = {}

    def validate_sensor_reading(
        self,
        reading: BatterySensorReading,
        timestamp_s: float | None = None,
    ) -> ValidationResult:
        """Check the reading's counter and timestamp for freshness."""

        reasons: list[str] = []

        source_id = reading.source_id
        current_counter = reading.sequence_counter

        # Reject counters outside the configured simulation range.
        if (
            current_counter < 0
            or current_counter > self.max_counter
        ):
            reasons.append(
                f"Sequence counter {current_counter} is outside "
                f"the allowed range 0 through {self.max_counter}."
            )

        # Reject invalid simulated timestamps.
        if timestamp_s is not None and timestamp_s < 0:
            reasons.append(
                "Timestamp must be zero or greater."
            )

        last_counter = self._last_counter_by_source.get(
            source_id
        )
        last_timestamp_s = self._last_timestamp_by_source.get(
            source_id
        )

        # A new source has no accepted history to compare against.
        if last_counter is not None:
            expected_counter = (
                0
                if last_counter == self.max_counter
                else last_counter + 1
            )

            # Reusing the same counter represents a duplicate.
            if current_counter == last_counter:
                reasons.append(
                    f"Duplicate sequence counter "
                    f"{current_counter} received from source "
                    f"0x{source_id:X}."
                )

            # A lower counter is out of order unless valid wraparound applies.
            elif (
                current_counter < last_counter
                and not (
                    last_counter == self.max_counter
                    and current_counter == 0
                )
            ):
                reasons.append(
                    f"Out-of-order sequence counter "
                    f"{current_counter}; last accepted counter "
                    f"was {last_counter}."
                )

            # A counter that skips forward is suspicious.
            elif current_counter != expected_counter:
                reasons.append(
                    f"Unexpected sequence-counter jump from "
                    f"{last_counter} to {current_counter}; "
                    f"expected {expected_counter}."
                )

        # A timestamp must advance beyond the last accepted timestamp.
        if (
            timestamp_s is not None
            and last_timestamp_s is not None
            and timestamp_s <= last_timestamp_s
        ):
            reasons.append(
                f"Stale timestamp {timestamp_s}; last accepted "
                f"timestamp was {last_timestamp_s}."
            )

        status = "FAIL" if reasons else "PASS"

        return ValidationResult(
            requirement_id=self.REQUIREMENT_ID,
            status=status,
            reasons=tuple(reasons),
        )

    def record_accepted_reading(
        self,
        reading: BatterySensorReading,
        timestamp_s: float | None = None,
    ) -> None:
        """Record freshness state only after all required checks pass."""

        if timestamp_s is not None and timestamp_s < 0:
            raise ValueError(
                "Timestamp must be zero or greater."
            )

        source_id = reading.source_id

        # Save the accepted counter for this specific source.
        self._last_counter_by_source[source_id] = (
            reading.sequence_counter
        )

        # Save the timestamp only when one was supplied.
        if timestamp_s is not None:
            self._last_timestamp_by_source[source_id] = (
                timestamp_s
            )

    def get_last_counter(
        self,
        source_id: int,
    ) -> int | None:
        """Return the last accepted counter for one source."""

        return self._last_counter_by_source.get(source_id)