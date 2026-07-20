# Import the object that represents one received BMS sensor reading.
from .sensor_reading import BatterySensorReading


class SensorHistory:
    """Store the most recently accepted sensor reading and timestamp."""

    def __init__(self) -> None:
        # No reading has been accepted when the history object is created.
        self._previous_reading: BatterySensorReading | None = None

        # Time is measured in seconds for this simulation.
        self._previous_timestamp_s: float | None = None

    def has_previous_reading(self) -> bool:
        """Return True when an accepted reading already exists."""

        return (
            self._previous_reading is not None
            and self._previous_timestamp_s is not None
        )

    def get_previous_reading(
        self,
    ) -> BatterySensorReading | None:
        """Return the previously accepted reading, if one exists."""

        return self._previous_reading

    def get_previous_timestamp_s(self) -> float | None:
        """Return the timestamp of the previous accepted reading."""

        return self._previous_timestamp_s

    def record_accepted_reading(
        self,
        reading: BatterySensorReading,
        timestamp_s: float,
    ) -> None:
        """Store a reading only after validation has accepted it."""

        # Prevent an invalid simulated timestamp from entering history.
        if timestamp_s < 0:
            raise ValueError("Timestamp must be zero or greater.")

        # Replace the old history with the newly accepted reading.
        self._previous_reading = reading
        self._previous_timestamp_s = timestamp_s