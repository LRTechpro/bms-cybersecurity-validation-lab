# Import the sensor reading and history objects used for comparison.
from .sensor_history import SensorHistory
from .sensor_reading import BatterySensorReading

# Import the shared validator contract and result object.
from .validator import ValidationResult, Validator


class PlausibilityValidator(Validator):
    """Detect sensor values that change too quickly to be believable."""

    REQUIREMENT_ID = "BMS-SEC-SEN-002"

    def __init__(
        self,
        history: SensorHistory,
        max_soc_change_per_s: float = 5.0,
        max_voltage_change_v_per_s: float = 50.0,
        max_temperature_change_c_per_s: float = 2.0,
        soc_direction_tolerance_percent: float = 0.1,
        positive_current_means_charging: bool = True,
    ) -> None:
        # Store the accepted-reading history used for comparisons.
        self.history = history

        # Store configurable training limits.
        self.max_soc_change_per_s = max_soc_change_per_s
        self.max_voltage_change_v_per_s = (
            max_voltage_change_v_per_s
        )
        self.max_temperature_change_c_per_s = (
            max_temperature_change_c_per_s
        )

        # Ignore very small SOC changes that may represent normal noise.
        self.soc_direction_tolerance_percent = (
            soc_direction_tolerance_percent
        )

        # Define the current-sign convention used by this simulation.
        self.positive_current_means_charging = (
            positive_current_means_charging
        )

        # Rate limits must be greater than zero.
        if (
            max_soc_change_per_s <= 0
            or max_voltage_change_v_per_s <= 0
            or max_temperature_change_c_per_s <= 0
        ):
            raise ValueError(
                "Plausibility limits must be greater than zero."
            )

        # Noise tolerance may be zero, but it cannot be negative.
        if soc_direction_tolerance_percent < 0:
            raise ValueError(
                "SOC direction tolerance cannot be negative."
            )

    def validate_sensor_reading(
        self,
        reading: BatterySensorReading,
        timestamp_s: float | None = None,
    ) -> ValidationResult:
        """Compare the current reading with accepted history."""

        # A timestamp is required to calculate change over time.
        if timestamp_s is None:
            return ValidationResult(
                requirement_id=self.REQUIREMENT_ID,
                status="FAIL",
                reasons=("A timestamp is required.",),
            )

        if timestamp_s < 0:
            return ValidationResult(
                requirement_id=self.REQUIREMENT_ID,
                status="FAIL",
                reasons=("Timestamp must be zero or greater.",),
            )

        # The first reading has no earlier value for comparison.
        if not self.history.has_previous_reading():
            return ValidationResult(
                requirement_id=self.REQUIREMENT_ID,
                status="PASS",
                reasons=(),
            )

        previous = self.history.get_previous_reading()
        previous_timestamp_s = (
            self.history.get_previous_timestamp_s()
        )

        # These values exist because history reported a previous reading.
        assert previous is not None
        assert previous_timestamp_s is not None

        elapsed_s = timestamp_s - previous_timestamp_s

        # Time must move forward before rates can be calculated.
        if elapsed_s <= 0:
            return ValidationResult(
                requirement_id=self.REQUIREMENT_ID,
                status="FAIL",
                reasons=(
                    "Current timestamp must be later than "
                    "the previous timestamp.",
                ),
            )

        # Collect every plausibility problem found.
        reasons: list[str] = []

        # Calculate the absolute SOC rate of change.
        soc_change = reading.soc_percent - previous.soc_percent
        soc_rate = abs(soc_change) / elapsed_s

        if soc_rate > self.max_soc_change_per_s:
            reasons.append(
                f"SOC changed at {soc_rate:.2f}%/s, above the "
                f"{self.max_soc_change_per_s:.2f}%/s test limit."
            )

        # Check whether current direction agrees with SOC direction.
        if (
            abs(soc_change)
            > self.soc_direction_tolerance_percent
        ):
            if self.positive_current_means_charging:
                charging_current = reading.pack_current_a > 0
                discharging_current = reading.pack_current_a < 0
            else:
                charging_current = reading.pack_current_a < 0
                discharging_current = reading.pack_current_a > 0

            # SOC should not rise while current indicates discharge.
            if soc_change > 0 and discharging_current:
                reasons.append(
                    "SOC increased while current indicated discharge."
                )

            # SOC should not fall while current indicates charging.
            if soc_change < 0 and charging_current:
                reasons.append(
                    "SOC decreased while current indicated charging."
                )

        # Calculate the absolute pack-voltage rate of change.
        voltage_rate = (
            abs(
                reading.pack_voltage_v
                - previous.pack_voltage_v
            )
            / elapsed_s
        )

        if voltage_rate > self.max_voltage_change_v_per_s:
            reasons.append(
                f"Voltage changed at {voltage_rate:.2f} V/s, "
                f"above the "
                f"{self.max_voltage_change_v_per_s:.2f} V/s "
                "test limit."
            )

        # Calculate the absolute temperature rate of change.
        temperature_rate = (
            abs(
                reading.max_temperature_c
                - previous.max_temperature_c
            )
            / elapsed_s
        )

        if (
            temperature_rate
            > self.max_temperature_change_c_per_s
        ):
            reasons.append(
                f"Temperature changed at "
                f"{temperature_rate:.2f} C/s, above the "
                f"{self.max_temperature_change_c_per_s:.2f} "
                "C/s test limit."
            )

        # Any recorded reason causes validation to fail.
        status = "FAIL" if reasons else "PASS"

        return ValidationResult(
            requirement_id=self.REQUIREMENT_ID,
            status=status,
            reasons=tuple(reasons),
        )