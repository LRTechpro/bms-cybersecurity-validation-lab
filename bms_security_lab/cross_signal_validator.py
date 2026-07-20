# Import the sensor-reading object evaluated by this phase.
from .sensor_reading import BatterySensorReading

# Import the shared validation result and base validator contract.
from .validator import ValidationResult, Validator


class CrossSignalValidator(Validator):
    """Detect internally inconsistent BMS measurements."""

    REQUIREMENT_ID = "BMS-SEC-SEN-003"

    def __init__(
        self,
        low_soc_threshold_percent: float = 20.0,
        high_soc_threshold_percent: float = 80.0,
        low_voltage_threshold_v: float = 650.0,
        high_voltage_threshold_v: float = 760.0,
        redundant_soc_tolerance_percent: float = 3.0,
        redundant_voltage_tolerance_v: float = 10.0,
        redundant_current_tolerance_a: float = 15.0,
        redundant_temperature_tolerance_c: float = 3.0,
    ) -> None:
        # These are configurable training limits, not production BMS values.
        self.low_soc_threshold_percent = low_soc_threshold_percent
        self.high_soc_threshold_percent = high_soc_threshold_percent
        self.low_voltage_threshold_v = low_voltage_threshold_v
        self.high_voltage_threshold_v = high_voltage_threshold_v

        # Redundant sources may differ slightly because of normal sensor error.
        self.redundant_soc_tolerance_percent = (
            redundant_soc_tolerance_percent
        )
        self.redundant_voltage_tolerance_v = (
            redundant_voltage_tolerance_v
        )
        self.redundant_current_tolerance_a = (
            redundant_current_tolerance_a
        )
        self.redundant_temperature_tolerance_c = (
            redundant_temperature_tolerance_c
        )

        if low_soc_threshold_percent >= high_soc_threshold_percent:
            raise ValueError(
                "Low SOC threshold must be below the high SOC threshold."
            )

        if low_voltage_threshold_v >= high_voltage_threshold_v:
            raise ValueError(
                "Low voltage threshold must be below the high voltage threshold."
            )

        tolerances = (
            redundant_soc_tolerance_percent,
            redundant_voltage_tolerance_v,
            redundant_current_tolerance_a,
            redundant_temperature_tolerance_c,
        )
        if any(value < 0 for value in tolerances):
            raise ValueError("Redundant-source tolerances cannot be negative.")

    def validate_sensor_reading(
        self,
        reading: BatterySensorReading,
    ) -> ValidationResult:
        """Evaluate configured relationships within one sensor reading."""

        reasons: list[str] = []

        # Low SOC combined with very high voltage is internally inconsistent.
        if (
            reading.soc_percent <= self.low_soc_threshold_percent
            and reading.pack_voltage_v >= self.high_voltage_threshold_v
        ):
            reasons.append(
                f"Low SOC {reading.soc_percent}% conflicts with high pack "
                f"voltage {reading.pack_voltage_v} V."
            )

        # High SOC combined with very low voltage is also inconsistent.
        if (
            reading.soc_percent >= self.high_soc_threshold_percent
            and reading.pack_voltage_v <= self.low_voltage_threshold_v
        ):
            reasons.append(
                f"High SOC {reading.soc_percent}% conflicts with low pack "
                f"voltage {reading.pack_voltage_v} V."
            )

        return self._build_result(reasons)

    def validate_redundant_sources(
        self,
        primary: BatterySensorReading,
        redundant: BatterySensorReading,
    ) -> ValidationResult:
        """Compare two independently sourced readings."""

        reasons: list[str] = []

        # A redundant comparison requires two distinct source identities.
        if primary.source_id == redundant.source_id:
            reasons.append(
                "Redundant readings must come from different source IDs."
            )

        soc_difference = abs(
            primary.soc_percent - redundant.soc_percent
        )
        if soc_difference > self.redundant_soc_tolerance_percent:
            reasons.append(
                f"Redundant SOC difference {soc_difference:.2f}% exceeds "
                f"the {self.redundant_soc_tolerance_percent:.2f}% test limit."
            )

        voltage_difference = abs(
            primary.pack_voltage_v - redundant.pack_voltage_v
        )
        if voltage_difference > self.redundant_voltage_tolerance_v:
            reasons.append(
                f"Redundant voltage difference {voltage_difference:.2f} V "
                f"exceeds the {self.redundant_voltage_tolerance_v:.2f} V "
                "test limit."
            )

        current_difference = abs(
            primary.pack_current_a - redundant.pack_current_a
        )
        if current_difference > self.redundant_current_tolerance_a:
            reasons.append(
                f"Redundant current difference {current_difference:.2f} A "
                f"exceeds the {self.redundant_current_tolerance_a:.2f} A "
                "test limit."
            )

        temperature_difference = abs(
            primary.max_temperature_c
            - redundant.max_temperature_c
        )
        if (
            temperature_difference
            > self.redundant_temperature_tolerance_c
        ):
            reasons.append(
                "Redundant temperature difference "
                f"{temperature_difference:.2f} C exceeds the "
                f"{self.redundant_temperature_tolerance_c:.2f} C "
                "test limit."
            )

        return self._build_result(reasons)

    def validate_complete_relationships(
        self,
        primary: BatterySensorReading,
        redundant: BatterySensorReading,
    ) -> ValidationResult:
        """Run cross-signal and redundant-source checks together."""

        primary_result = self.validate_sensor_reading(primary)
        redundant_result = self.validate_sensor_reading(redundant)
        pair_result = self.validate_redundant_sources(
            primary,
            redundant,
        )

        # Combine all reasons so one execution exposes every inconsistency.
        reasons = (
            primary_result.reasons
            + redundant_result.reasons
            + pair_result.reasons
        )
        return self._build_result(list(reasons))

    def _build_result(
        self,
        reasons: list[str],
    ) -> ValidationResult:
        """Create one consistent validation result."""

        return ValidationResult(
            requirement_id=self.REQUIREMENT_ID,
            status="FAIL" if reasons else "PASS",
            reasons=tuple(reasons),
        )
