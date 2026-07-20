# Import the BMS objects used in this demonstration.
from .sensor_reading import BatterySensorReading
from .trusted_state import TrustedBMSState
from .validator import BMSValidator


def apply_reading_if_valid(
    state: TrustedBMSState,
    reading: BatterySensorReading,
    validator: BMSValidator,
) -> str:
    """Update trusted SOC only when the reading passes validation."""

    # Ask the validator whether the received sensor reading is acceptable.
    result = validator.validate_sensor_reading(reading)

    # Only validated data is allowed to change trusted BMS state.
    if result.status == "PASS":
        state.update_soc(reading.soc_percent)

    # Return the decision so the caller can report or test it.
    return result.status


def main() -> None:
    # Start with a known trusted SOC and create the range validator.
    state = TrustedBMSState(soc_percent=75.0)
    validator = BMSValidator()

    # Normal reading: all values are within the configured test ranges.
    legitimate_reading = BatterySensorReading(
        soc_percent=82.0,
        pack_voltage_v=720.0,
        pack_current_a=40.0,
        max_temperature_c=35.0,
        source_id=0x180,
        sequence_counter=1,
        authenticated=True,
    )

    # Spoofed reading: only SOC changes, allowing a controlled comparison.
    spoofed_reading = BatterySensorReading(
        soc_percent=145.0,
        pack_voltage_v=720.0,
        pack_current_a=40.0,
        max_temperature_c=35.0,
        source_id=0x180,
        sequence_counter=2,
        authenticated=True,
    )

    print(f"Initial trusted SOC: {state.get_soc()}%")

    # The legitimate reading should pass and update trusted SOC.
    legitimate_status = apply_reading_if_valid(
        state,
        legitimate_reading,
        validator,
    )

    print(f"Legitimate reading: {legitimate_status}")
    print(f"Trusted SOC: {state.get_soc()}%")

    # The spoofed reading should fail and leave trusted SOC unchanged.
    spoofed_status = apply_reading_if_valid(
        state,
        spoofed_reading,
        validator,
    )

    print(f"Spoofed reading: {spoofed_status}")
    print(f"Trusted SOC: {state.get_soc()}%")


# Run main() only when this file is executed as a module or script.
if __name__ == "__main__":
    main()