from dataclasses import dataclass


@dataclass(frozen=True)
class BatterySensorReading:
    """Represents one received set of BMS sensor values."""

    soc_percent: float
    pack_voltage_v: float
    pack_current_a: float
    max_temperature_c: float
    source_id: int
    sequence_counter: int
    authenticated: bool = False