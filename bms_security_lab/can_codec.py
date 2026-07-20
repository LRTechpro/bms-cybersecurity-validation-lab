SOC_SCALE = 10
SOC_MIN = 0.0
SOC_MAX = 100.0


def encode_soc(soc_percent: float) -> bytes:
    """Convert an SOC percentage into a two-byte CAN payload."""

    if not SOC_MIN <= soc_percent <= SOC_MAX:
        raise ValueError(f"Invalid SOC value: {soc_percent}%")

    raw_value = int(round(soc_percent * SOC_SCALE))

    return raw_value.to_bytes(
        length=2,
        byteorder="big",
        signed=False,
    )


def decode_soc(data: bytes) -> float:
    """Convert a two-byte CAN payload back into an SOC percentage."""

    if len(data) != 2:
        raise ValueError("SOC payload must contain exactly two bytes.")

    raw_value = int.from_bytes(
        data,
        byteorder="big",
        signed=False,
    )

    return raw_value / SOC_SCALE