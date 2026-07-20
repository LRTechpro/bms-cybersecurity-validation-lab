from dataclasses import dataclass

from .can_frame import CANFrame, CANFrameValidationError
from .sensor_reading import BatterySensorReading


class CANCodecError(ValueError):
    """Base error for BMS CAN encoding and decoding."""


class CANDecodeError(CANCodecError):
    """Raised when frame content cannot be decoded safely."""


class CANIdentifierError(CANDecodeError):
    """Raised when a frame uses an unexpected arbitration ID."""


class CANIntegrityError(CANDecodeError):
    """Raised when application-level error-detection data is invalid."""


class CANAuthenticationError(CANDecodeError):
    """Raised when required MAC metadata is missing or invalid."""


@dataclass(frozen=True)
class DecodedBMSData:
    """Decoded BMS values extracted from one payload."""

    soc_percent: float
    pack_voltage_v: float
    pack_current_a: float
    max_temperature_c: float


class BMSCANCodec:
    """Encode and decode the lab's virtual BMS CAN payload."""

    EXPECTED_ARBITRATION_ID = 0x180
    PAYLOAD_LENGTH = 8

    SOC_SCALE_PERCENT = 0.1
    VOLTAGE_SCALE_V = 0.1
    CURRENT_SCALE_A = 0.1
    TEMPERATURE_OFFSET_C = -40.0

    def __init__(
        self,
        byteorder: str = "big",
        require_mac_metadata: bool = False,
    ) -> None:
        if byteorder not in {"big", "little"}:
            raise ValueError("Byte order must be 'big' or 'little'.")

        self.byteorder = byteorder
        self.require_mac_metadata = require_mac_metadata

    def encode_sensor_reading(
        self,
        reading: BatterySensorReading,
        timestamp_s: float = 0.0,
        channel: str = "virtual",
        mac_valid: bool | None = None,
    ) -> CANFrame:
        """Encode one high-level sensor object into an eight-byte payload."""

        self._validate_encodable_ranges(reading)

        soc_raw = round(reading.soc_percent / self.SOC_SCALE_PERCENT)
        voltage_raw = round(
            reading.pack_voltage_v / self.VOLTAGE_SCALE_V
        )
        current_raw = round(
            reading.pack_current_a / self.CURRENT_SCALE_A
        )
        temperature_raw = round(
            reading.max_temperature_c - self.TEMPERATURE_OFFSET_C
        )

        payload_without_crc = b"".join(
            (
                soc_raw.to_bytes(2, self.byteorder, signed=False),
                voltage_raw.to_bytes(2, self.byteorder, signed=False),
                current_raw.to_bytes(2, self.byteorder, signed=True),
                temperature_raw.to_bytes(1, "big", signed=False),
            )
        )

        application_crc = self.calculate_crc8(payload_without_crc)
        payload = payload_without_crc + bytes((application_crc,))

        return CANFrame(
            arbitration_id=self.EXPECTED_ARBITRATION_ID,
            data=payload,
            dlc=self.PAYLOAD_LENGTH,
            timestamp_s=timestamp_s,
            channel=channel,
            is_fd=False,
            application_crc_valid=True,
            mac_valid=mac_valid,
        )

    def decode_sensor_frame(
        self,
        frame: CANFrame,
    ) -> DecodedBMSData:
        """Validate frame structure and decode its BMS measurements."""

        try:
            frame.validate_protocol()
        except CANFrameValidationError as error:
            raise CANDecodeError(str(error)) from error

        if frame.arbitration_id != self.EXPECTED_ARBITRATION_ID:
            raise CANIdentifierError(
                f"Unexpected arbitration ID 0x{frame.arbitration_id:X}; "
                f"expected 0x{self.EXPECTED_ARBITRATION_ID:X}."
            )

        if len(frame.data) != self.PAYLOAD_LENGTH:
            raise CANDecodeError(
                f"BMS payload must contain exactly {self.PAYLOAD_LENGTH} "
                f"bytes; received {len(frame.data)}."
            )

        payload_without_crc = frame.data[:-1]
        received_crc = frame.data[-1]
        calculated_crc = self.calculate_crc8(payload_without_crc)

        # This application CRC detects corruption; it does not authenticate.
        if (
            frame.application_crc_valid is False
            or received_crc != calculated_crc
        ):
            raise CANIntegrityError(
                "Application CRC check failed. CRC provides error detection, "
                "not cryptographic authenticity."
            )

        # MAC handling is a policy model only in this phase.
        if self.require_mac_metadata and frame.mac_valid is not True:
            raise CANAuthenticationError(
                "Required MAC metadata is missing or invalid."
            )

        soc_raw = int.from_bytes(
            frame.data[0:2],
            self.byteorder,
            signed=False,
        )
        voltage_raw = int.from_bytes(
            frame.data[2:4],
            self.byteorder,
            signed=False,
        )
        current_raw = int.from_bytes(
            frame.data[4:6],
            self.byteorder,
            signed=True,
        )
        temperature_raw = frame.data[6]

        return DecodedBMSData(
            soc_percent=soc_raw * self.SOC_SCALE_PERCENT,
            pack_voltage_v=voltage_raw * self.VOLTAGE_SCALE_V,
            pack_current_a=current_raw * self.CURRENT_SCALE_A,
            max_temperature_c=(
                temperature_raw + self.TEMPERATURE_OFFSET_C
            ),
        )

    @staticmethod
    def calculate_crc8(data: bytes) -> int:
        """Calculate CRC-8 over application payload bytes."""

        crc = 0xFF
        polynomial = 0x1D

        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x80:
                    crc = ((crc << 1) ^ polynomial) & 0xFF
                else:
                    crc = (crc << 1) & 0xFF

        return crc

    @staticmethod
    def _validate_encodable_ranges(
        reading: BatterySensorReading,
    ) -> None:
        """Keep encoding limits separate from plausibility decisions."""

        limits = (
            ("SOC", reading.soc_percent, 0.0, 100.0),
            ("Voltage", reading.pack_voltage_v, 0.0, 1000.0),
            ("Current", reading.pack_current_a, -1000.0, 1000.0),
            (
                "Temperature",
                reading.max_temperature_c,
                -40.0,
                85.0,
            ),
        )

        for name, value, minimum, maximum in limits:
            if not minimum <= value <= maximum:
                raise CANCodecError(
                    f"{name} {value} is outside the encodable range "
                    f"{minimum} through {maximum}."
                )
