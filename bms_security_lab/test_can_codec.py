import unittest

from .can_codec import (
    BMSCANCodec,
    CANAuthenticationError,
    CANDecodeError,
    CANIdentifierError,
    CANIntegrityError,
)
from .can_frame import CANFrame, CANFrameValidationError
from .sensor_reading import BatterySensorReading


class TestBMSCANCodec(unittest.TestCase):
    """Test virtual CAN/CAN-FD structure and BMS payload decoding."""

    def setUp(self) -> None:
        self.codec = BMSCANCodec(byteorder="big")

    def _make_reading(
        self,
        soc_percent: float = 65.0,
        voltage_v: float = 720.0,
        current_a: float = 20.0,
        temperature_c: float = 35.0,
    ) -> BatterySensorReading:
        return BatterySensorReading(
            soc_percent=soc_percent,
            pack_voltage_v=voltage_v,
            pack_current_a=current_a,
            max_temperature_c=temperature_c,
            source_id=0x180,
            sequence_counter=1,
            authenticated=True,
        )

    def test_valid_soc_payload_decodes_expected_values(self) -> None:
        reading = self._make_reading()
        frame = self.codec.encode_sensor_reading(reading)

        decoded = self.codec.decode_sensor_frame(frame)

        self.assertAlmostEqual(decoded.soc_percent, 65.0)
        self.assertAlmostEqual(decoded.pack_voltage_v, 720.0)
        self.assertAlmostEqual(decoded.pack_current_a, 20.0)
        self.assertAlmostEqual(decoded.max_temperature_c, 35.0)

    def test_payload_too_short_raises_decode_error(self) -> None:
        frame = CANFrame(
            arbitration_id=0x180,
            data=b"\x00" * 7,
            dlc=7,
            timestamp_s=0.0,
            channel="virtual",
        )

        with self.assertRaisesRegex(
            CANDecodeError,
            "exactly 8 bytes",
        ):
            self.codec.decode_sensor_frame(frame)

    def test_payload_too_long_is_rejected(self) -> None:
        frame = CANFrame(
            arbitration_id=0x180,
            data=b"\x00" * 12,
            dlc=9,
            timestamp_s=0.0,
            channel="virtual",
            is_fd=True,
        )

        with self.assertRaisesRegex(
            CANDecodeError,
            "exactly 8 bytes",
        ):
            self.codec.decode_sensor_frame(frame)

    def test_wrong_endianness_changes_interpreted_value(self) -> None:
        frame = self.codec.encode_sensor_reading(
            self._make_reading(soc_percent=65.0)
        )
        wrong_codec = BMSCANCodec(byteorder="little")

        decoded = wrong_codec.decode_sensor_frame(frame)

        self.assertNotEqual(decoded.soc_percent, 65.0)

    def test_invalid_arbitration_id_is_rejected(self) -> None:
        valid_frame = self.codec.encode_sensor_reading(
            self._make_reading()
        )
        wrong_id = CANFrame(
            arbitration_id=0x181,
            data=valid_frame.data,
            dlc=valid_frame.dlc,
            timestamp_s=valid_frame.timestamp_s,
            channel=valid_frame.channel,
            application_crc_valid=True,
        )

        with self.assertRaises(CANIdentifierError):
            self.codec.decode_sensor_frame(wrong_id)

    def test_corrupt_application_crc_fails_integrity(self) -> None:
        valid_frame = self.codec.encode_sensor_reading(
            self._make_reading()
        )
        corrupted_data = (
            valid_frame.data[:-1]
            + bytes((valid_frame.data[-1] ^ 0xFF,))
        )
        corrupted_frame = CANFrame(
            arbitration_id=valid_frame.arbitration_id,
            data=corrupted_data,
            dlc=valid_frame.dlc,
            timestamp_s=valid_frame.timestamp_s,
            channel=valid_frame.channel,
            application_crc_valid=False,
        )

        with self.assertRaisesRegex(
            CANIntegrityError,
            "error detection",
        ):
            self.codec.decode_sensor_frame(corrupted_frame)

    def test_dlc_mismatch_is_rejected(self) -> None:
        frame = CANFrame(
            arbitration_id=0x180,
            data=b"\x00" * 8,
            dlc=7,
            timestamp_s=0.0,
            channel="virtual",
        )

        with self.assertRaisesRegex(
            CANDecodeError,
            "frame contains 8",
        ):
            self.codec.decode_sensor_frame(frame)

    def test_corrupt_mac_metadata_fails_authenticity_policy(self) -> None:
        protected_codec = BMSCANCodec(
            byteorder="big",
            require_mac_metadata=True,
        )
        frame = protected_codec.encode_sensor_reading(
            self._make_reading(),
            mac_valid=False,
        )

        with self.assertRaises(CANAuthenticationError):
            protected_codec.decode_sensor_frame(frame)

    def test_negative_current_uses_signed_decoding(self) -> None:
        frame = self.codec.encode_sensor_reading(
            self._make_reading(current_a=-125.5)
        )

        decoded = self.codec.decode_sensor_frame(frame)

        self.assertAlmostEqual(decoded.pack_current_a, -125.5)

    def test_minimum_and_maximum_values_round_trip(self) -> None:
        minimum = self.codec.encode_sensor_reading(
            self._make_reading(
                soc_percent=0.0,
                voltage_v=0.0,
                current_a=-1000.0,
                temperature_c=-40.0,
            )
        )
        maximum = self.codec.encode_sensor_reading(
            self._make_reading(
                soc_percent=100.0,
                voltage_v=1000.0,
                current_a=1000.0,
                temperature_c=85.0,
            )
        )

        decoded_minimum = self.codec.decode_sensor_frame(minimum)
        decoded_maximum = self.codec.decode_sensor_frame(maximum)

        self.assertEqual(decoded_minimum.soc_percent, 0.0)
        self.assertEqual(decoded_minimum.max_temperature_c, -40.0)
        self.assertEqual(decoded_maximum.soc_percent, 100.0)
        self.assertEqual(decoded_maximum.max_temperature_c, 85.0)

    def test_can_fd_dlc_mapping_accepts_discrete_payload_size(self) -> None:
        frame = CANFrame(
            arbitration_id=0x180,
            data=b"\x00" * 12,
            dlc=9,
            timestamp_s=0.0,
            channel="virtual",
            is_fd=True,
        )

        frame.validate_protocol()
        self.assertEqual(frame.expected_data_length(), 12)

    def test_classical_can_rejects_payload_over_eight_bytes(self) -> None:
        frame = CANFrame(
            arbitration_id=0x180,
            data=b"\x00" * 9,
            dlc=9,
            timestamp_s=0.0,
            channel="virtual",
            is_fd=False,
        )

        with self.assertRaises(CANFrameValidationError):
            frame.validate_protocol()


if __name__ == "__main__":
    unittest.main()
