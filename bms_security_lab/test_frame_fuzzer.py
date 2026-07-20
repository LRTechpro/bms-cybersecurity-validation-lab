"""Phase 10 tests for deterministic structured fuzzing."""

import json
import random
import unittest

from .can_codec import BMSCANCodec
from .frame_fuzzer import FrameFuzzer, FuzzCase
from .replay_validator import ReplayValidator
from .sensor_reading import BatterySensorReading


class TestFrameFuzzer(unittest.TestCase):
    def test_same_seed_reproduces_identical_cases(self) -> None:
        first = FrameFuzzer(seed=21434).generate_cases(50)
        second = FrameFuzzer(seed=21434).generate_cases(50)

        self.assertEqual(first, second)

    def test_random_payload_lengths_never_escape_exception_isolation(self) -> None:
        fuzzer = FrameFuzzer(seed=10, max_iterations=300)
        results = fuzzer.run_campaign(300)

        self.assertTrue(
            all(0 <= len(result.case.data) <= 64 for result in results)
        )
        self.assertFalse(any(result.status == "ERROR" for result in results))

    def test_every_one_byte_value_has_a_defined_result(self) -> None:
        fuzzer = FrameFuzzer(seed=11)

        results = []
        for value in range(256):
            case = FuzzCase(
                case_index=value,
                seed=11,
                arbitration_id=BMSCANCodec.EXPECTED_ARBITRATION_ID,
                data=bytes((value,)),
                dlc=1,
                timestamp_s=float(value),
                is_fd=False,
                is_extended_id=False,
            )
            results.append(fuzzer.evaluate_case(case))

        self.assertEqual(len(results), 256)
        self.assertTrue(
            all(result.status in {"PASS", "FAIL"} for result in results)
        )

    def test_invalid_metadata_remains_json_serializable(self) -> None:
        case = FuzzCase(
            case_index=1,
            seed=12,
            arbitration_id=0x180,
            data=b"\x00",
            dlc=1,
            timestamp_s=0.0,
            is_fd=False,
            is_extended_id=False,
            metadata={"invalid_unicode": "\udcff", "object": object()},
        )

        serialized = case.to_json()
        restored = json.loads(serialized)

        self.assertEqual(restored["case_index"], 1)
        self.assertIn("invalid_unicode", restored["metadata"])

    def test_iteration_limit_bounds_resource_use(self) -> None:
        fuzzer = FrameFuzzer(seed=13, max_iterations=5)

        with self.assertRaises(ValueError):
            fuzzer.generate_cases(6)

    def test_valid_encode_decode_round_trip_is_stable(self) -> None:
        codec = BMSCANCodec()

        for soc in (0.0, 10.5, 50.0, 82.3, 100.0):
            reading = BatterySensorReading(
                soc_percent=soc,
                pack_voltage_v=720.4,
                pack_current_a=-25.6,
                max_temperature_c=37.0,
                source_id=0x180,
                sequence_counter=1,
                authenticated=True,
            )

            decoded = codec.decode_sensor_frame(
                codec.encode_sensor_reading(reading)
            )

            self.assertAlmostEqual(decoded.soc_percent, soc, places=1)
            self.assertAlmostEqual(decoded.pack_voltage_v, 720.4, places=1)
            self.assertAlmostEqual(decoded.pack_current_a, -25.6, places=1)
            self.assertEqual(decoded.max_temperature_c, 37.0)

    def test_random_sequence_counters_produce_defined_replay_results(self) -> None:
        random_source = random.Random(27)
        validator = ReplayValidator(max_counter=255)

        for timestamp in range(1, 101):
            counter = random_source.randint(-10, 265)
            reading = BatterySensorReading(
                soc_percent=50.0,
                pack_voltage_v=700.0,
                pack_current_a=0.0,
                max_temperature_c=30.0,
                source_id=0x180,
                sequence_counter=counter,
                authenticated=True,
            )

            result = validator.validate_sensor_reading(
                reading,
                timestamp_s=float(timestamp),
            )
            self.assertIn(result.status, {"PASS", "FAIL"})

            if result.status == "PASS":
                validator.record_accepted_reading(
                    reading,
                    timestamp_s=float(timestamp),
                )

    def test_failing_case_preserves_exact_input(self) -> None:
        case = FuzzCase(
            case_index=99,
            seed=99,
            arbitration_id=0x800,
            data=b"\x01\x02\x03",
            dlc=3,
            timestamp_s=1.5,
            is_fd=False,
            is_extended_id=False,
        )

        result = FrameFuzzer(seed=99).evaluate_case(case)

        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.case.data, b"\x01\x02\x03")
        self.assertEqual(result.case.arbitration_id, 0x800)


if __name__ == "__main__":
    unittest.main()
