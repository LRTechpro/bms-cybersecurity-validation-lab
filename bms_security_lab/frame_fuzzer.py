"""Deterministic structured fuzzing for the virtual BMS CAN interface."""

from __future__ import annotations

from dataclasses import dataclass
import json
import random
from typing import Any

from .can_codec import BMSCANCodec, CANCodecError
from .can_frame import CANFrame, CANFrameValidationError, CAN_FD_DLC_TO_LENGTH


@dataclass(frozen=True)
class FuzzCase:
    """One fully reproducible fuzz input."""

    case_index: int
    seed: int
    arbitration_id: int
    data: bytes
    dlc: int
    timestamp_s: float
    is_fd: bool
    is_extended_id: bool
    metadata: Any = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation for evidence capture."""

        return {
            "case_index": self.case_index,
            "seed": self.seed,
            "arbitration_id": self.arbitration_id,
            "data_hex": self.data.hex(),
            "data_length": len(self.data),
            "dlc": self.dlc,
            "timestamp_s": self.timestamp_s,
            "is_fd": self.is_fd,
            "is_extended_id": self.is_extended_id,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Serialize the exact case without failing on unusual text."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=True,
            sort_keys=True,
            default=repr,
        )


@dataclass(frozen=True)
class FuzzResult:
    """Outcome of one isolated fuzz execution."""

    case: FuzzCase
    status: str
    reason: str


class FrameFuzzer:
    """Generate bounded CAN/CAN-FD inputs from a deterministic seed."""

    def __init__(
        self,
        seed: int,
        max_iterations: int = 500,
    ) -> None:
        if max_iterations < 1:
            raise ValueError("Maximum iterations must be at least 1.")

        self.seed = seed
        self.max_iterations = max_iterations
        self._random = random.Random(seed)

    def generate_case(self, case_index: int) -> FuzzCase:
        """Generate one controlled frame candidate with length 0 through 64."""

        if case_index < 0:
            raise ValueError("Case index cannot be negative.")

        payload_length = self._random.randint(0, 64)
        data = bytes(
            self._random.randrange(0, 256)
            for _ in range(payload_length)
        )

        is_fd = self._random.choice((False, True))
        is_extended_id = self._random.choice((False, False, False, True))

        # Mix expected, merely valid, and deliberately invalid identifiers.
        identifier_choices = [
            BMSCANCodec.EXPECTED_ARBITRATION_ID,
            self._random.randint(0, 0x7FF),
            0x800,
            -1,
        ]
        if is_extended_id:
            identifier_choices.append(
                self._random.randint(0, 0x1FFFFFFF)
            )
        arbitration_id = self._random.choice(identifier_choices)

        dlc = self._select_dlc(payload_length, is_fd)
        timestamp_s = round(self._random.uniform(0.0, 60.0), 6)

        return FuzzCase(
            case_index=case_index,
            seed=self.seed,
            arbitration_id=arbitration_id,
            data=data,
            dlc=dlc,
            timestamp_s=timestamp_s,
            is_fd=is_fd,
            is_extended_id=is_extended_id,
            metadata={"label": f"case-{case_index}"},
        )

    def generate_cases(self, iterations: int) -> list[FuzzCase]:
        """Generate a bounded campaign so resource use remains controlled."""

        if not 0 <= iterations <= self.max_iterations:
            raise ValueError(
                f"Iterations must be between 0 and {self.max_iterations}."
            )

        return [self.generate_case(index) for index in range(iterations)]

    def evaluate_case(
        self,
        case: FuzzCase,
        codec: BMSCANCodec | None = None,
    ) -> FuzzResult:
        """Decode one case while isolating expected parser failures."""

        active_codec = codec or BMSCANCodec()

        try:
            frame = CANFrame(
                arbitration_id=case.arbitration_id,
                data=case.data,
                dlc=case.dlc,
                timestamp_s=case.timestamp_s,
                channel="fuzz",
                is_fd=case.is_fd,
                is_extended_id=case.is_extended_id,
            )
            active_codec.decode_sensor_frame(frame)
        except (CANCodecError, CANFrameValidationError, TypeError, ValueError) as error:
            return FuzzResult(case=case, status="FAIL", reason=str(error))
        except Exception as error:  # pragma: no cover - safety net for new parsers
            return FuzzResult(
                case=case,
                status="ERROR",
                reason=f"Unhandled {type(error).__name__}: {error}",
            )

        return FuzzResult(case=case, status="PASS", reason="Decoded safely.")

    def run_campaign(
        self,
        iterations: int,
        codec: BMSCANCodec | None = None,
    ) -> list[FuzzResult]:
        """Execute every generated case without stopping on one failure."""

        return [
            self.evaluate_case(case, codec)
            for case in self.generate_cases(iterations)
        ]

    def _select_dlc(self, payload_length: int, is_fd: bool) -> int:
        """Sometimes match the payload and sometimes create a mismatch."""

        choose_matching = self._random.choice((True, False))

        if is_fd:
            length_to_dlc = {
                length: dlc
                for dlc, length in CAN_FD_DLC_TO_LENGTH.items()
            }
            if choose_matching and payload_length in length_to_dlc:
                return length_to_dlc[payload_length]
            return self._random.randint(0, 15)

        if choose_matching and payload_length <= 8:
            return payload_length
        return self._random.randint(0, 8)
