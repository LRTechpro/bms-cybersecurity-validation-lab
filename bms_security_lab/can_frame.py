from dataclasses import dataclass


class CANFrameValidationError(ValueError):
    """Raised when a CAN or CAN-FD frame violates protocol structure."""


CLASSICAL_CAN_MAX_DATA_LENGTH = 8

# CAN-FD DLC values 9 through 15 represent discrete payload lengths.
CAN_FD_DLC_TO_LENGTH: dict[int, int] = {
    **{value: value for value in range(0, 9)},
    9: 12,
    10: 16,
    11: 20,
    12: 24,
    13: 32,
    14: 48,
    15: 64,
}


@dataclass(frozen=True)
class CANFrame:
    """Represent one virtual CAN or CAN-FD frame."""

    arbitration_id: int
    data: bytes
    dlc: int
    timestamp_s: float
    channel: str
    is_fd: bool = False
    is_extended_id: bool = False
    application_crc_valid: bool | None = None
    mac_valid: bool | None = None

    def __post_init__(self) -> None:
        # Normalize byte-like input while keeping the frame immutable.
        if not isinstance(self.data, bytes):
            try:
                object.__setattr__(self, "data", bytes(self.data))
            except (TypeError, ValueError) as error:
                raise TypeError(
                    "CAN frame data must be bytes or byte-like."
                ) from error

        if not isinstance(self.arbitration_id, int):
            raise TypeError("Arbitration ID must be an integer.")

        if not isinstance(self.dlc, int):
            raise TypeError("DLC must be an integer.")

        if self.timestamp_s < 0:
            raise CANFrameValidationError(
                "Timestamp must be zero or greater."
            )

        if not self.channel.strip():
            raise CANFrameValidationError(
                "Channel cannot be empty."
            )

    def expected_data_length(self) -> int:
        """Return the payload length represented by this frame's DLC."""

        if self.is_fd:
            if self.dlc not in CAN_FD_DLC_TO_LENGTH:
                raise CANFrameValidationError(
                    f"CAN-FD DLC {self.dlc} is outside the valid range "
                    "0 through 15."
                )
            return CAN_FD_DLC_TO_LENGTH[self.dlc]

        if not 0 <= self.dlc <= CLASSICAL_CAN_MAX_DATA_LENGTH:
            raise CANFrameValidationError(
                "Classical CAN DLC must be between 0 and 8."
            )
        return self.dlc

    def validate_protocol(self) -> None:
        """Reject invalid identifier, DLC, and payload-length combinations."""

        maximum_id = 0x1FFFFFFF if self.is_extended_id else 0x7FF
        identifier_type = "extended" if self.is_extended_id else "standard"

        if not 0 <= self.arbitration_id <= maximum_id:
            raise CANFrameValidationError(
                f"Arbitration ID 0x{self.arbitration_id:X} is invalid "
                f"for a {identifier_type} CAN frame."
            )

        expected_length = self.expected_data_length()
        actual_length = len(self.data)

        if actual_length != expected_length:
            raise CANFrameValidationError(
                f"DLC {self.dlc} represents {expected_length} data bytes, "
                f"but the frame contains {actual_length}."
            )
