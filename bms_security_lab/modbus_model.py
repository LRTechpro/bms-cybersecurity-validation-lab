from dataclasses import dataclass
from enum import Enum


class ModbusFunction(str, Enum):
    READ_HOLDING_REGISTERS = "READ_HOLDING_REGISTERS"
    WRITE_SINGLE_REGISTER = "WRITE_SINGLE_REGISTER"
    WRITE_MULTIPLE_REGISTERS = "WRITE_MULTIPLE_REGISTERS"

    @property
    def is_write(self) -> bool:
        return self in {
            ModbusFunction.WRITE_SINGLE_REGISTER,
            ModbusFunction.WRITE_MULTIPLE_REGISTERS,
        }


class NetworkZone(str, Enum):
    MONITORING = "MONITORING"
    CONTROL = "CONTROL"
    SERVICE = "SERVICE"
    UNTRUSTED = "UNTRUSTED"


@dataclass(frozen=True)
class ClientSession:
    """Authentication and network context supplied by a local mock session."""

    client_id: str
    role: str
    zone: NetworkZone
    authenticated: bool
    certificate_revoked: bool = False

    def __post_init__(self) -> None:
        if not self.client_id.strip() or not self.role.strip():
            raise ValueError("Client identity and role are required.")


@dataclass(frozen=True)
class ModbusRequest:
    """Local request model; it never opens a network connection."""

    function: ModbusFunction
    start_address: int
    quantity: int
    timestamp_s: float
    values: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if self.start_address < 0:
            raise ValueError("Register address must be zero or greater.")
        if self.quantity < 1:
            raise ValueError("Register quantity must be at least one.")
        if self.timestamp_s < 0:
            raise ValueError("Timestamp must be zero or greater.")
        if self.function.is_write and len(self.values) != self.quantity:
            raise ValueError("Write requests require one value per register.")
        if not self.function.is_write and self.values:
            raise ValueError("Read requests cannot carry write values.")
