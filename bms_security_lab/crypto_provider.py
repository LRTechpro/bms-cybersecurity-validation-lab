import hashlib
from abc import ABC, abstractmethod

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class CryptoProviderError(RuntimeError):
    """Raised when the cryptographic provider cannot complete safely."""


class CryptoProvider(ABC):
    """Abstract cryptographic boundary that can later map to secure hardware."""

    @abstractmethod
    def sha256_hex(self, data: bytes) -> str:
        raise NotImplementedError

    @abstractmethod
    def verify_ed25519(
        self,
        public_key_bytes: bytes,
        signature: bytes,
        message: bytes,
    ) -> bool:
        raise NotImplementedError


class Ed25519CryptoProvider(CryptoProvider):
    """Local lab provider using vetted library primitives."""

    def sha256_hex(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def verify_ed25519(
        self,
        public_key_bytes: bytes,
        signature: bytes,
        message: bytes,
    ) -> bool:
        try:
            key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except (TypeError, ValueError) as error:
            raise CryptoProviderError(
                "Ed25519 verification input is malformed."
            ) from error
