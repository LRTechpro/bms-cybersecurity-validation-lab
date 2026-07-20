import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FirmwareManifest:
    """Security metadata signed as exact canonical JSON bytes."""

    firmware_id: str
    ecu_target: str
    hardware_profiles: tuple[str, ...]
    software_version: str
    security_version: int
    image_sha256: str
    signer_id: str
    issued_at_s: float
    expires_at_s: float

    def __post_init__(self) -> None:
        if not self.firmware_id.strip() or not self.ecu_target.strip():
            raise ValueError("Firmware identity and ECU target are required.")
        if not self.hardware_profiles:
            raise ValueError("At least one hardware profile is required.")
        if self.security_version < 0:
            raise ValueError("Security version must be zero or greater.")
        if len(self.image_sha256) != 64:
            raise ValueError("Image SHA-256 must contain 64 hexadecimal characters.")
        try:
            int(self.image_sha256, 16)
        except ValueError as error:
            raise ValueError("Image SHA-256 must be hexadecimal.") from error
        if not self.signer_id.strip():
            raise ValueError("Signer identity is required.")
        if self.issued_at_s < 0 or self.expires_at_s <= self.issued_at_s:
            raise ValueError("Manifest validity interval is invalid.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecu_target": self.ecu_target,
            "expires_at_s": self.expires_at_s,
            "firmware_id": self.firmware_id,
            "hardware_profiles": list(self.hardware_profiles),
            "image_sha256": self.image_sha256,
            "issued_at_s": self.issued_at_s,
            "security_version": self.security_version,
            "signer_id": self.signer_id,
            "software_version": self.software_version,
        }

    def to_canonical_bytes(self) -> bytes:
        """Produce the documented stable representation used for signing."""
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    @classmethod
    def from_stored_bytes(cls, stored_bytes: bytes) -> "FirmwareManifest":
        """Parse stored bytes without replacing them for signature checks."""
        try:
            raw = json.loads(stored_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Stored manifest is not valid UTF-8 JSON.") from error

        required = {
            "ecu_target",
            "expires_at_s",
            "firmware_id",
            "hardware_profiles",
            "image_sha256",
            "issued_at_s",
            "security_version",
            "signer_id",
            "software_version",
        }
        if not isinstance(raw, dict) or set(raw) != required:
            raise ValueError("Stored manifest schema is incomplete or unexpected.")

        return cls(
            firmware_id=str(raw["firmware_id"]),
            ecu_target=str(raw["ecu_target"]),
            hardware_profiles=tuple(str(item) for item in raw["hardware_profiles"]),
            software_version=str(raw["software_version"]),
            security_version=int(raw["security_version"]),
            image_sha256=str(raw["image_sha256"]),
            signer_id=str(raw["signer_id"]),
            issued_at_s=float(raw["issued_at_s"]),
            expires_at_s=float(raw["expires_at_s"]),
        )


@dataclass(frozen=True)
class FirmwarePackage:
    """Exact stored firmware, manifest, and signature bytes."""

    firmware_bytes: bytes
    manifest_bytes: bytes
    signature: bytes

    def __post_init__(self) -> None:
        for field_name in ("firmware_bytes", "manifest_bytes", "signature"):
            value = getattr(self, field_name)
            if not isinstance(value, bytes):
                raise TypeError(f"{field_name} must be bytes.")
        if not self.firmware_bytes or not self.manifest_bytes or not self.signature:
            raise ValueError("Firmware, manifest, and signature bytes are required.")
