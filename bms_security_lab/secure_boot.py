from dataclasses import dataclass

from .crypto_provider import CryptoProvider, CryptoProviderError
from .firmware_manifest import FirmwareManifest, FirmwarePackage
from .trusted_key_store import TrustedKeyStore


@dataclass(frozen=True)
class BootVerificationContext:
    ecu_target: str
    hardware_profile: str
    accepted_security_version: int
    now_s: float
    recovery_authorized: bool = False


@dataclass(frozen=True)
class VerificationToken:
    """Digest snapshot used to detect verify-to-activate modification."""

    firmware_sha256: str
    manifest_sha256: str
    signer_id: str
    security_version: int


@dataclass(frozen=True)
class BootDecision:
    requirement_id: str
    status: str
    execute_allowed: bool
    reasons: tuple[str, ...]
    token: VerificationToken | None = None
    manifest: FirmwareManifest | None = None


class SecureBootVerifier:
    """Fail-closed verification over the exact stored package bytes."""

    REQUIREMENT_ID = "BMS-SEC-FW-001"

    def __init__(
        self,
        key_store: TrustedKeyStore,
        crypto_provider: CryptoProvider,
    ) -> None:
        self.key_store = key_store
        self.crypto_provider = crypto_provider

    def verify_package(
        self,
        package: FirmwarePackage,
        context: BootVerificationContext,
    ) -> BootDecision:
        reasons: list[str] = []
        manifest: FirmwareManifest | None = None

        try:
            manifest = FirmwareManifest.from_stored_bytes(package.manifest_bytes)
        except (TypeError, ValueError) as error:
            return self._failure(f"Manifest parse failed: {error}")

        if context.now_s < manifest.issued_at_s:
            reasons.append("Manifest is not yet valid.")
        if context.now_s > manifest.expires_at_s:
            reasons.append("Manifest is expired.")

        if not self.key_store.is_known(manifest.signer_id):
            reasons.append("Manifest signer is unknown.")
        elif self.key_store.is_revoked(manifest.signer_id):
            reasons.append("Manifest signer is revoked.")

        trusted_key = self.key_store.get_current_key(
            manifest.signer_id,
            context.now_s,
        )
        if trusted_key is None and not any(
            word in reason for reason in reasons for word in ("unknown", "revoked")
        ):
            reasons.append("Signer key is outside its validity interval.")

        if trusted_key is not None:
            try:
                signature_valid = self.crypto_provider.verify_ed25519(
                    trusted_key.public_key_bytes,
                    package.signature,
                    package.manifest_bytes,
                )
            except (CryptoProviderError, RuntimeError) as error:
                reasons.append(f"Cryptographic provider failed closed: {error}")
            else:
                if not signature_valid:
                    reasons.append("Manifest signature is invalid.")

        try:
            actual_image_hash = self.crypto_provider.sha256_hex(
                package.firmware_bytes
            )
        except RuntimeError as error:
            reasons.append(f"Image hashing failed closed: {error}")
            actual_image_hash = ""

        if actual_image_hash != manifest.image_sha256:
            reasons.append("Firmware image hash does not match the manifest.")

        if manifest.ecu_target != context.ecu_target:
            reasons.append("Firmware ECU target is incorrect.")

        if context.hardware_profile not in manifest.hardware_profiles:
            reasons.append("Firmware is incompatible with the hardware profile.")

        if (
            manifest.security_version < context.accepted_security_version
            and not context.recovery_authorized
        ):
            reasons.append("Firmware security version violates anti-rollback policy.")

        if reasons:
            return BootDecision(
                requirement_id=self.REQUIREMENT_ID,
                status="FAIL",
                execute_allowed=False,
                reasons=tuple(reasons),
                manifest=manifest,
            )

        token = VerificationToken(
            firmware_sha256=actual_image_hash,
            manifest_sha256=self.crypto_provider.sha256_hex(
                package.manifest_bytes
            ),
            signer_id=manifest.signer_id,
            security_version=manifest.security_version,
        )
        return BootDecision(
            requirement_id=self.REQUIREMENT_ID,
            status="PASS",
            execute_allowed=True,
            reasons=(),
            token=token,
            manifest=manifest,
        )

    def verify_for_activation(
        self,
        package: FirmwarePackage,
        context: BootVerificationContext,
        previous_token: VerificationToken,
    ) -> BootDecision:
        """Reverify stored bytes and compare them to the prior verification."""
        decision = self.verify_package(package, context)
        if not decision.execute_allowed or decision.token is None:
            return decision
        if decision.token != previous_token:
            return self._failure(
                "Stored firmware or manifest changed after initial verification."
            )
        return decision

    def _failure(self, reason: str) -> BootDecision:
        return BootDecision(
            requirement_id=self.REQUIREMENT_ID,
            status="FAIL",
            execute_allowed=False,
            reasons=(reason,),
        )
