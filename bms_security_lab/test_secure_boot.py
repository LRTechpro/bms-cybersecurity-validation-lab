import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto_provider import (
    CryptoProvider,
    CryptoProviderError,
    Ed25519CryptoProvider,
)
from .firmware_manifest import FirmwareManifest, FirmwarePackage
from .secure_boot import BootVerificationContext, SecureBootVerifier
from .trusted_key_store import TrustedKeyStore, TrustedPublicKey
from .update_manager import UpdateManager, UpdateState


class FaultyCryptoProvider(CryptoProvider):
    def sha256_hex(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def verify_ed25519(
        self,
        public_key_bytes: bytes,
        signature: bytes,
        message: bytes,
    ) -> bool:
        raise CryptoProviderError("simulated provider failure")


def make_signer(
    signer_id: str = "lab-root",
    valid_until_s: float = 1000.0,
) -> tuple[Ed25519PrivateKey, TrustedPublicKey]:
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, TrustedPublicKey(
        signer_id=signer_id,
        public_key_bytes=public_bytes,
        valid_from_s=0.0,
        valid_until_s=valid_until_s,
    )


def make_package(
    private_key: Ed25519PrivateKey,
    signer_id: str = "lab-root",
    firmware_bytes: bytes = b"trusted-bms-firmware-v2",
    ecu_target: str = "BMS-A",
    hardware_profiles: tuple[str, ...] = ("PACK-192S",),
    security_version: int = 2,
    expires_at_s: float = 500.0,
) -> FirmwarePackage:
    manifest = FirmwareManifest(
        firmware_id="BMS-FW-2",
        ecu_target=ecu_target,
        hardware_profiles=hardware_profiles,
        software_version="2.0.0",
        security_version=security_version,
        image_sha256=hashlib.sha256(firmware_bytes).hexdigest(),
        signer_id=signer_id,
        issued_at_s=0.0,
        expires_at_s=expires_at_s,
    )
    manifest_bytes = manifest.to_canonical_bytes()
    return FirmwarePackage(
        firmware_bytes=firmware_bytes,
        manifest_bytes=manifest_bytes,
        signature=private_key.sign(manifest_bytes),
    )


def make_verifier(*keys: TrustedPublicKey) -> SecureBootVerifier:
    return SecureBootVerifier(
        key_store=TrustedKeyStore(tuple(keys)),
        crypto_provider=Ed25519CryptoProvider(),
    )


def context(
    accepted_security_version: int = 1,
    recovery_authorized: bool = False,
    ecu_target: str = "BMS-A",
    hardware_profile: str = "PACK-192S",
) -> BootVerificationContext:
    return BootVerificationContext(
        ecu_target=ecu_target,
        hardware_profile=hardware_profile,
        accepted_security_version=accepted_security_version,
        now_s=100.0,
        recovery_authorized=recovery_authorized,
    )


def test_trusted_signed_compatible_package_passes() -> None:
    private_key, public_key = make_signer()
    decision = make_verifier(public_key).verify_package(
        make_package(private_key),
        context(),
    )
    assert decision.status == "PASS"
    assert decision.execute_allowed is True
    assert decision.token is not None


def test_invalid_signature_fails() -> None:
    private_key, public_key = make_signer()
    package = make_package(private_key)
    invalid = FirmwarePackage(
        package.firmware_bytes,
        package.manifest_bytes,
        bytes([package.signature[0] ^ 0x01]) + package.signature[1:],
    )
    decision = make_verifier(public_key).verify_package(invalid, context())
    assert decision.status == "FAIL"
    assert decision.execute_allowed is False
    assert any("signature" in reason.lower() for reason in decision.reasons)


def test_corrupted_firmware_image_fails_hash_check() -> None:
    private_key, public_key = make_signer()
    package = make_package(private_key)
    corrupted = FirmwarePackage(
        package.firmware_bytes + b"tamper",
        package.manifest_bytes,
        package.signature,
    )
    decision = make_verifier(public_key).verify_package(corrupted, context())
    assert decision.status == "FAIL"
    assert any("hash" in reason.lower() for reason in decision.reasons)


def test_wrong_ecu_target_fails() -> None:
    private_key, public_key = make_signer()
    decision = make_verifier(public_key).verify_package(
        make_package(private_key, ecu_target="OTHER-ECU"),
        context(),
    )
    assert decision.status == "FAIL"
    assert any("target" in reason.lower() for reason in decision.reasons)


def test_incompatible_hardware_profile_fails() -> None:
    private_key, public_key = make_signer()
    decision = make_verifier(public_key).verify_package(
        make_package(private_key, hardware_profiles=("PACK-96S",)),
        context(),
    )
    assert decision.status == "FAIL"
    assert any("hardware" in reason.lower() for reason in decision.reasons)


def test_older_security_version_fails_rollback_policy() -> None:
    private_key, public_key = make_signer()
    decision = make_verifier(public_key).verify_package(
        make_package(private_key, security_version=1),
        context(accepted_security_version=2),
    )
    assert decision.status == "FAIL"
    assert any("rollback" in reason.lower() for reason in decision.reasons)


def test_power_loss_during_install_enters_recovery() -> None:
    private_key, public_key = make_signer()
    package = make_package(private_key)
    decision = make_verifier(public_key).verify_package(package, context())
    result = UpdateManager().install(package, decision, interrupt=True)
    assert result.status == "FAIL"
    assert result.state is UpdateState.RECOVERY


def test_post_install_health_failure_rolls_back() -> None:
    private_key, public_key = make_signer()
    package = make_package(private_key)
    verifier = make_verifier(public_key)
    decision = verifier.verify_package(package, context())
    manager = UpdateManager()
    assert manager.install(package, decision).status == "PASS"
    result = manager.activate(verifier, context(), post_install_health_ok=False)
    assert result.status == "FAIL"
    assert result.state is UpdateState.ROLLED_BACK


def test_expired_manifest_fails() -> None:
    private_key, public_key = make_signer()
    package = make_package(private_key, expires_at_s=50.0)
    decision = make_verifier(public_key).verify_package(package, context())
    assert decision.status == "FAIL"
    assert any("expired" in reason.lower() for reason in decision.reasons)


def test_revoked_signer_fails() -> None:
    private_key, public_key = make_signer()
    store = TrustedKeyStore((public_key,))
    store.revoke("lab-root", actor="security-admin")
    verifier = SecureBootVerifier(store, Ed25519CryptoProvider())
    decision = verifier.verify_package(make_package(private_key), context())
    assert decision.status == "FAIL"
    assert any("revoked" in reason.lower() for reason in decision.reasons)


def test_unknown_public_key_fails_without_execution() -> None:
    private_key, _ = make_signer(signer_id="unknown-signer")
    decision = make_verifier().verify_package(
        make_package(private_key, signer_id="unknown-signer"),
        context(),
    )
    assert decision.status == "FAIL"
    assert decision.execute_allowed is False
    assert any("unknown" in reason.lower() for reason in decision.reasons)


def test_manifest_changed_after_signing_fails() -> None:
    private_key, public_key = make_signer()
    package = make_package(private_key)
    changed = FirmwarePackage(
        package.firmware_bytes,
        package.manifest_bytes + b" ",
        package.signature,
    )
    decision = make_verifier(public_key).verify_package(changed, context())
    assert decision.status == "FAIL"
    assert any("signature" in reason.lower() for reason in decision.reasons)


def test_crypto_provider_error_fails_closed() -> None:
    private_key, public_key = make_signer()
    verifier = SecureBootVerifier(
        TrustedKeyStore((public_key,)),
        FaultyCryptoProvider(),
    )
    decision = verifier.verify_package(make_package(private_key), context())
    assert decision.status == "FAIL"
    assert decision.execute_allowed is False
    assert any("failed closed" in reason.lower() for reason in decision.reasons)


def test_authorized_public_key_rotation_accepts_new_key() -> None:
    old_private, old_public = make_signer("old-root")
    new_private, new_public = make_signer("new-root")
    store = TrustedKeyStore((old_public,))
    store.rotate(new_public, actor="security-admin", authenticated=True)
    verifier = SecureBootVerifier(store, Ed25519CryptoProvider())
    decision = verifier.verify_package(
        make_package(new_private, signer_id="new-root"),
        context(),
    )
    assert decision.status == "PASS"
    assert any(entry.startswith("ROTATE:new-root") for entry in store.audit_log)
    assert old_private is not None


def test_runtime_modules_do_not_contain_signing_private_key_material() -> None:
    runtime_files = (
        "firmware_manifest.py",
        "trusted_key_store.py",
        "crypto_provider.py",
        "secure_boot.py",
        "firmware_validator.py",
        "update_manager.py",
    )
    package_dir = Path(__file__).parent
    for filename in runtime_files:
        source = (package_dir / filename).read_text(encoding="utf-8")
        assert "Ed25519PrivateKey" not in source
        assert "BEGIN PRIVATE KEY" not in source


def test_valid_recovery_image_starts_only_after_full_verification() -> None:
    primary_private, primary_public = make_signer("primary")
    recovery_private, recovery_public = make_signer("recovery")
    verifier = make_verifier(primary_public, recovery_public)
    primary = make_package(primary_private, signer_id="primary")
    broken_primary = FirmwarePackage(
        primary.firmware_bytes + b"broken",
        primary.manifest_bytes,
        primary.signature,
    )
    assert verifier.verify_package(broken_primary, context()).status == "FAIL"

    recovery = make_package(recovery_private, signer_id="recovery")
    recovery_decision = verifier.verify_package(recovery, context())
    result = UpdateManager().start_verified_recovery(recovery_decision)
    assert recovery_decision.status == "PASS"
    assert result.status == "PASS"
    assert result.state is UpdateState.RECOVERY


def test_image_modified_between_verification_and_activation_is_blocked() -> None:
    private_key, public_key = make_signer()
    package = make_package(private_key)
    verifier = make_verifier(public_key)
    decision = verifier.verify_package(package, context())
    manager = UpdateManager()
    assert manager.install(package, decision).status == "PASS"

    modified = FirmwarePackage(
        package.firmware_bytes + b"after-verification-change",
        package.manifest_bytes,
        package.signature,
    )
    result = manager.activate(
        verifier,
        context(),
        post_install_health_ok=True,
        package_override=modified,
    )
    assert result.status == "FAIL"
    assert result.state is UpdateState.SAFE


def test_semantically_identical_reserialized_manifest_fails_exact_byte_signature() -> None:
    private_key, public_key = make_signer()
    package = make_package(private_key)
    parsed = json.loads(package.manifest_bytes)
    reserialized = json.dumps(parsed, sort_keys=False, indent=2).encode("utf-8")
    assert json.loads(reserialized) == parsed
    changed = FirmwarePackage(
        package.firmware_bytes,
        reserialized,
        package.signature,
    )
    decision = make_verifier(public_key).verify_package(changed, context())
    assert decision.status == "FAIL"
    assert any("signature" in reason.lower() for reason in decision.reasons)


def test_older_version_with_authorized_recovery_passes_and_logs_event() -> None:
    private_key, public_key = make_signer()
    verifier = make_verifier(public_key)
    decision = verifier.verify_package(
        make_package(private_key, security_version=1),
        context(accepted_security_version=2, recovery_authorized=True),
    )
    assert decision.status == "PASS"
    assert decision.execute_allowed is True
    assert any(
        event.startswith("AUTHORIZED_RECOVERY_ROLLBACK")
        for event in verifier.events
    )
