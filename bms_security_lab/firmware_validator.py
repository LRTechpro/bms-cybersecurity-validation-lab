from .firmware_manifest import FirmwarePackage
from .secure_boot import (
    BootDecision,
    BootVerificationContext,
    SecureBootVerifier,
    VerificationToken,
)


class FirmwareValidator:
    """Present one validation boundary to boot and update orchestration."""

    def __init__(self, verifier: SecureBootVerifier) -> None:
        self.verifier = verifier

    def validate_for_install(
        self,
        package: FirmwarePackage,
        context: BootVerificationContext,
    ) -> BootDecision:
        return self.verifier.verify_package(package, context)

    def validate_for_activation(
        self,
        package: FirmwarePackage,
        context: BootVerificationContext,
        token: VerificationToken,
    ) -> BootDecision:
        return self.verifier.verify_for_activation(package, context, token)
