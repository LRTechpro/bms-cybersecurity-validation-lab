from dataclasses import dataclass
from enum import Enum

from .firmware_manifest import FirmwarePackage
from .secure_boot import (
    BootDecision,
    BootVerificationContext,
    SecureBootVerifier,
    VerificationToken,
)


class UpdateState(str, Enum):
    IDLE = "IDLE"
    VERIFIED = "VERIFIED"
    INSTALLING = "INSTALLING"
    PENDING_HEALTH = "PENDING_HEALTH"
    ACTIVE = "ACTIVE"
    RECOVERY = "RECOVERY"
    ROLLED_BACK = "ROLLED_BACK"
    SAFE = "SAFE"


@dataclass(frozen=True)
class UpdateResult:
    status: str
    state: UpdateState
    reasons: tuple[str, ...]


class UpdateManager:
    """Model interruption, health checks, activation, and recovery."""

    def __init__(self, accepted_security_version: int = 0) -> None:
        self.accepted_security_version = accepted_security_version
        self.state = UpdateState.IDLE
        self.events: list[str] = []
        self._staged_package: FirmwarePackage | None = None
        self._verification_token: VerificationToken | None = None

    def install(
        self,
        package: FirmwarePackage,
        decision: BootDecision,
        interrupt: bool = False,
    ) -> UpdateResult:
        if not decision.execute_allowed or decision.token is None:
            self.state = UpdateState.SAFE
            self.events.append("INSTALL_REJECTED")
            return UpdateResult(
                status="FAIL",
                state=self.state,
                reasons=("Unverified firmware cannot be installed.",),
            )

        self.state = UpdateState.VERIFIED
        self._staged_package = package
        self._verification_token = decision.token
        self.events.append("PACKAGE_VERIFIED")

        self.state = UpdateState.INSTALLING
        if interrupt:
            self.state = UpdateState.RECOVERY
            self.events.append("INSTALL_INTERRUPTED")
            return UpdateResult(
                status="FAIL",
                state=self.state,
                reasons=("Installation was interrupted; recovery is required.",),
            )

        self.state = UpdateState.PENDING_HEALTH
        self.events.append("INSTALL_COMPLETE_PENDING_HEALTH")
        return UpdateResult(status="PASS", state=self.state, reasons=())

    def activate(
        self,
        verifier: SecureBootVerifier,
        context: BootVerificationContext,
        post_install_health_ok: bool,
        package_override: FirmwarePackage | None = None,
    ) -> UpdateResult:
        if self.state is not UpdateState.PENDING_HEALTH:
            return UpdateResult(
                status="FAIL",
                state=self.state,
                reasons=("No verified installation is pending activation.",),
            )
        if self._staged_package is None or self._verification_token is None:
            self.state = UpdateState.SAFE
            return UpdateResult(
                status="FAIL",
                state=self.state,
                reasons=("Verification state is incomplete.",),
            )

        stored_package = package_override or self._staged_package
        activation_decision = verifier.verify_for_activation(
            package=stored_package,
            context=context,
            previous_token=self._verification_token,
        )
        if not activation_decision.execute_allowed:
            self.state = UpdateState.SAFE
            self.events.append("ACTIVATION_REVERIFY_FAILED")
            return UpdateResult(
                status="FAIL",
                state=self.state,
                reasons=activation_decision.reasons,
            )

        if not post_install_health_ok:
            self.state = UpdateState.ROLLED_BACK
            self.events.append("POST_INSTALL_HEALTH_FAILED")
            return UpdateResult(
                status="FAIL",
                state=self.state,
                reasons=("Post-install health check failed; rollback required.",),
            )

        self.state = UpdateState.ACTIVE
        self.accepted_security_version = max(
            self.accepted_security_version,
            activation_decision.token.security_version,
        )
        self.events.append("FIRMWARE_ACTIVATED")
        return UpdateResult(status="PASS", state=self.state, reasons=())

    def start_verified_recovery(
        self,
        recovery_decision: BootDecision,
    ) -> UpdateResult:
        """Start recovery only after separate full package verification."""
        if not recovery_decision.execute_allowed:
            self.state = UpdateState.SAFE
            self.events.append("RECOVERY_IMAGE_REJECTED")
            return UpdateResult(
                status="FAIL",
                state=self.state,
                reasons=("Recovery image failed verification.",),
            )
        self.state = UpdateState.RECOVERY
        self.events.append("VERIFIED_RECOVERY_STARTED")
        return UpdateResult(status="PASS", state=self.state, reasons=())
