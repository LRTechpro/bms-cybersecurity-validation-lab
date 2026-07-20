from dataclasses import dataclass

from .diagnostic_model import (
    DiagnosticRequest,
    DiagnosticService,
    DiagnosticSession,
    DiagnosticState,
)


@dataclass(frozen=True)
class DiagnosticResponse:
    requirement_id: str
    status: str
    response_code: str
    reasons: tuple[str, ...]


class DiagnosticValidator:
    """Model session, role, unlock, lockout, and programming order."""

    REQUIREMENT_ID = "BMS-SEC-DIA-001"

    def __init__(
        self,
        state: DiagnosticState | None = None,
        max_failed_attempts: int = 3,
        lockout_duration_s: float = 30.0,
    ) -> None:
        if max_failed_attempts < 1 or lockout_duration_s < 0:
            raise ValueError("Diagnostic lockout limits are invalid.")
        self.state = state or DiagnosticState()
        self.max_failed_attempts = max_failed_attempts
        self.lockout_duration_s = lockout_duration_s

    def process_request(self, request: DiagnosticRequest) -> DiagnosticResponse:
        reasons: list[str] = []

        if not request.authenticated:
            reasons.append("Diagnostic client is not authenticated.")

        if request.timestamp_s < self.state.lockout_until_s:
            reasons.append("Security access is temporarily locked out.")

        if reasons:
            return self._response(reasons, "NRC-0x33")

        service = request.service

        if service is DiagnosticService.READ_DATA:
            return self._response([], "POSITIVE")

        if service is DiagnosticService.SESSION_CONTROL:
            if request.target_session is None:
                return self._response(["Target session is required."], "NRC-0x13")
            self.state.session = request.target_session
            self.state.security_unlocked = False
            self.state.programming_step = 0
            return self._response([], "POSITIVE")

        if service is DiagnosticService.SECURITY_ACCESS:
            return self._process_security_access(request)

        if service is DiagnosticService.WRITE_CONFIGURATION:
            if self.state.session not in {
                DiagnosticSession.EXTENDED,
                DiagnosticSession.SUPPLIER,
            }:
                reasons.append("Configuration write is not allowed in this session.")
            if not self.state.security_unlocked:
                reasons.append("Configuration write requires security unlock.")
            if request.role not in {"service", "supplier"}:
                reasons.append("Role is not authorized for configuration write.")
            return self._response(reasons, "NRC-0x7E" if reasons else "POSITIVE")

        if service is DiagnosticService.CLEAR_FAULT:
            if request.role != "service" or not self.state.security_unlocked:
                reasons.append("Fault clear requires unlocked service role.")
            return self._response(reasons, "NRC-0x33" if reasons else "POSITIVE")

        return self._process_programming_service(request)

    def _process_security_access(
        self,
        request: DiagnosticRequest,
    ) -> DiagnosticResponse:
        if request.key_valid is True:
            self.state.security_unlocked = True
            self.state.failed_unlock_attempts = 0
            return self._response([], "POSITIVE")

        self.state.failed_unlock_attempts += 1
        reasons = ["Security access key is invalid."]
        if self.state.failed_unlock_attempts >= self.max_failed_attempts:
            self.state.lockout_until_s = (
                request.timestamp_s + self.lockout_duration_s
            )
            reasons.append("Security access lockout activated.")
        return self._response(reasons, "NRC-0x35")

    def _process_programming_service(
        self,
        request: DiagnosticRequest,
    ) -> DiagnosticResponse:
        service = request.service
        if self.state.session is not DiagnosticSession.PROGRAMMING:
            return self._response(
                ["Programming service requires programming session."],
                "NRC-0x7E",
            )
        if not self.state.security_unlocked:
            return self._response(
                ["Programming service requires security unlock."],
                "NRC-0x33",
            )
        if request.role not in {"service", "supplier"}:
            return self._response(
                ["Role is not authorized for programming."],
                "NRC-0x33",
            )

        expected_steps = {
            DiagnosticService.REQUEST_DOWNLOAD: 0,
            DiagnosticService.TRANSFER_DATA: 1,
            DiagnosticService.TRANSFER_EXIT: 2,
            DiagnosticService.VERIFY_IMAGE: 3,
            DiagnosticService.ECU_RESET: 4,
        }
        expected = expected_steps.get(service)
        if expected is None:
            return self._response(["Unsupported diagnostic service."], "NRC-0x11")

        if service is DiagnosticService.ECU_RESET and self.state.update_transfer_active:
            return self._response(
                ["ECU reset is blocked during active update transfer."],
                "NRC-0x22",
            )

        if self.state.programming_step != expected:
            return self._response(
                [
                    f"Programming sequence violation: expected step "
                    f"{self.state.programming_step}, received {expected}."
                ],
                "NRC-0x24",
            )

        if service is DiagnosticService.REQUEST_DOWNLOAD:
            self.state.update_transfer_active = True
        elif service is DiagnosticService.TRANSFER_EXIT:
            self.state.update_transfer_active = False

        self.state.programming_step += 1
        return self._response([], "POSITIVE")

    def _response(
        self,
        reasons: list[str],
        response_code: str,
    ) -> DiagnosticResponse:
        return DiagnosticResponse(
            requirement_id=self.REQUIREMENT_ID,
            status="FAIL" if reasons else "PASS",
            response_code=response_code,
            reasons=tuple(reasons),
        )
