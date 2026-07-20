"""Timing and missing-message monitoring for simulated BMS traffic."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AvailabilityDecision:
    """One availability verdict with a defined response action."""

    requirement_id: str
    status: str
    reasons: tuple[str, ...]
    action: str


class TimingMonitor:
    """Detect late, missing, and slow-processed critical messages."""

    MISSING_REQUIREMENT_ID = "BMS-SEC-AVA-001"
    PROCESSING_REQUIREMENT_ID = "BMS-SEC-AVA-002"

    def __init__(
        self,
        expected_periods_s: dict[int, float],
        timeout_periods: float = 2.0,
        timeout_margin_s: float = 0.01,
        processing_budget_s: float = 0.05,
    ) -> None:
        if not expected_periods_s:
            raise ValueError("At least one expected message period is required.")
        if any(period <= 0 for period in expected_periods_s.values()):
            raise ValueError("Expected message periods must be positive.")
        if timeout_periods < 1.0:
            raise ValueError("Timeout periods must be at least 1.0.")
        if timeout_margin_s < 0 or processing_budget_s <= 0:
            raise ValueError("Timing margins and budgets must be valid.")

        self.expected_periods_s = dict(expected_periods_s)
        self.timeout_periods = timeout_periods
        self.timeout_margin_s = timeout_margin_s
        self.processing_budget_s = processing_budget_s
        self._monitoring_start_s: float | None = None
        self._last_seen_s: dict[int, float] = {}

    def start(self, timestamp_s: float = 0.0) -> None:
        """Start the deterministic timing window."""

        if timestamp_s < 0:
            raise ValueError("Start timestamp cannot be negative.")
        self._monitoring_start_s = timestamp_s

    def record_message(
        self,
        arbitration_id: int,
        timestamp_s: float,
    ) -> AvailabilityDecision:
        """Record a configured message and evaluate its arrival interval."""

        if timestamp_s < 0:
            raise ValueError("Message timestamp cannot be negative.")
        if arbitration_id not in self.expected_periods_s:
            return AvailabilityDecision(
                requirement_id=self.MISSING_REQUIREMENT_ID,
                status="INFO",
                reasons=(
                    f"Message 0x{arbitration_id:X} is not timing-monitored.",
                ),
                action="NONE",
            )

        previous = self._last_seen_s.get(arbitration_id)
        self._last_seen_s[arbitration_id] = timestamp_s

        if previous is None:
            return self._pass(self.MISSING_REQUIREMENT_ID)

        if timestamp_s < previous:
            return AvailabilityDecision(
                requirement_id=self.MISSING_REQUIREMENT_ID,
                status="FAIL",
                reasons=("Message timestamp moved backward.",),
                action="ALERT",
            )

        period = self.expected_periods_s[arbitration_id]
        allowed_gap = (
            period * self.timeout_periods + self.timeout_margin_s
        )
        actual_gap = timestamp_s - previous

        if actual_gap > allowed_gap:
            return AvailabilityDecision(
                requirement_id=self.MISSING_REQUIREMENT_ID,
                status="FAIL",
                reasons=(
                    f"Message 0x{arbitration_id:X} arrived after "
                    f"{actual_gap:.6f}s; limit is {allowed_gap:.6f}s.",
                ),
                action="DEGRADED",
            )

        return self._pass(self.MISSING_REQUIREMENT_ID)

    def check_missing(self, now_s: float) -> list[AvailabilityDecision]:
        """Check every configured critical message for timeout."""

        if now_s < 0:
            raise ValueError("Current timestamp cannot be negative.")
        if self._monitoring_start_s is None:
            raise RuntimeError("Timing monitor must be started first.")

        decisions: list[AvailabilityDecision] = []
        for arbitration_id, period in self.expected_periods_s.items():
            reference = self._last_seen_s.get(
                arbitration_id,
                self._monitoring_start_s,
            )
            allowed_gap = (
                period * self.timeout_periods + self.timeout_margin_s
            )
            actual_gap = now_s - reference

            if actual_gap > allowed_gap:
                decisions.append(
                    AvailabilityDecision(
                        requirement_id=self.MISSING_REQUIREMENT_ID,
                        status="FAIL",
                        reasons=(
                            f"Critical message 0x{arbitration_id:X} missing "
                            f"for {actual_gap:.6f}s; timeout is "
                            f"{allowed_gap:.6f}s.",
                        ),
                        action="DEGRADED",
                    )
                )
            else:
                decisions.append(self._pass(self.MISSING_REQUIREMENT_ID))

        return decisions

    def evaluate_processing_latency(
        self,
        latency_s: float,
    ) -> AvailabilityDecision:
        """Fail processing that exceeds the configured simulation budget."""

        if latency_s < 0:
            raise ValueError("Processing latency cannot be negative.")

        if latency_s > self.processing_budget_s:
            return AvailabilityDecision(
                requirement_id=self.PROCESSING_REQUIREMENT_ID,
                status="FAIL",
                reasons=(
                    f"Processing latency {latency_s:.6f}s exceeds budget "
                    f"{self.processing_budget_s:.6f}s.",
                ),
                action="DEGRADED",
            )

        return self._pass(self.PROCESSING_REQUIREMENT_ID)

    @staticmethod
    def _pass(requirement_id: str) -> AvailabilityDecision:
        return AvailabilityDecision(
            requirement_id=requirement_id,
            status="PASS",
            reasons=(),
            action="NONE",
        )
