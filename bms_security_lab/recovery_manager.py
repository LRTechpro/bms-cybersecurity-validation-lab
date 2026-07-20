from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryDecision:
    status: str
    transition_allowed: bool
    reasons: tuple[str, ...]


class RecoveryManager:
    """Permit recovery only after trust and safety conditions pass."""

    def __init__(self, authorized_roles: set[str] | None = None) -> None:
        self.authorized_roles = set(authorized_roles or {"service", "safety-manager"})
        self.events: list[str] = []

    def request_recovery(
        self,
        actor: str,
        role: str,
        authenticated: bool,
        conditions_clear: bool,
        evidence_preserved: bool,
    ) -> RecoveryDecision:
        reasons: list[str] = []
        if not actor.strip() or not authenticated:
            reasons.append("Recovery requester is not authenticated.")
        if role not in self.authorized_roles:
            reasons.append("Recovery requester role is not authorized.")
        if not conditions_clear:
            reasons.append("Recovery conditions have not cleared.")
        if not evidence_preserved:
            reasons.append("Original failure evidence must be preserved first.")

        if reasons:
            self.events.append(f"RECOVERY_REJECTED:{actor or 'unknown'}")
            return RecoveryDecision(
                status="FAIL",
                transition_allowed=False,
                reasons=tuple(reasons),
            )

        self.events.append(f"RECOVERY_AUTHORIZED:{actor}")
        return RecoveryDecision(
            status="PASS",
            transition_allowed=True,
            reasons=(),
        )
