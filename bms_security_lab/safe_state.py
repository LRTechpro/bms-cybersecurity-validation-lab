from dataclasses import dataclass
from enum import Enum


class OperatingMode(str, Enum):
    PARKED = "PARKED"
    DRIVING = "DRIVING"
    CHARGING = "CHARGING"


class SafeAction(str, Enum):
    BLOCK_STATE_UPDATE = "BLOCK_STATE_UPDATE"
    MARK_SOC_STALE = "MARK_SOC_STALE"
    LIMIT_POWER = "LIMIT_POWER"
    REQUEST_CONTACTOR_OPEN = "REQUEST_CONTACTOR_OPEN"
    PRESERVE_COOLING = "PRESERVE_COOLING"
    STOP_CHARGE_REQUEST = "STOP_CHARGE_REQUEST"
    NOTIFY_OPERATOR = "NOTIFY_OPERATOR"
    PRESERVE_EVIDENCE = "PRESERVE_EVIDENCE"


@dataclass(frozen=True)
class SafeStateDecision:
    failure_class: str
    mode: OperatingMode
    actions: tuple[SafeAction, ...]
    soc_valid: bool
    prior_soc_for_audit: float | None


class SafeStateController:
    """Map loss of confidence to deterministic mode-aware actions."""

    def decide(
        self,
        failure_class: str,
        mode: OperatingMode,
        prior_soc_percent: float | None = None,
    ) -> SafeStateDecision:
        actions = {
            SafeAction.BLOCK_STATE_UPDATE,
            SafeAction.NOTIFY_OPERATOR,
            SafeAction.PRESERVE_EVIDENCE,
        }
        soc_valid = True

        if failure_class in {
            "SOC_CONFIDENCE_LOSS",
            "COMMUNICATION_LOSS",
            "VALIDATOR_EXCEPTION",
        }:
            soc_valid = False
            actions.update(
                {
                    SafeAction.MARK_SOC_STALE,
                    SafeAction.LIMIT_POWER,
                }
            )

        if failure_class == "CRITICAL_TEMPERATURE_DATA_LOSS":
            actions.update(
                {
                    SafeAction.LIMIT_POWER,
                    SafeAction.PRESERVE_COOLING,
                }
            )

        if failure_class == "UNAUTHORIZED_CONTACTOR_CLOSE":
            actions.add(SafeAction.BLOCK_STATE_UPDATE)

        # Contactor behavior depends on operating mode; driving avoids
        # a generic open request that could itself create a hazard.
        if mode is OperatingMode.PARKED:
            actions.add(SafeAction.REQUEST_CONTACTOR_OPEN)
        elif mode is OperatingMode.CHARGING:
            actions.update(
                {
                    SafeAction.STOP_CHARGE_REQUEST,
                    SafeAction.REQUEST_CONTACTOR_OPEN,
                }
            )
        elif mode is OperatingMode.DRIVING:
            actions.add(SafeAction.LIMIT_POWER)

        return SafeStateDecision(
            failure_class=failure_class,
            mode=mode,
            actions=tuple(sorted(actions, key=lambda action: action.value)),
            soc_valid=soc_valid,
            # Prior SOC is retained only as evidence, never restored as truth.
            prior_soc_for_audit=prior_soc_percent,
        )
