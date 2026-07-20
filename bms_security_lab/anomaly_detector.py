from .event_store import EventStore
from .security_event import EventSeverity, SecurityEvent


class AnomalyDetector:
    """Correlate repeated and combined events inside a time window."""

    def __init__(
        self,
        event_store: EventStore,
        correlation_window_s: float = 10.0,
        failed_auth_threshold: int = 5,
    ) -> None:
        if correlation_window_s <= 0 or failed_auth_threshold < 2:
            raise ValueError("Detector thresholds are invalid.")
        self.event_store = event_store
        self.correlation_window_s = correlation_window_s
        self.failed_auth_threshold = failed_auth_threshold
        self._emitted_alert_keys: set[str] = set()

    def process(self, event: SecurityEvent) -> tuple[SecurityEvent, ...]:
        self.event_store.add(event)
        alerts: list[SecurityEvent] = []
        recent = self._recent_events(event.timestamp_s)

        failed_auth = [
            item
            for item in recent
            if item.event_type == "AUTHENTICATION_FAILURE"
            and item.source_id == event.source_id
        ]
        if len(failed_auth) >= self.failed_auth_threshold:
            key = f"AUTH_BURST:{event.source_id}"
            if key not in self._emitted_alert_keys:
                alerts.append(
                    self._make_alert(
                        timestamp_s=event.timestamp_s,
                        source_id=event.source_id,
                        event_type="AUTHENTICATION_FAILURE_BURST",
                        severity=EventSeverity.HIGH,
                        test_id=event.related_test_id,
                        count=len(failed_auth),
                    )
                )
                self._emitted_alert_keys.add(key)

        event_types = {item.event_type for item in recent}
        if {"REPLAY_DETECTED", "SOURCE_ANOMALY"}.issubset(event_types):
            key = f"REPLAY_SOURCE:{event.source_id}"
            if key not in self._emitted_alert_keys:
                alerts.append(
                    self._make_alert(
                        timestamp_s=event.timestamp_s,
                        source_id=event.source_id,
                        event_type="CORRELATED_REPLAY_SOURCE_INCIDENT",
                        severity=EventSeverity.CRITICAL,
                        test_id=event.related_test_id,
                        count=2,
                    )
                )
                self._emitted_alert_keys.add(key)

        for alert in alerts:
            self.event_store.add(alert)
        return tuple(alerts)

    def _recent_events(self, now_s: float) -> tuple[SecurityEvent, ...]:
        minimum = now_s - self.correlation_window_s
        return tuple(
            event
            for event in self.event_store.all_events()
            if minimum <= event.timestamp_s <= now_s
        )

    @staticmethod
    def _make_alert(
        timestamp_s: float,
        source_id: str,
        event_type: str,
        severity: EventSeverity,
        test_id: str,
        count: int,
    ) -> SecurityEvent:
        return SecurityEvent(
            timestamp_s=timestamp_s,
            asset_id="AST-008",
            source_id=source_id,
            event_type=event_type,
            severity=severity,
            related_test_id=test_id,
            evidence={"correlated_event_count": count},
        )
