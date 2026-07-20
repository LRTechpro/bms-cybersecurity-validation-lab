from .anomaly_detector import AnomalyDetector
from .event_store import EventStore
from .security_event import EventSeverity, SecurityEvent


def event(
    event_type: str,
    timestamp_s: float,
    severity: EventSeverity = EventSeverity.MEDIUM,
    source_id: str = "0x180",
) -> SecurityEvent:
    return SecurityEvent(
        timestamp_s=timestamp_s,
        asset_id="AST-001",
        source_id=source_id,
        event_type=event_type,
        severity=severity,
        related_test_id="DET-TEST",
        evidence={"input": "simulated"},
    )


def test_single_invalid_value_creates_one_event() -> None:
    store = EventStore(maximum_events=10)
    detector = AnomalyDetector(store)
    alerts = detector.process(event("INVALID_VALUE", 1.0))
    assert alerts == ()
    assert len(store.all_events()) == 1


def test_five_failed_authentications_escalate_alert() -> None:
    store = EventStore(maximum_events=20)
    detector = AnomalyDetector(store, failed_auth_threshold=5)
    alerts = ()
    for timestamp in range(1, 6):
        alerts = detector.process(
            event("AUTHENTICATION_FAILURE", float(timestamp))
        )
    assert len(alerts) == 1
    assert alerts[0].severity is EventSeverity.HIGH
    assert alerts[0].event_type == "AUTHENTICATION_FAILURE_BURST"


def test_replay_plus_source_anomaly_creates_correlated_incident() -> None:
    store = EventStore(maximum_events=20)
    detector = AnomalyDetector(store)
    detector.process(event("REPLAY_DETECTED", 1.0))
    alerts = detector.process(event("SOURCE_ANOMALY", 2.0))
    assert len(alerts) == 1
    assert alerts[0].severity is EventSeverity.CRITICAL


def test_event_flood_is_bounded_without_losing_critical_event() -> None:
    store = EventStore(maximum_events=3)
    for timestamp in range(3):
        store.add(
            event(
                "NOISE",
                float(timestamp),
                severity=EventSeverity.LOW,
                source_id=f"noise-{timestamp}",
            )
        )
    critical = event(
        "CRITICAL_ATTACK",
        4.0,
        severity=EventSeverity.CRITICAL,
    )
    assert store.add(critical) is True
    assert len(store.all_events()) == 3
    assert critical in store.all_events()
    assert store.dropped_events == 1


def test_normal_campaign_produces_no_high_severity_alert() -> None:
    store = EventStore(maximum_events=20)
    detector = AnomalyDetector(store)
    all_alerts = []
    for timestamp in range(5):
        all_alerts.extend(
            detector.process(
                event(
                    "NORMAL_VALIDATION",
                    float(timestamp),
                    severity=EventSeverity.INFO,
                )
            )
        )
    assert all_alerts == []
    assert store.critical_events() == ()
