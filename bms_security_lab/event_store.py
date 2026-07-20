from .security_event import EventSeverity, SecurityEvent


class EventStore:
    """Bound event growth while preserving higher-severity observations."""

    def __init__(self, maximum_events: int = 1000) -> None:
        if maximum_events < 1:
            raise ValueError("Event-store capacity must be at least one.")
        self.maximum_events = maximum_events
        self._events: list[SecurityEvent] = []
        self.dropped_events = 0

    def add(self, event: SecurityEvent) -> bool:
        if len(self._events) < self.maximum_events:
            self._events.append(event)
            return True

        lowest_index = min(
            range(len(self._events)),
            key=lambda index: self._events[index].severity,
        )
        lowest = self._events[lowest_index]

        if event.severity > lowest.severity:
            self._events.pop(lowest_index)
            self._events.append(event)
            self.dropped_events += 1
            return True

        self.dropped_events += 1
        return False

    def all_events(self) -> tuple[SecurityEvent, ...]:
        return tuple(self._events)

    def by_type(self, event_type: str) -> tuple[SecurityEvent, ...]:
        return tuple(
            event for event in self._events if event.event_type == event_type
        )

    def critical_events(self) -> tuple[SecurityEvent, ...]:
        return tuple(
            event
            for event in self._events
            if event.severity >= EventSeverity.HIGH
        )
