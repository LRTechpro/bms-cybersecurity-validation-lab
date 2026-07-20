"""Bounded traffic-rate and queue monitoring for the BMS simulation."""

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from .can_frame import CANFrame
from .timing_monitor import AvailabilityDecision


@dataclass(frozen=True)
class QueueUpdate:
    """Result of adding one item to a bounded queue."""

    dropped_item: Any | None
    queue_depth: int
    drop_count: int


class TrafficMonitor:
    """Detect flooding while keeping internal storage bounded."""

    REQUIREMENT_ID = "BMS-SEC-AVA-002"

    def __init__(
        self,
        max_rate_hz: float = 50.0,
        rate_window_s: float = 1.0,
        max_events: int = 100,
        max_processing_queue: int = 50,
    ) -> None:
        if max_rate_hz <= 0 or rate_window_s <= 0:
            raise ValueError("Rate limits and windows must be positive.")
        if max_events < 1 or max_processing_queue < 1:
            raise ValueError("Queue limits must be at least 1.")

        self.max_rate_hz = max_rate_hz
        self.rate_window_s = rate_window_s
        self.max_events = max_events
        self.max_processing_queue = max_processing_queue

        self._timestamps_by_id: dict[int, deque[float]] = defaultdict(deque)
        self._events: deque[Any] = deque()
        self._processing_queue: deque[Any] = deque()
        self._event_drop_count = 0
        self._processing_drop_count = 0

    def observe_frame(self, frame: CANFrame) -> AvailabilityDecision:
        """Calculate source rate inside a sliding deterministic window."""

        timestamps = self._timestamps_by_id[frame.arbitration_id]
        cutoff = frame.timestamp_s - self.rate_window_s

        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        if timestamps and frame.timestamp_s < timestamps[-1]:
            return AvailabilityDecision(
                requirement_id=self.REQUIREMENT_ID,
                status="FAIL",
                reasons=("Traffic timestamp moved backward.",),
                action="ALERT",
            )

        timestamps.append(frame.timestamp_s)

        if len(timestamps) < 2:
            return self._pass()

        span = timestamps[-1] - timestamps[0]
        if span <= 0:
            observed_rate_hz = float("inf")
        else:
            observed_rate_hz = (len(timestamps) - 1) / span

        if observed_rate_hz > self.max_rate_hz:
            return AvailabilityDecision(
                requirement_id=self.REQUIREMENT_ID,
                status="FAIL",
                reasons=(
                    f"Observed rate {observed_rate_hz:.2f} Hz exceeds "
                    f"limit {self.max_rate_hz:.2f} Hz for "
                    f"0x{frame.arbitration_id:X}.",
                ),
                action="RATE_LIMIT",
            )

        return self._pass()

    def record_event(self, event: Any) -> QueueUpdate:
        """Store an event and drop the oldest when the cap is reached."""

        dropped: Any | None = None
        if len(self._events) >= self.max_events:
            dropped = self._events.popleft()
            self._event_drop_count += 1

        self._events.append(event)
        return QueueUpdate(
            dropped_item=dropped,
            queue_depth=len(self._events),
            drop_count=self._event_drop_count,
        )

    def enqueue_for_processing(self, item: Any) -> QueueUpdate:
        """Keep the processing queue responsive by dropping oldest work."""

        dropped: Any | None = None
        if len(self._processing_queue) >= self.max_processing_queue:
            dropped = self._processing_queue.popleft()
            self._processing_drop_count += 1

        self._processing_queue.append(item)
        return QueueUpdate(
            dropped_item=dropped,
            queue_depth=len(self._processing_queue),
            drop_count=self._processing_drop_count,
        )

    def dequeue_for_processing(self) -> Any | None:
        """Return the next queued item without blocking."""

        if not self._processing_queue:
            return None
        return self._processing_queue.popleft()

    @property
    def events(self) -> tuple[Any, ...]:
        return tuple(self._events)

    @property
    def processing_queue_depth(self) -> int:
        return len(self._processing_queue)

    def _pass(self) -> AvailabilityDecision:
        return AvailabilityDecision(
            requirement_id=self.REQUIREMENT_ID,
            status="PASS",
            reasons=(),
            action="NONE",
        )
