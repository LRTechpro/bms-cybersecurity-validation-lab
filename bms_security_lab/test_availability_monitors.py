"""Phase 11 tests for timing, flooding, latency, and bounded queues."""

import unittest

from .can_frame import CANFrame
from .timing_monitor import TimingMonitor
from .traffic_monitor import TrafficMonitor


class TestAvailabilityMonitors(unittest.TestCase):
    @staticmethod
    def _frame(timestamp_s: float) -> CANFrame:
        return CANFrame(
            arbitration_id=0x180,
            data=b"\x00" * 8,
            dlc=8,
            timestamp_s=timestamp_s,
            channel="virtual",
        )

    def test_message_arrives_on_schedule(self) -> None:
        monitor = TimingMonitor(expected_periods_s={0x180: 0.1})
        monitor.start(0.0)

        first = monitor.record_message(0x180, 0.0)
        second = monitor.record_message(0x180, 0.1)

        self.assertEqual(first.status, "PASS")
        self.assertEqual(second.status, "PASS")

    def test_missing_message_beyond_timeout_fails_and_degrades(self) -> None:
        monitor = TimingMonitor(
            expected_periods_s={0x180: 0.1},
            timeout_periods=2.0,
            timeout_margin_s=0.01,
        )
        monitor.start(0.0)
        monitor.record_message(0x180, 0.0)

        decision = monitor.check_missing(0.211)[0]

        self.assertEqual(decision.status, "FAIL")
        self.assertEqual(decision.action, "DEGRADED")
        self.assertIn("missing", decision.reasons[0])

    def test_high_rate_duplicate_frames_fail_rate_policy(self) -> None:
        monitor = TrafficMonitor(max_rate_hz=20.0, rate_window_s=1.0)

        monitor.observe_frame(self._frame(0.00))
        monitor.observe_frame(self._frame(0.01))
        decision = monitor.observe_frame(self._frame(0.02))

        self.assertEqual(decision.status, "FAIL")
        self.assertEqual(decision.action, "RATE_LIMIT")

    def test_processing_delay_over_budget_fails(self) -> None:
        monitor = TimingMonitor(
            expected_periods_s={0x180: 0.1},
            processing_budget_s=0.05,
        )

        decision = monitor.evaluate_processing_latency(0.051)

        self.assertEqual(decision.status, "FAIL")
        self.assertEqual(decision.action, "DEGRADED")

    def test_event_queue_drops_oldest_at_limit(self) -> None:
        monitor = TrafficMonitor(max_events=3)

        monitor.record_event("event-1")
        monitor.record_event("event-2")
        monitor.record_event("event-3")
        update = monitor.record_event("event-4")

        self.assertEqual(update.dropped_item, "event-1")
        self.assertEqual(update.queue_depth, 3)
        self.assertEqual(update.drop_count, 1)
        self.assertEqual(
            monitor.events,
            ("event-2", "event-3", "event-4"),
        )

    def test_processing_queue_stays_bounded_and_responsive(self) -> None:
        monitor = TrafficMonitor(max_processing_queue=2)

        monitor.enqueue_for_processing("frame-1")
        monitor.enqueue_for_processing("frame-2")
        update = monitor.enqueue_for_processing("frame-3")

        self.assertEqual(update.dropped_item, "frame-1")
        self.assertEqual(monitor.processing_queue_depth, 2)
        self.assertEqual(monitor.dequeue_for_processing(), "frame-2")
        self.assertEqual(monitor.dequeue_for_processing(), "frame-3")
        self.assertIsNone(monitor.dequeue_for_processing())

    def test_normal_message_rate_passes(self) -> None:
        monitor = TrafficMonitor(max_rate_hz=11.0, rate_window_s=1.0)

        decisions = [
            monitor.observe_frame(self._frame(index * 0.1))
            for index in range(5)
        ]

        self.assertTrue(all(item.status == "PASS" for item in decisions))

    def test_message_late_on_arrival_is_detected(self) -> None:
        monitor = TimingMonitor(
            expected_periods_s={0x180: 0.1},
            timeout_periods=2.0,
            timeout_margin_s=0.01,
        )
        monitor.start(0.0)
        monitor.record_message(0x180, 0.0)

        decision = monitor.record_message(0x180, 0.25)

        self.assertEqual(decision.status, "FAIL")
        self.assertEqual(decision.action, "DEGRADED")


if __name__ == "__main__":
    unittest.main()
