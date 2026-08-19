"""
tests/test_notifier.py
Unit tests for the Brevo SMTP notifier deduplication, cooldown resending,
and email formatting.
"""

import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import notifier
from notifier import Notifier, _body, _html_body, _subject


class MockServer:
    def __init__(self, id="srv1", name="Hybris-Prod-01", host="hybris01.internal", port=22, log_path="/var/log/hybris.log"):
        self.id = id
        self.name = name
        self.host = host
        self.port = port
        self.log_path = log_path


class MockGroup:
    def __init__(self, gid="g123", severity="error", exception_class="java.lang.NullPointerException",
                 message="Null pointer while executing payment transaction", top_frame="com.hybris.PaymentService.charge",
                 count=1, first_seen=None, last_seen=None, sample_raw_text="2026-08-19 ERROR stack trace"):
        self.gid = gid
        self.severity = severity
        self.exception_class = exception_class
        self.message = message
        self.top_frame = top_frame
        self.count = count
        self.first_seen = first_seen or datetime(2026, 8, 19, 10, 0, 0)
        self.last_seen = last_seen or datetime(2026, 8, 19, 10, 0, 0)
        self.sample_raw_text = sample_raw_text


class TestNotifierFlow(unittest.TestCase):

    def setUp(self):
        os.environ["NOTIFY_ENABLED"] = "1"
        os.environ["MAIL_TO"] = "ops@example.com"
        os.environ["NOTIFY_INTERVAL_HOURS"] = "3"
        self.notifier = Notifier()
        self.sent_emails = []

        def mock_sender(subject, body_plain, body_html):
            self.sent_emails.append({
                "subject": subject,
                "body_plain": body_plain,
                "body_html": body_html,
            })

        self.notifier._sender = mock_sender

    def test_first_occurrence_sends_email(self):
        server = MockServer()
        group = MockGroup(count=1)

        snap = notifier._snapshot(server, group)
        self.notifier._maybe_send(snap)

        self.assertEqual(len(self.sent_emails), 1)
        email = self.sent_emails[0]
        self.assertIn("[ERROR]", email["subject"])
        self.assertIn("NullPointerException", email["subject"])
        self.assertIn("Hybris-Prod-01", email["subject"])
        self.assertIn("Occurrences     : 1 times", email["body_plain"])
        self.assertIn("Null pointer while executing payment transaction", email["body_plain"])
        self.assertIn("2026-08-19 10:00:00", email["body_plain"])

    def test_recurrence_within_cooldown_is_suppressed(self):
        server = MockServer()
        group1 = MockGroup(count=1)
        snap1 = notifier._snapshot(server, group1)

        # 1st occurrence -> send
        self.notifier._maybe_send(snap1)
        self.assertEqual(len(self.sent_emails), 1)

        # 2nd occurrence 30 minutes later (count=5) -> within 3h cooldown -> suppressed
        group2 = MockGroup(count=5, last_seen=datetime(2026, 8, 19, 10, 30, 0))
        snap2 = notifier._snapshot(server, group2)
        self.notifier._maybe_send(snap2)

        self.assertEqual(len(self.sent_emails), 1, "Expected email to be suppressed within cooldown")

    def test_recurrence_after_cooldown_resends_with_updated_count(self):
        server = MockServer()
        group1 = MockGroup(count=1)
        snap1 = notifier._snapshot(server, group1)

        # 1st occurrence
        self.notifier._maybe_send(snap1)
        self.assertEqual(len(self.sent_emails), 1)

        # Simulate 3.5 hours elapsed since first alert
        key = (server.id, group1.gid)
        with self.notifier._lock:
            self.notifier._sent[key]["last_sent_at"] = datetime.utcnow() - timedelta(hours=3.5)

        # Recurrence with count=42 after 3.5 hours ("still not fixed")
        group2 = MockGroup(count=42, last_seen=datetime(2026, 8, 19, 13, 30, 0))
        snap2 = notifier._snapshot(server, group2)
        self.notifier._maybe_send(snap2)

        self.assertEqual(len(self.sent_emails), 2)
        second_email = self.sent_emails[1]
        self.assertIn("[RECURRING - 42 occurrences]", second_email["subject"])
        self.assertIn("Occurrences     : 42 times", second_email["body_plain"])
        self.assertIn("RECURRING ALERT", second_email["body_plain"])
        self.assertIn("2026-08-19 13:30:00", second_email["body_plain"])
        self.assertIn("42", second_email["body_html"])

    def test_fixed_error_after_cooldown_is_not_resent(self):
        server = MockServer()
        group1 = MockGroup(count=10)
        snap1 = notifier._snapshot(server, group1)

        self.notifier._maybe_send(snap1)
        self.assertEqual(len(self.sent_emails), 1)

        # Simulate 4 hours elapsed, but count is unchanged (error stopped occurring)
        key = (server.id, group1.gid)
        with self.notifier._lock:
            self.notifier._sent[key]["last_sent_at"] = datetime.utcnow() - timedelta(hours=4)

        group_unchanged = MockGroup(count=10)
        snap_unchanged = notifier._snapshot(server, group_unchanged)
        self.notifier._maybe_send(snap_unchanged)

        self.assertEqual(len(self.sent_emails), 1, "Should not resend if error count did not grow")

    def test_delivery_failure_rolls_back_state(self):
        server = MockServer()
        group = MockGroup(count=1)
        snap = notifier._snapshot(server, group)

        def failing_sender(subject, plain, html_body):
            raise ConnectionError("SMTP Connection Refused")

        self.notifier._sender = failing_sender

        with self.assertRaises(ConnectionError):
            self.notifier._maybe_send(snap)

        # State should be rolled back so next attempt can try sending
        key = (server.id, group.gid)
        with self.notifier._lock:
            self.assertNotIn(key, self.notifier._sent)

    def test_email_body_formatting(self):
        snap = {
            "server_id": "s1",
            "server_name": "Node-A",
            "server_host": "10.0.0.1",
            "server_port": 22,
            "server_path": "/opt/hybris/log/console.log",
            "gid": "abc",
            "severity": "error",
            "exception_class": "de.hybris.CustomException",
            "message": "Payment timeout on gateway",
            "top_frame": "com.hybris.Payment.process",
            "count": 7,
            "first_seen": "2026-08-19 12:00:00",
            "last_seen": "2026-08-19 15:30:00",
            "sample": "Sample trace line",
            "is_resend": True,
        }

        body_plain = _body(snap)
        body_html = _html_body(snap)
        subject = _subject(snap)

        self.assertIn("[RECURRING - 7 occurrences]", subject)
        self.assertIn("Payment timeout on gateway", body_plain)
        self.assertIn("Occurrences     : 7 times", body_plain)
        self.assertIn("Last Seen       : 2026-08-19 15:30:00", body_plain)
        self.assertIn("Node-A", body_plain)
        self.assertIn("de.hybris.CustomException", body_html)
        self.assertIn("Payment timeout on gateway", body_html)
        self.assertIn("7", body_html)
        self.assertIn("2026-08-19 15:30:00", body_html)


if __name__ == "__main__":
    unittest.main()
