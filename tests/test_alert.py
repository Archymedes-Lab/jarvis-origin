import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis_origin import alert
from jarvis_origin.store import Store


CONF = {
    "resend_api_key": "test-key",
    "alert_from": "jarvis-origin@example.test",
    "alert_to": "owner@example.test",
}


class AdvisoryReportTests(unittest.TestCase):
    def test_gaps_do_not_page_or_falsely_clear_after_reclassification(self):
        import json
        finding = {"category": "coverage gap", "severity": "high",
                   "title": "T1003", "detail": "missing coverage", "where": ""}
        self.store.set_meta(alert._M_STATE, json.dumps({alert._key(finding): {
            "job": "gaps", "first": 1, "last_sent": 1, "count": 2}}))
        with patch.object(alert, "send_email") as send:
            alert._dispatch(self.store, CONF, "gaps", [finding], "")
            alert._dispatch(self.store, CONF, "gaps", [finding], "")
        send.assert_not_called()
        self.assertEqual(json.loads(self.store.get_meta(alert._M_STATE)), {})

    def test_collector_outages_still_page(self):
        finding = {"category": "collectors", "severity": "high",
                   "title": "collector 'scan' is stale", "detail": "no results", "where": ""}
        with patch.object(alert, "send_email", return_value="") as send:
            alert._dispatch(self.store, CONF, "coverage", [finding], "")
        send.assert_called_once()

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tempdir.name, "jarvis_origin.db"))

    def tearDown(self):
        self.store.close()
        self.tempdir.cleanup()

    def test_sender_always_uses_jarvis_display_name(self):
        self.assertEqual(
            alert.branded_sender({"alert_from": "jarvis-origin@example.test"}),
            "JARVIS-1 <jarvis-origin@example.test>",
        )
        self.assertEqual(
            alert.branded_sender({"alert_from": "Old Name <alerts@example.test>"}),
            "JARVIS-1 <alerts@example.test>",
        )

    def test_report_prioritizes_actions_and_keeps_process_details_local(self):
        self.store.save_snapshot("coverage", [{
            "category": "visibility", "severity": "medium", "host": "wsl",
            "title": "running unprivileged", "detail": "some views are hidden",
            "where": "sudo jarvis-origin coverage",
        }])
        self.store.save_snapshot("bridge", [{
            "category": "collectors", "severity": "critical", "host": "win",
            "title": "the Windows side is blind — interop bridge is down",
            "detail": "powershell.exe is unreachable", "where": "WSL interop",
        }])
        self.store.save_snapshot("hunt", [{
            "category": "hunt", "severity": "ok", "host": "wsl",
            "title": "no indicator matches", "detail": "", "where": "",
        }])
        self.store.save_snapshot("scan", [{
            "category": "process", "severity": "high", "host": "wsl",
            "title": "private-process", "detail": "SECRET_ON_COMMAND_LINE",
            "where": "/tmp/private",
        }])

        sent = {}

        def capture(_conf, subject, body, html=None):
            sent.update(subject=subject, body=body, html=html)
            return ""

        jobs = {
            "scan": (60, "scan"),
            "coverage": (600, "coverage"),
            "bridge": (45, "bridge"),
            "hunt": (1800, "hunt"),
            "report": (18000, "report"),
        }
        with patch("jarvis_origin.alert.load_conf", return_value=CONF), \
             patch("jarvis_origin.alert.send_email", side_effect=capture):
            result = alert.advisory_report(self.store, jobs)

        self.assertEqual(result[0]["severity"], "ok")
        self.assertTrue(sent["subject"].startswith("[JARVIS-1]"))
        self.assertIn("5-hour security report", sent["subject"])
        self.assertIn("JARVIS-1 FIVE-HOUR SECURITY ADVISORY", sent["body"])
        self.assertIn("JARVIS-1 · FIVE-HOUR SECURITY ADVISORY", sent["html"])
        self.assertIn("SECURE NEXT", sent["body"])
        self.assertIn("interop bridge is down", sent["body"])
        self.assertIn("wsl --shutdown", sent["body"])
        self.assertIn("running unprivileged", sent["body"])
        self.assertIn("no indicator matches", sent["body"])
        self.assertNotIn("SECRET_ON_COMMAND_LINE", sent["body"])
        self.assertNotIn("SECRET_ON_COMMAND_LINE", sent["html"])
        self.assertIn("Current findings by protection layer", sent["html"])
        self.assertIn("Optional deeper AI assessment", sent["html"])
        self.assertTrue(self.store.get_meta(alert._M_REPORT_OK))

    def test_report_surfaces_missing_delivery_configuration(self):
        with patch("jarvis_origin.alert.load_conf", return_value={}):
            result = alert.advisory_report(
                self.store, {"report": (18000, "report")})
        self.assertEqual(result[0]["severity"], "medium")
        self.assertIn("not configured", result[0]["title"])


if __name__ == "__main__":
    unittest.main()
