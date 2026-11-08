import json
import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis_origin import resourcewatch
from jarvis_origin.store import Store


class ResourceWatchTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tempdir.name, "jarvis_origin.db"))

    def tearDown(self):
        self.store.close()
        self.tempdir.cleanup()

    def test_sustained_cpu_is_calculated_from_two_samples(self):
        key = "wsl:42:fp"
        self.store.set_meta(resourcewatch._META, json.dumps({
            "ts": 700.0, "processes": {key: {"cpu": 100.0}}
        }))
        proc = {"host": "wsl", "pid": 42, "fp": "fp", "name": "worker",
                "exe": "/opt/worker", "rss_bytes": 100, "cpu_seconds": 400.0}
        with patch("jarvis_origin.resourcewatch.time.time", return_value=1000.0), \
             patch("jarvis_origin.resourcewatch.monitor.collect_all", return_value=[proc]), \
             patch("jarvis_origin.resourcewatch.os.cpu_count", return_value=4), \
             patch("jarvis_origin.resourcewatch._memory_pressure", return_value=(100, 100)), \
             patch("jarvis_origin.resourcewatch.os.path.exists", return_value=False):
            findings = resourcewatch.audit(self.store, hosts=("wsl",))

        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("25.0%", findings[0]["detail"])
        self.assertNotIn("command", findings[0]["detail"])


if __name__ == "__main__":
    unittest.main()
