import time
import unittest
from unittest.mock import patch

from jarvis_origin.server import JOBS, Scheduler


class SchedulerColdStartTests(unittest.TestCase):
    def setUp(self):
        self.scheduler = Scheduler(":memory:", ("wsl",))
        future = time.time() + 3600
        self.scheduler.next_run = {name: future for name in JOBS}
        self.scheduler.next_run["coverage"] = 0

    def test_automatic_coverage_waits_for_first_collector_sweep(self):
        self.assertIsNone(self.scheduler._due())
        self.scheduler.cold_start_pending.clear()
        self.assertEqual(self.scheduler._due(), "coverage")

    def test_forced_coverage_still_runs_during_cold_start(self):
        self.scheduler.force("coverage")
        self.assertEqual(self.scheduler._due(), "coverage")

    def test_automatic_report_waits_for_first_collector_sweep(self):
        self.scheduler.next_run["coverage"] = time.time() + 3600
        self.scheduler.next_run["report"] = 0
        self.assertIsNone(self.scheduler._due())
        self.scheduler.cold_start_pending.clear()
        self.assertEqual(self.scheduler._due(), "report")

    def test_initial_deadlines_use_current_time_not_epoch(self):
        scheduler = Scheduler(":memory:", ("wsl",))
        created = time.time()
        self.assertTrue(all(abs(deadline - created) < 1
                            for deadline in scheduler.next_run.values()))


class SchedulerFairnessTests(unittest.TestCase):
    def setUp(self):
        self.scheduler = Scheduler(":memory:", ("wsl",))
        self.scheduler.cold_start_pending.clear()

    def test_relative_lateness_protects_short_interval_jobs(self):
        future = 2_000.0
        self.scheduler.next_run = {name: future for name in JOBS}
        # Feeds has been waiting longer in absolute seconds, but scan has
        # missed a larger share of its promised cadence and must run first.
        self.scheduler.next_run["feeds"] = 900.0
        self.scheduler.next_run["scan"] = 950.0
        with patch("jarvis_origin.server.time.time", return_value=1_000.0):
            self.assertEqual(self.scheduler._due(), "scan")

    def test_not_yet_due_jobs_are_not_selected(self):
        self.scheduler.next_run = {name: 1_001.0 for name in JOBS}
        with patch("jarvis_origin.server.time.time", return_value=1_000.0):
            self.assertIsNone(self.scheduler._due())


if __name__ == "__main__":
    unittest.main()
