"""Invariants of the JARVIS-1 cut: what it contains, what it claims, what it touches.

These guard the boundary of the public release itself:

  * exactly the published modules exist, and nothing imports anything else;
  * the ATT&CK coverage map credits only collectors that ship here;
  * the Windows hook helper is found and stopped by a name unique to this
    project, so it can never stop another tool's helper on the same machine;
  * state, config, env vars and the dashboard port are namespaced so a copy of
    JARVIS-1 cannot collide with another monitor installed alongside it;
  * a Windows side that is unreachable means no Windows process is launched.
"""

import ast
import fnmatch
import importlib
import os
import pathlib
import re
import tempfile
import time
import unittest
from unittest.mock import patch

PKG = pathlib.Path(__file__).resolve().parent.parent / "jarvis_origin"

PUBLISHED = {
    "__init__", "__main__", "alert", "cli", "collect_linux", "collect_windows",
    "coverage", "detect", "feeds", "fixit", "hunt", "inputwatch", "intel",
    "monitor", "resourcewatch", "sdnotify", "server", "store", "util", "vet",
}


def _imported_modules(path):
    """Every jarvis_origin-internal module a file imports, by AST."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level >= 1:                     # from . import x / from .x import y
                if node.module:
                    found.add(node.module.split(".")[0])
                else:
                    found.update(a.name for a in node.names)
            elif node.module and node.module.split(".")[0] == "jarvis-origin":
                parts = node.module.split(".")
                if len(parts) > 1:
                    found.add(parts[1])
                else:
                    found.update(a.name for a in node.names)
        elif isinstance(node, ast.Import):
            for a in node.names:
                parts = a.name.split(".")
                if parts[0] == "jarvis-origin" and len(parts) > 1:
                    found.add(parts[1])
    return found


class PackageBoundaryTests(unittest.TestCase):
    def test_only_published_modules_ship(self):
        shipped = {p.stem for p in PKG.glob("*.py")}
        self.assertEqual(shipped, PUBLISHED)
        self.assertEqual(sorted(p.name for p in (PKG / "win").iterdir()),
                         ["inputhook.ps1"])

    def test_no_file_imports_a_module_that_does_not_ship(self):
        for path in sorted(PKG.glob("*.py")):
            with self.subTest(file=path.name):
                self.assertLessEqual(_imported_modules(path), PUBLISHED)

    def test_every_published_module_imports(self):
        for name in sorted(PUBLISHED - {"__main__"}):
            with self.subTest(module=name):
                importlib.import_module(f"jarvis_origin.{name}")

    def test_cli_offers_exactly_the_published_commands(self):
        from jarvis_origin.cli import build_parser
        sub = next(a for a in build_parser()._actions
                   if a.__class__.__name__ == "_SubParsersAction")
        self.assertEqual(set(sub.choices), {
            "alert", "approve", "baseline", "coverage", "events", "feeds", "gaps",
            "hunt", "inputwatch", "intel", "investigate", "peers", "procs", "scan",
            "serve", "status", "watch"})


class SchedulerTableTests(unittest.TestCase):
    def test_every_job_dispatches_and_unknown_jobs_fail_loudly(self):
        import inspect
        from jarvis_origin import server
        source = inspect.getsource(server._run_job)
        for name in server.JOBS:
            with self.subTest(job=name):
                self.assertIn(f'"{name}"', source)
        with self.assertRaises(ValueError):
            server._run_job("no-such-job", ("wsl",))


class HonestCoverageTests(unittest.TestCase):
    def test_coverage_map_credits_only_shipped_collectors(self):
        from jarvis_origin import hunt
        credited = set()
        for where in hunt.COVERAGE.values():
            head = where.split("—")[0]
            credited.update(w.strip() for w in head.split("/"))
        self.assertLessEqual(credited, PUBLISHED)

    def test_no_interception_layer_is_ever_credited(self):
        from jarvis_origin import hunt
        hunt._INTERCEPT = None
        self.assertEqual(hunt._intercept_active(), (False, ""))

    def test_withheld_techniques_are_reported_as_gaps_not_coverage(self):
        from jarvis_origin import hunt
        from jarvis_origin.store import Store
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(os.path.join(tmp, "t.db"))
            try:
                ts = int(time.time())
                rows = [("T1055", "Process Injection", "defense-evasion,privilege-escalation"),
                        ("T1036", "Masquerading", "defense-evasion"),
                        ("T1003", "OS Credential Dumping", "credential-access")]
                for tid, name, tactics in rows:
                    store.db.execute(
                        "INSERT INTO attack_techniques(tid,name,tactics,updated) "
                        "VALUES (?,?,?,?)", (tid, name, tactics, ts))
                    store.db.execute(
                        "INSERT INTO indicators(kind,value,norm,source_url,first_seen,"
                        "last_seen,doc_count) VALUES ('attack',?,?,'https://example.test',?,?,3)",
                        (tid, tid, ts, ts))
                store.db.commit()
                findings, covered, closeable = hunt.gaps(store)
            finally:
                store.close()
        covered_ids = {c[0] for c in covered}
        gap_ids = {c[0] for c in closeable}
        self.assertEqual(covered_ids, {"T1036"})
        self.assertEqual(gap_ids, {"T1055", "T1003"})
        for f in findings:
            self.assertIn("not observed activity", f["detail"])


class HookHelperIsolationTests(unittest.TestCase):
    """The helper is found and stopped by command-line match. That match must
    never reach another product's hook helper running on the same Windows."""

    FOREIGN = [
        r'powershell.exe -File "C:\Users\u\AppData\Local\Jarvis\inputhook.ps1" -OutFile x',
        r'powershell.exe -File "C:\Program Files\Other\inputhook.ps1"',
        r'powershell.exe -File C:\tools\keyboard-inputhook.ps1',
    ]
    OWN = r'powershell.exe -NoProfile -File "C:\Users\u\AppData\Local\JarvisOrigin\jarvis-origin-inputhook.ps1" -OutFile y'

    def _scripts(self, fn):
        sent = []

        def capture(script, timeout=120):
            sent.append(script)
            return {"n": 0, "ok": 1}

        from jarvis_origin import inputwatch
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(inputwatch.collect_windows, "ps_json", side_effect=capture), \
                patch.object(inputwatch, "_paths",
                             return_value=(r"C:\x\JarvisOrigin\input.jsonl",
                                           os.path.join(tmp, "input.jsonl"))):
            fn()
        return sent

    def _patterns(self, scripts):
        pats = []
        for s in scripts:
            pats += re.findall(r"CommandLine -like '([^']+)'", s)
        return pats

    def test_stop_all_matches_only_this_projects_helper(self):
        from jarvis_origin import inputwatch
        pats = self._patterns(self._scripts(inputwatch._stop_all))
        self.assertTrue(pats, "the reconciliation query changed shape")
        for pat in pats:
            # PowerShell -like is case-insensitive wildcard matching.
            for cmd in self.FOREIGN:
                self.assertFalse(fnmatch.fnmatch(cmd.lower(), pat.lower()), (pat, cmd))
            self.assertTrue(fnmatch.fnmatch(self.OWN.lower(), pat.lower()), pat)

    def test_helper_count_uses_the_same_unique_name(self):
        from jarvis_origin import inputwatch
        pats = self._patterns(self._scripts(inputwatch._helper_count))
        self.assertEqual(pats, [f"*{inputwatch.HELPER_NAME}*"])
        self.assertTrue(inputwatch.HELPER_NAME.startswith("jarvis-origin-"))

    def test_no_windows_process_launches_when_the_bridge_is_down(self):
        from jarvis_origin import collect_windows
        with patch.object(collect_windows, "available", return_value=False), \
                patch.object(collect_windows.subprocess, "run",
                             side_effect=AssertionError("launched a process")):
            self.assertIsNone(collect_windows.ps_json("Get-Date"))

    def test_unreachable_windows_side_writes_nothing_to_it(self):
        from jarvis_origin import inputwatch
        made = []
        inputwatch._PATHS_CACHE = None
        with patch.object(inputwatch.collect_windows, "ps_json", return_value=None), \
                patch.object(inputwatch.os, "makedirs", side_effect=lambda *a, **k: made.append(a)):
            win, wsl = inputwatch._paths()
        self.assertEqual(made, [])
        self.assertIsNone(inputwatch._PATHS_CACHE)   # a guess is never cached
        inputwatch._PATHS_CACHE = None
        with patch.object(inputwatch.collect_windows, "ps_json",
                          return_value={"t": r"C:\Users\u\AppData\Local"}), \
                patch.object(inputwatch.os, "makedirs", side_effect=lambda *a, **k: made.append(a)):
            inputwatch._paths()
        inputwatch._PATHS_CACHE = None
        self.assertEqual(len(made), 1)
        self.assertTrue(made[0][0].endswith("/JarvisOrigin"))

    def test_hook_never_records_key_values(self):
        source = (PKG / "win" / "inputhook.ps1").read_text(encoding="utf-8")
        self.assertIn("deliberately does NOT record what was typed", source)
        self.assertNotRegex(source, r"ToUnicode|GetKeyNameText|MapVirtualKey")


class NamespaceIsolationTests(unittest.TestCase):
    def test_state_config_env_and_port_are_namespaced(self):
        from jarvis_origin import alert, cli, intel, store
        home = os.path.expanduser("~")
        self.assertEqual(store.DEFAULT_DB, os.path.join(home, ".jarvis-origin", "jarvis-origin.db"))
        self.assertNotIn(os.path.join(home, ".jarvis") + os.sep, store.DEFAULT_DB)
        self.assertEqual(alert.CONFIG_PATH, os.path.join(home, ".jarvis-origin", "config.json"))
        self.assertEqual(intel.CONFIG_PATH, alert.CONFIG_PATH)
        serve = next(a for a in cli.build_parser()._actions
                     if a.__class__.__name__ == "_SubParsersAction").choices["serve"]
        port = next(a for a in serve._actions if "--port" in a.option_strings)
        self.assertEqual(port.default, 8790)
        for path in sorted(PKG.rglob("*")):
            if path.suffix not in (".py", ".ps1", ".html"):
                continue
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=path.name):
                # Another monitor's names (JARVIS_*, ~/.jarvis, %LOCALAPPDATA%\Jarvis)
                # must never be read or written; only the JARVIS_ORIGIN_ namespace.
                self.assertNotRegex(text, r"(?<![A-Z_])JARVIS_(?!ORIGIN_)[A-Z]")
                self.assertNotRegex(text, r"~/\.jarvis(?!-origin)\b|\\Jarvis\\")

    def test_dashboard_accepts_only_loopback_hosts(self):
        from jarvis_origin import server
        self.assertEqual(server.ALLOWED_HOSTS, {"localhost", "127.0.0.1", "[::1]", "::1"})

        class Fake:
            def __init__(self, host):
                self.headers = {"Host": host}

        for host, ok in [("127.0.0.1:8790", True), ("localhost", True), ("[::1]:8790", True),
                         ("evil.example:8790", False), ("192.0.2.5:8790", False),
                         ("127.0.0.1.evil.example", False)]:
            with self.subTest(host=host):
                self.assertIs(server.Handler._host_ok(Fake(host)), ok)


class FixSuggestionTests(unittest.TestCase):
    def test_only_findings_jarvis_origin_raises_get_a_command(self):
        from jarvis_origin import coverage, fixit
        with patch.object(coverage.collect_windows, "available", return_value=False):
            bridge = coverage.bridge_status()[0]
        self.assertIn("wsl --shutdown", fixit.suggest(bridge))
        self.assertEqual(fixit.suggest({"title": "ASR rules are not enforcing"}), "")
        self.assertEqual(fixit.suggest({"title": "custom systemd service"}), "")
        for _pred, fix in fixit._RULES:
            self.assertNotIn("sudo", fix("", "", ""))


if __name__ == "__main__":
    unittest.main()
