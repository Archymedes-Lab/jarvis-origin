"""The always-on half: a scheduler that keeps auditing, and a local dashboard.

Design constraints that shaped this:

  * The collectors have wildly different costs. Reading /proc takes 20ms; a
    PowerShell audit takes 15-60s because crossing the WSL interop boundary and
    spinning up powershell.exe dominates everything else. So jobs run on their
    own intervals, and never concurrently -- a single worker thread runs them
    one at a time, because two simultaneous powershell.exe launches are slower
    than running them back to back and would fight over the same interop pipe.

  * The page must never wait for a scan. Every request is served from the last
    stored snapshot, so the dashboard is instant even while a 60-second Windows
    audit is running behind it.

  * Nothing binds beyond localhost. A dashboard listing your firewall gaps and
    running processes is exactly what an attacker would like to read, so the
    listener is 127.0.0.1 and there is no option to change that to 0.0.0.0.
"""

import json
import os
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import (alert, feeds, hunt, intel, inputwatch, monitor, resourcewatch,
               sdnotify)
from . import coverage as coverage_mod
from .store import DEFAULT_DB, Store
from .util import now

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "static", "dashboard.html")

# name -> (interval seconds, label, callable(hosts) -> list[finding])
# Intervals have to fit through one worker. The scheduler runs jobs strictly
# one at a time on purpose — two concurrent powershell.exe launches are slower
# than running them back to back and fight over the same interop pipe — so the
# sum of (duration / interval) across every job is a duty cycle that must stay
# well under 1. Adding the intel and forensics collectors pushed it over, and
# the symptom was exactly what coverage.py is built to catch: short-interval
# checks silently starving behind a four-minute firewall audit and serving
# hour-old snapshots that still looked current.
#
# Measured on the original WSL2 workstation: the costs are dominated by the
# queries that cross the WSL interop boundary; a bare powershell.exe round
# trip is 0.5s. scan 2.2s, feeds ~90s (network), coverage/hunt/gaps under 0.5s
# because they only touch SQLite.
#
JOBS = {
    "scan":     (60,    "Processes & network"),
    # Early in the dict so that on a cold start the watchdogs run before the
    # slower jobs. Both healthy paths are local-only (well under a second).
    #
    # "bridge" is a standalone, fast copy of coverage.py's Windows-bridge
    # check: available() only stats a socket, so at 45s it can page within a
    # minute of the interop link dying instead of waiting for the 10-minute
    # coverage cycle. Its finding is classed as an outage, so it mails
    # immediately regardless of alert_min_severity.
    "bridge":   (45,    "Windows bridge reachability"),
    "input_hook":(45,   "Input monitor watchdog"),
    "resources":(300,   "Resource pressure"),
    "coverage": (600,   "Self-audit & blind spots"),
    # Local and cheap: compare what intel knows against what is on the box.
    "hunt":     (1800,  "Threat-intel indicator hunt"),
    "gaps":     (21600, "Detection coverage vs current intel"),
    # Networked and metered. One topic per run, so the corpus rotates itself
    # and the daily budget guard in intel.py is what actually bounds spend.
    "intel":    (18000, "Threat-intelligence refresh"),
    # Runs after the equally frequent intel refresh in declaration-order ties,
    # so a report can describe the newest research rather than the prior wave.
    "report":   (18000, "Five-hour security advisory"),
    # Free, unauthenticated and high volume. Each feed has its own publisher
    # cadence; this job just asks which are due.
    "feeds":    (3600,  "Bulk indicator feeds"),
    # Cheap: the helper does the watching, this only drains its output file
    # and runs the injected-event audit. The short-interval "input_hook"
    # watchdog (declared above) is what keeps the helper itself alive.
    "input":    (300,   "Synthetic input"),
}


def scan_findings(res):
    """Turn a monitor.scan() result into findings in the common shape."""
    out = []
    for f in res["findings"]:
        remotes = ", ".join(
            f"{r['ip']}:{r['port']}" for r in f["remotes"][:3]
            if r["scope"] == "public")
        out.append({
            "category": "process", "severity": f["severity"],
            "host": f["host"],
            "title": f"{f['name']} [pid {f['pid']}]"
                     + (" — NEW" if f["unknown"] else ""),
            "detail": (f["cmdline"] or "")[:160]
                      + (f"  →  {remotes}" if remotes else ""),
            "where": f["exe"] or f.get("script") or "",
        })
    for p in res["new_public_peers"]:
        out.append({
            "category": "peer", "severity": "medium",
            "host": p["proc"]["host"],
            "title": "new external peer",
            "detail": f"{p['ip']}:{p['port']} ← {p['proc']['name']}",
            "where": p["proc"].get("exe") or "",
        })
    return out


def _run_job(name, hosts):
    """Run one audit and return its findings in the common shape."""
    if name == "scan":
        # The process scan is stateful (it maintains the baseline), so it needs
        # its own store handle inside the worker thread.
        store = Store(_run_job.db_path)
        try:
            return scan_findings(monitor.scan(store, hosts=hosts))
        finally:
            store.close()

    if name == "resources":
        store = Store(_run_job.db_path)
        try:
            return resourcewatch.audit(store, hosts=hosts)
        finally:
            store.close()
    if name == "bridge":
        return coverage_mod.bridge_status()
    if name == "coverage":
        return coverage_mod.sort_findings(
            coverage_mod.audit(db_path=_run_job.db_path, hosts=hosts))
    if name == "report":
        store = Store(_run_job.db_path)
        try:
            return alert.advisory_report(store, JOBS)
        finally:
            store.close()
    if name in ("input", "input_hook"):
        store = Store(_run_job.db_path)
        try:
            # The Windows-side hook does not survive a reboot or a WSL restart
            # and nothing outside this loop respawns it, so supervise() keeps
            # it up — cheaply on the healthy path, with backoff and flap
            # detection when it is not. "input_hook" is the short-interval
            # watchdog; "input" additionally runs the full injected-event audit.
            pids, findings = inputwatch.supervise(store, deep=(name == "input"))
            if name == "input":
                findings += inputwatch.audit(store, pids=pids, supervised=True)
            return findings
        finally:
            store.close()

    if name == "feeds":
        store = Store(_run_job.db_path)
        try:
            results = feeds.refresh(store)
            results.append(feeds.refresh_attack(store))
            out = []
            for r in results:
                if r.get("error"):
                    out.append({"category": "feed", "severity": "medium",
                                "host": "wsl",
                                "title": f"{r['name']} feed failed",
                                "detail": r["error"], "where": ""})
            kept = sum(r.get("kept", 0) for r in results if not r.get("error"))
            if kept:
                out.append({"category": "feed", "severity": "low", "host": "wsl",
                            "title": f"{kept} indicators refreshed",
                            "detail": ", ".join(
                                r["name"] for r in results
                                if r.get("kept")), "where": ""})
            feeds.prune(store)
            return out
        finally:
            store.close()

    if name in ("hunt", "gaps", "intel"):
        store = Store(_run_job.db_path)
        try:
            if name == "hunt":
                return hunt.sort_findings(hunt.hunt(store, hosts=hosts))
            if name == "gaps":
                return hunt.gaps(store)[0]
            try:
                options = intel.daemon_options(store)
                stats = intel.refresh(store, **options)
            except intel.BudgetExceeded as exc:
                # Not a failure: the brake worked. Say so quietly and keep the
                # previous findings on the dashboard.
                return [{"category": "intel", "severity": "low",
                         "host": "wsl", "title": "intel refresh paused",
                         "detail": str(exc), "where": ""}]
            out = []
            if stats["errors"]:
                out.append({
                    "category": "intel", "severity": "medium", "host": "wsl",
                    "title": "intel refresh had errors",
                    "detail": "; ".join(stats["errors"])[:400], "where": ""})
            out.append({
                "category": "intel", "severity": "low", "host": "wsl",
                "title": f"refreshed {', '.join(stats['topics'])}",
                "detail": f"{stats['docs']} documents, {stats['kept']} indicators "
                          f"kept of {stats['seen']} candidates, "
                          f"${stats['cost']:.3f}",
                "where": ""})
            return out
        finally:
            store.close()
    raise ValueError(name)


class Scheduler(threading.Thread):
    """Runs the audits forever, one at a time, each on its own interval."""

    daemon = True

    def __init__(self, db_path, hosts):
        super().__init__(name="jarvis-origin-scheduler")
        self.db_path = db_path
        self.hosts = hosts
        # Give every cold-start job a real deadline. Using 0 here makes every
        # job that has not run yet appear decades more overdue than a recurring
        # short-interval job. The result is a full, multi-minute cold-start
        # sweep before scan/bridge/input_hook get their second turn.
        first_deadline = time.time()
        self.next_run = {name: first_deadline for name in JOBS}
        # Coverage judges persisted timestamps. On restart those timestamps are
        # necessarily from the previous process until each collector gets its
        # first turn; running coverage halfway through that cold-start sweep
        # sends a burst of false "stale" pages for perfectly healthy jobs later
        # in the dict. Hold the automatic coverage pass until every other job
        # has attempted once. A manually forced pass still runs immediately.
        self.cold_start_pending = set(JOBS) - {"coverage", "report"}
        self.forced = []
        self.current = None
        # Bumped at the top of every loop iteration. The systemd watchdog pings
        # only while this keeps advancing, so a wedged scheduler — alive process,
        # frozen snapshots — gets the service restarted instead of going
        # unnoticed. It is deliberately not touched mid-job: the longest job
        # (~106s) must not look like a hang, but a multi-minute stall must.
        self.heartbeat = time.time()
        self.started_at = time.time()
        self.lock = threading.Lock()
        _run_job.db_path = db_path

    def force(self, name):
        if name in JOBS:
            with self.lock:
                self.forced.append(name)
            return True
        return False

    def _due(self):
        with self.lock:
            if self.forced:
                return self.forced.pop(0)
        now = time.time()
        most_overdue, score = None, None
        for name, t in self.next_run.items():
            if name in ("coverage", "report") and self.cold_start_pending:
                continue
            if t > now:
                continue
            # Compare lateness as a fraction of each job's own cadence. An
            # absolute oldest-deadline policy starves the one-minute watchdogs
            # behind every not-yet-run hourly collector after a restart or a
            # long suspend. Relative lateness keeps all cadences represented;
            # stable dict order remains the tie-breaker on the first pass.
            overdue = (now - t) / max(1, JOBS[name][0])
            if score is None or overdue > score:
                most_overdue, score = name, overdue
        return most_overdue

    def run(self):
        store = Store(self.db_path)
        try:
            while True:
                self.heartbeat = time.time()
                name = self._due()
                if name is None:
                    time.sleep(1)
                    continue
                self.current = name
                started = time.time()
                findings, err = [], ""
                try:
                    findings = _run_job(name, self.hosts)
                    store.save_snapshot(name, findings, max(0.0, time.time() - started))
                except Exception:
                    # One broken collector must never stop the other six.
                    err = traceback.format_exc()[-800:]
                    store.save_snapshot(name, [], max(0.0, time.time() - started), err)
                finally:
                    self.current = None
                    self.next_run[name] = time.time() + JOBS[name][0]
                    self.cold_start_pending.discard(name)
                # Page out anything that warrants it — especially a collector
                # that has stopped recording. Guarded so a mail failure can
                # never take down the scheduler.
                try:
                    alert.dispatch(store, name, findings, error=err)
                except Exception:
                    pass
        finally:
            store.close()


def _watchdog_loop(scheduler):
    """Feed the systemd hardware-style watchdog, but only while healthy.

    Healthy == the scheduler thread is alive and has looped within
    STALL_LIMIT seconds. If it has wedged or died we simply stop pinging;
    systemd then hits WatchdogSec, kills the process and starts it clean.
    A monitor that quietly stops monitoring is the exact failure this whole
    module exists to prevent, so the watchdog treats "no progress" as death.
    """
    usec = sdnotify.watchdog_usec()
    if not usec:
        return
    interval = max(5.0, usec / 1_000_000 / 3)
    # A job may honestly run for minutes — `intel` does networked LLM calls —
    # so the bar for "wedged" is deliberately high. Killing a healthy daemon
    # mid-refresh would make this hardening an outage of its own.
    stall_limit = max(600.0, usec / 1_000_000 * 0.8)
    while True:
        time.sleep(interval)
        alive = scheduler.is_alive()
        progressed = (time.time() - scheduler.heartbeat) < stall_limit
        if alive and progressed:
            sdnotify.watchdog()
        # else: withhold the ping and let systemd restart us.


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def _intel_state(store):
    """Knowledge-base health, so the page shows what the hunt is hunting with.

    A hunt that finds nothing is only reassuring if the thing doing the hunting
    is current. Showing the indicator count, the age of each feed and the last
    refresh makes "no findings" mean something.
    """
    try:
        kinds = {r["kind"]: r["n"] for r in store.db.execute(
            "SELECT kind, COUNT(*) n FROM indicators WHERE status='active' "
            "GROUP BY kind ORDER BY n DESC")}
        feeds_rows = [dict(r) for r in store.db.execute(
            "SELECT name,last_run,rows,kept,error FROM feed_runs ORDER BY name")]
        hits = [dict(r) for r in store.db.execute(
            "SELECT ts,kind,value,host,severity,evidence FROM hunt_hits "
            "ORDER BY ts DESC LIMIT 20")]
        docs = store.db.execute(
            "SELECT COUNT(*) FROM intel_docs").fetchone()[0]
        today = time.strftime("%Y%m%d")
        return {
            "total": sum(kinds.values()),
            "kinds": kinds,
            "docs": docs,
            "feeds": feeds_rows,
            "hits": hits,
            "last_refresh": int(store.get_meta("intel_last_refresh", 0) or 0),
            "last_hunt": int(store.get_meta("hunt_last_run", 0) or 0),
            "spend_today": float(store.get_meta(f"intel_spend_{today}", 0) or 0),
            "spend_total": float(store.get_meta("intel_spend_total", 0) or 0),
        }
    except Exception:
        return {"total": 0, "kinds": {}, "docs": 0, "feeds": [], "hits": [],
                "last_refresh": 0, "last_hunt": 0,
                "spend_today": 0.0, "spend_total": 0.0}


def build_state(db_path, scheduler):
    store = Store(db_path)
    try:
        snaps = store.get_snapshots()
        jobs, all_findings, all_checks = [], [], []
        for name, (interval, label) in JOBS.items():
            s = snaps.get(name)
            counts, ok_count = {}, 0
            if s:
                for f in s["findings"]:
                    sev = f.get("severity")
                    if sev == "ok":
                        # "Checked and found clean" is a result, not an absence
                        # of one. Without it the page cannot distinguish a check
                        # that passed from a check that never ran.
                        ok_count += 1
                        all_checks.append({**f, "job": name})
                    elif sev:
                        counts[sev] = counts.get(sev, 0) + 1
                        all_findings.append({**f, "job": name})
            jobs.append({
                "name": name, "label": label, "interval": interval,
                "ts": s["ts"] if s else 0,
                "duration": round(s["duration"], 1) if s else 0,
                "error": (s["error"] or "")[:400] if s else "",
                "counts": counts, "ok": ok_count,
                "stale": bool(s and s["ts"]
                              and (time.time() - s["ts"]) > max(interval * 2,
                                                                interval + 300)),
                "running": scheduler.current == name,
                "next": int(scheduler.next_run.get(name, 0) - time.time()),
            })

        all_findings.sort(key=lambda f: (SEV_ORDER.get(f.get("severity"), 9),
                                         f.get("job", "")))
        worst = all_findings[0]["severity"] if all_findings else "ok"
        totals = {}
        for f in all_findings:
            totals[f["severity"]] = totals.get(f["severity"], 0) + 1

        all_checks.sort(key=lambda f: (f.get("job", ""), f.get("title", "")))

        by_host = {}
        for f in all_findings:
            h = f.get("host") or "?"
            by_host.setdefault(h, {})
            by_host[h][f["severity"]] = by_host[h].get(f["severity"], 0) + 1

        by_category = {}
        for f in all_findings:
            c = f.get("category") or "other"
            by_category[c] = by_category.get(c, 0) + 1

        def _count(sql):
            try:
                return store.db.execute(sql).fetchone()[0]
            except Exception:
                return 0

        return {
            "now": now(),
            "worst": worst,
            "totals": totals,
            "by_host": by_host,
            "by_category": by_category,
            "jobs": jobs,
            "findings": all_findings[:1000],
            "findings_total": len(all_findings),
            "checks": all_checks,
            "history": store.get_history(24),
            "peers": [dict(r) for r in store.list_peers(scope="public", limit=60)],
            "events": [dict(r) for r in store.list_events(limit=40)],
            "stats": {
                "procs": _count("SELECT COUNT(*) FROM procs"),
                "approved": _count("SELECT COUNT(*) FROM procs WHERE approved=1"),
                "peers": _count("SELECT COUNT(*) FROM peers"),
                "peers_public": _count(
                    "SELECT COUNT(*) FROM peers WHERE scope='public'"),
                "events": _count("SELECT COUNT(*) FROM events"),
            },
            "intel": _intel_state(store),
            "baseline_at": store.get_meta("baseline_at"),
            "db": db_path,
        }
    finally:
        store.close()


# Binding to 127.0.0.1 is NOT sufficient on its own. A malicious page you visit
# can point a hostname it controls at 127.0.0.1 (DNS rebinding); the browser then
# treats that hostname as same-origin with this server and can read every
# response — which for this tool means handing over a complete map of the
# machine's firewall gaps, running processes and external peers. The defence is
# to check the Host header and serve only names we expect.
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


class Handler(BaseHTTPRequestHandler):
    server_version = "Jarvis Origin"
    db_path = DEFAULT_DB
    scheduler = None

    def log_message(self, *a):
        pass  # the dashboard polls constantly; access logs would be noise

    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip()
        # Strip the port; ports are not part of the rebinding decision.
        if host.startswith("["):                      # bracketed IPv6 literal
            name = host[: host.index("]") + 1] if "]" in host else host
        else:
            name = host.rsplit(":", 1)[0] if ":" in host else host
        return name.lower() in ALLOWED_HOSTS

    def _same_origin(self):
        """Reject cross-site calls. Browsers that send Sec-Fetch-Site make this
        exact; for anything older we fall back to checking Origin."""
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None:
            return site in ("same-origin", "none")
        origin = self.headers.get("Origin")
        if not origin:
            return True  # curl and friends send no Origin at all
        return any(origin == f"http://{h}:{self.server.server_address[1]}"
                   for h in ("localhost", "127.0.0.1"))

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # The page is entirely self-contained; forbid anything external.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, json.dumps({"error": "bad host"}))
        if not self._same_origin():
            return self._send(403, json.dumps({"error": "cross-site request"}))
        url = urlparse(self.path)
        if url.path == "/api/run":
            job = (parse_qs(url.query).get("job") or [""])[0]
            ok = self.scheduler.force(job)
            return self._send(200 if ok else 404, json.dumps({"queued": ok}))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, "forbidden: unexpected Host header\n"
                                   "reach this dashboard as http://localhost:PORT",
                              "text/plain")
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            try:
                with open(PAGE, "r", encoding="utf-8") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                return self._send(500, "dashboard.html missing", "text/plain")

        if url.path == "/api/state":
            return self._send(200, json.dumps(
                build_state(self.db_path, self.scheduler), default=str))

        # /api/run is a state-changing action, so it is POST-only: a cross-site
        # page cannot force one without a preflight it will not survive.
        if url.path == "/api/run":
            return self._send(405, json.dumps({"error": "use POST"}))

        return self._send(404, json.dumps({"error": "not found"}))


def serve(db_path=DEFAULT_DB, port=8790, hosts=("wsl", "win")):
    scheduler = Scheduler(db_path, hosts)
    scheduler.start()

    # Tell systemd we are up, then keep the watchdog fed for as long as the
    # scheduler is actually making progress. Both are no-ops when not run under
    # a systemd unit that asked for them.
    sdnotify.ready()
    sdnotify.status(f"scheduling {len(JOBS)} jobs")
    wd = threading.Thread(target=_watchdog_loop, args=(scheduler,),
                          name="jarvis-origin-watchdog", daemon=True)
    wd.start()

    Handler.db_path = db_path
    Handler.scheduler = scheduler
    # Localhost only, deliberately and without an override.
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    # flush=True so journalctl shows these immediately under systemd, where
    # stdout is a pipe and would otherwise stay buffered indefinitely.
    print(f"Jarvis Origin dashboard  \u2192  http://127.0.0.1:{port}", flush=True)
    print(f"  watching {'+'.join(hosts)};  database {db_path}", flush=True)
    print("  jobs: " + ", ".join(f"{n} every {v[0]}s" for n, v in JOBS.items()),
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
