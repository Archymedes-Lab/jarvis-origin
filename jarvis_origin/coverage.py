"""Audit the monitor itself: where is it blind, degraded, or silently failing?

Every other module answers "what is wrong with the machine?". This one answers
"what can this system not see, and is it actually running?" — which is the
question that decides how much the others' silence is worth.

The failure mode this exists to prevent has already happened once here. The
daemon ran for hours reporting every Windows collector as healthy while the
interop socket was dead: each job had a timestamp, each timestamp was recent,
and every one of them was a stale snapshot being re-read. A clean report and no
report look identical unless something is specifically checking.

So the rules are:

  * A collector that has never produced a result is not "clean", it is missing.
  * A result older than its own interval is stale, and stale is a failure.
  * A check that could not run must say so where the result would have gone.
  * Degraded coverage is named with what specifically is invisible because of
    it, not as a generic warning.
"""

import os
import shutil
import subprocess
import time

from . import collect_windows
from .store import DEFAULT_DB, Store


def _finding(category, severity, title, detail, where="", host="wsl"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def _cmd(args, timeout=10):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout, text=True)
        return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def job_health(db_path=DEFAULT_DB):
    """Is every collector actually producing fresh results?"""
    from .server import JOBS

    out = []
    try:
        store = Store(db_path)
    except Exception as exc:
        return [_finding("collectors", "critical", "cannot open the database",
                         f"{exc} — nothing is being recorded", db_path)]
    try:
        snaps = store.get_snapshots()
    finally:
        store.close()

    now = time.time()
    stale, broken, missing = [], [], []
    for name, (interval, _label) in JOBS.items():
        # This audit cannot observe its own result: the scheduler writes a
        # snapshot only after the job returns, so on every run our own entry is
        # either absent or one interval old. Reporting that would be a permanent
        # false positive about the one collector that is provably running.
        if name in ("coverage", "report"):
            continue
        s = snaps.get(name)
        if not s or not s.get("ts"):
            missing.append(name)
            continue
        age = now - s["ts"]
        if s.get("error"):
            broken.append((name, s["error"]))
        # Two intervals of slack: jobs run one at a time, so a long Windows
        # audit legitimately delays the one queued behind it.
        elif age > max(interval * 2, interval + 300):
            stale.append((name, age, interval))

    for name in missing:
        out.append(_finding(
            "collectors", "critical", f"collector '{name}' has never produced a result",
            "there is no snapshot for it at all, so its entire subject area is "
            "unmonitored — this is not a clean result, it is no result",
            "jarvis-origin serve"))
    for name, err in broken:
        out.append(_finding(
            "collectors", "high", f"collector '{name}' is failing",
            f"last run raised: {err.strip().splitlines()[-1][:160] if err.strip() else 'unknown error'}",
            "jarvis-origin serve"))
    for name, age, interval in stale:
        out.append(_finding(
            "collectors", "high", f"collector '{name}' is stale",
            f"last result is {int(age // 60)} min old but it is supposed to run "
            f"every {interval // 60 or 1} min — you are reading history, not status",
            "jarvis-origin serve"))
    if not (missing or broken or stale):
        out.append(_finding(
            "collectors", "ok", "all collectors are current",
            f"{len(JOBS) - 2} collectors checked (coverage and the email report "
            f"excluded), every one fresh and error-free",
            db_path))
    return out


def daemon_health():
    """Is the 24/7 chain intact — service, linger, and the Windows logon task?"""
    out = []
    if not shutil.which("systemctl"):
        return [_finding("daemon", "medium", "systemd not available",
                         "cannot verify that the monitor runs continuously", "")]

    # `--priority` moves the unit to the system manager (still running as this
    # user) so it can hold a negative nice and OOM score. Accept either scope.
    flag = "--user"
    active = _cmd(["systemctl", "--user", "is-active", "jarvis-origin.service"])
    if active != "active" and _cmd(["systemctl", "is-active", "jarvis-origin.service"]) \
            == "active":
        flag, active = "--system", "active"
    scope = [] if flag == "--system" else ["--user"]
    enabled = _cmd(["systemctl", *scope, "is-enabled", "jarvis-origin.service"])
    hint = "" if flag == "--system" else "--user "
    if active != "active":
        out.append(_finding("daemon", "critical", "the monitor is not running",
                            f"jarvis-origin.service is '{active or 'unknown'}' — nothing "
                            f"is being collected right now",
                            f"systemctl {hint}status jarvis-origin.service"))
    if enabled not in ("enabled", "enabled-runtime", "static"):
        out.append(_finding("daemon", "high", "the monitor will not start on boot",
                            f"jarvis-origin.service is '{enabled or 'unknown'}'",
                            f"systemctl {hint}enable jarvis-origin.service"))


    linger = _cmd(["loginctl", "show-user", os.environ.get("USER", ""),
                   "--property=Linger"])
    if "yes" not in linger.lower():
        out.append(_finding(
            "daemon", "high", "linger is off — the monitor dies with your shell",
            "without linger systemd tears down the user manager when your last "
            "session ends, so closing the terminal stops monitoring",
            f"sudo loginctl enable-linger {os.environ.get('USER', '$USER')}"))

    if not out:
        out.append(_finding("daemon", "ok", "the monitor runs continuously",
                            "service active and enabled, linger on — survives "
                            "logout and restarts on failure", "systemd --user"))
    return out


def bridge_status():
    """One finding: is the Windows interop bridge reachable right now?

    Split out of visibility() so the scheduler can run it on a short interval
    of its own. The Windows side going blind is the single blind spot that has
    to page in seconds, not on the ten-minute self-audit cycle — every Windows
    collector, including the injected-input/keylogger hook, reports nothing the
    moment powershell.exe stops answering, and nothing else notices.

    Category is "collectors" and the wording carries "is down" / "interop
    bridge" on purpose: alert.py classifies that as an outage, so it bypasses
    the min-severity filter and the persistence gate and mails immediately.
    """
    if collect_windows.available():
        return [_finding(
            "collectors", "ok", "Windows bridge is up",
            f"powershell.exe reachable via {os.environ.get('WSL_INTEROP', '?')}",
            collect_windows._PS or "", host="win")]
    return [_finding(
        "collectors", "critical",
        "the Windows side is blind — interop bridge is down",
        "powershell.exe is unreachable, so every Windows collector — the "
        "Windows process view and the injected-input hook — reports nothing "
        "rather than reporting a problem. Usually a WSL interop stall rather than tampering; "
        "`wsl --shutdown` from Windows rebuilds it, and the daemon recovers on "
        "its own once it is back.",
        "WSL interop", host="win")]


def visibility():
    """Which individual views are unavailable, and what each blind spot costs."""
    out = []

    # -- the Windows bridge (also run standalone on a fast interval) ------
    out.extend(bridge_status())

    # -- elevation ---------------------------------------------------------
    if os.geteuid() != 0:
        out.append(_finding(
            "visibility", "medium", "running unprivileged",
            "invisible from here: other users' process command lines and "
            "some /proc entries. Windows-side elevation is separate and also "
            "absent: protected-process identities cannot be read.",
            "run `sudo jarvis-origin ...` for the Linux half"))


    # -- io_uring ----------------------------------------------------------
    try:
        with open("/proc/sys/kernel/io_uring_disabled") as fh:
            val = fh.read().strip()
    except OSError:
        val = ""
    if val == "0":
        out.append(_finding(
            "visibility", "medium", "io_uring is unrestricted",
            "file, socket and process operations can be performed through a "
            "shared ring instead of syscalls, where no syscall-based monitoring "
            "sees them. `sysctl -w kernel.io_uring_disabled=2` closes it.",
            "/proc/sys/kernel/io_uring_disabled"))

    return out


def known_limits():
    """State the things this design cannot do, so silence is never over-read."""
    return [
        _finding("limits", "low", "sampling, not interception",
                 "the collectors read state on an interval, so anything that "
                 "starts and exits between two passes is invisible to them. "
                 "Closing that gap needs kernel-event interception (Sysmon, "
                 "Sysmon for Linux, auditd), which Jarvis Origin does not ship.",
                 "by design"),
        _finding("limits", "low", "no kernel component",
                 "every check runs in userland, so a rootkit already in the "
                 "kernel can lie to all of them at once. Jarvis Origin has no "
                 "cross-view or kernel-integrity checks; treat its silence as "
                 "\"nothing visible from userland\", not \"nothing there\".",
                 "by design"),
        _finding("limits", "low", "WSL is not a security boundary",
                 "anything in WSL can read and write /mnt/c, and Windows can see "
                 "into WSL. Treat findings on either side as findings about one "
                 "machine.",
                 "by design"),
    ]


def audit(db_path=DEFAULT_DB, hosts=("wsl", "win")):
    out = []
    out.extend(job_health(db_path))
    out.extend(daemon_health())
    out.extend(visibility())
    out.extend(known_limits())
    return out


CAT_ORDER = {"collectors": 0, "daemon": 1, "visibility": 2, "limits": 3}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9),
                                    x["title"]))
