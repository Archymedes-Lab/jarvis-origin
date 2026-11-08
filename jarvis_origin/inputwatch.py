"""Synthetic input: keystrokes and clicks that no human produced.

Windows tags every keyboard and mouse event that did not originate from real
hardware. `LLKHF_INJECTED` is set on anything delivered through `SendInput` or
`keybd_event`, and `LLKHF_LOWER_IL_INJECTED` additionally marks input injected
by a process at a lower integrity level than the window receiving it — which is
the shape of one program driving another's UI.

That flag is only visible from inside a low-level hook, so this module manages a
small Windows-side helper that installs one. Three things about that are worth
stating plainly, because all three are real costs:

**It is an agent.** Everything else here is agentless — it samples state and
exits. This runs resident on the Windows side, and if it dies the record stops.
The heartbeat exists so that a dead hook and a quiet keyboard are
distinguishable, because otherwise "no injected input" would be
indistinguishable from "not watching".

**It deliberately does not record what you type.** A low-level keyboard hook
sees every keystroke, and one that stored key values would be a keylogger
writing passwords to a SQLite file on a disk this machine's own posture audit
has confirmed is unencrypted. So real keystrokes are counted and nothing more;
injected events record only a coarse key class, the flags, and which window had
focus. Enough to say "something typed Enter into your terminal at 03:14", not
enough to reconstruct a sentence.

**Injected does not mean malicious.** Password-manager auto-type, AutoHotkey,
on-screen keyboards, accessibility tools, remote desktop, screen sharing and
some IDE features all inject legitimately. The flag also says nothing about
*which* process injected — only that the event was synthetic. The foreground
window is recorded as a weak correlate. So this reports evidence with the
context needed to judge it, and does not pretend to a verdict.
"""

import hashlib
import json
import os
import statistics
import subprocess

from . import collect_windows
from .util import iso, now

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

HOOK_PS1 = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "win", "inputhook.ps1")

# The name the helper is staged and launched under on Windows. It is unique to
# this project on purpose: the helper is found (and on reconciliation, stopped)
# by matching this name in powershell.exe command lines, and a generic name
# would match — and kill — another tool's hook helper on the same machine.
HELPER_NAME = "jarvis-origin-inputhook.ps1"

# Software that injects input as its normal job. Seeing these in the foreground
# alongside injected events is an explanation, not a finding.
BENIGN_INJECTORS = {
    "1password", "bitwarden", "keepass", "keepassxc", "lastpass", "dashlane",
    "autohotkey", "ahk", "osk", "tabtip", "magnify", "narrator",
    "mstsc", "rdpclip", "teamviewer", "anydesk", "rustdesk", "vncviewer",
    "synergy", "barrier", "deskflow", "sharemouse", "logioptionsplus",
    "logitech", "razer", "steam", "vmware", "virtualbox",
    "parsec", "moonlight", "sunshine", "obs64", "obs32",
}


def _finding(category, severity, title, detail, where="", host="win"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


_PATHS_CACHE = None


def _paths():
    """Where the helper writes, in both Windows and WSL spelling.

    `$env:LOCALAPPDATA` is fixed for the life of the machine, so the resolved
    answer is cached: the short-interval watchdog calls this every pass and a
    powershell.exe round trip each time would defeat the point of a local-only
    health check. A run that only reaches the fallback is not cached, so a
    transient interop failure does not pin us to C:\\Windows\\Temp.
    """
    global _PATHS_CACHE
    if _PATHS_CACHE:
        return _PATHS_CACHE
    out = collect_windows.ps_json(
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$env:LOCALAPPDATA})))", timeout=60)
    base = (out or {}).get("t")
    resolved = bool(base)
    base = base or r"C:\Windows\Temp"
    p = base.replace("\\", "/")
    wsl = "/mnt/" + p[0].lower() + p[2:] if len(p) > 2 and p[1] == ":" else "/tmp"
    wsl_dir = os.path.join(wsl, "JarvisOrigin")
    # Only create the directory once Windows has told us where it lives. With
    # the bridge down there is no helper to write there, and a fallback guess
    # must never leave files on the Windows filesystem.
    if resolved:
        try:
            os.makedirs(wsl_dir, exist_ok=True)
        except OSError:
            pass
    pair = (base + r"\JarvisOrigin\input.jsonl", os.path.join(wsl_dir, "input.jsonl"))
    if resolved:
        _PATHS_CACHE = pair
    return pair


def _stage_helper():
    """Copy the hook script somewhere powershell.exe can actually reach."""
    win_out, wsl_out = _paths()
    wsl_dir = os.path.dirname(wsl_out)
    dest = os.path.join(wsl_dir, HELPER_NAME)
    try:
        with open(HOOK_PS1, encoding="utf-8") as src, \
                open(dest, "w", encoding="utf-8-sig") as dst:
            dst.write(src.read())
    except OSError as exc:
        return None, None, f"could not stage the hook helper: {exc}"
    return win_out.rsplit("\\", 1)[0] + "\\" + HELPER_NAME, win_out, ""


def _pid_path():
    _win, wsl_out = _paths()
    return os.path.splitext(wsl_out)[0] + ".pid"


def running():
    """PIDs of the helper on the Windows side, if it is alive.

    Reads a pid file the helper writes rather than searching command lines.
    Searching was subtly wrong: the query's own command line contains the
    script name, so the querying shell matched itself, `running()` was always
    true, and `start()` short-circuited on "already running" without ever
    launching anything.
    """
    try:
        with open(_pid_path()) as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return []
    d = collect_windows.ps_json(
        "$ok = 0; try { $p = Get-Process -Id %d -ErrorAction Stop; "
        "if ($p.ProcessName -eq 'powershell') { $ok = 1 } } catch { };"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{ok=$ok})))" % pid, timeout=90)
    return [pid] if (d or {}).get("ok") else []


def _lock_path():
    _win, wsl_out = _paths()
    return os.path.splitext(wsl_out)[0] + ".starting"


def start():
    """Launch the hook helper, hidden and detached. Returns "" on success.

    Guarded by a short-lived lock file. `running()` reads the pid file, which
    the helper does not write until its hook is installed a few seconds in, so
    two supervise cycles racing through that window would each launch a helper
    — which is exactly the duplicate-process condition the watchdog then flags.
    """
    if running():
        return "already running"
    try:
        age = now() - os.path.getmtime(_lock_path())
        if age < 45:
            return "a start is already in progress"
    except OSError:
        pass
    if not collect_windows.available():
        return "the Windows interop bridge is not available"
    script_win, win_out, err = _stage_helper()
    if err:
        return err
    try:
        with open(_lock_path(), "w") as fh:
            fh.write(str(now()))
    except OSError:
        pass
    cmd = ("Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "
           "'-NoProfile','-ExecutionPolicy','Bypass','-File','"
           + script_win + "','-OutFile','" + win_out + "'")
    try:
        subprocess.run([collect_windows._PS, "-NoProfile", "-NonInteractive",
                        "-Command", cmd], capture_output=True, timeout=90, cwd="/")
    except (OSError, subprocess.SubprocessError) as exc:
        return f"could not start the helper: {exc}"
    return ""


# ── Aggressive supervision ───────────────────────────────────────────────────
# The hook is a Windows-side agent that detects synthetic keystrokes and
# clicks. Anything that wants to drive this machine's UI unseen has a direct
# motive to stop it, so "start it once" is not a monitor — it has to be kept
# up, and kept up in a way that makes repeated failure loud rather than silent.
#
#   * Liveness is judged by *change*, not by any absolute timestamp. Every
#     clock reachable from WSL — a heartbeat's embedded ts, a DrvFs mtime —
#     rides the Windows clock, and this codebase has already shipped a
#     multi-hour skew there. What a skew cannot fake is motion: a live helper
#     always advances its 10 s `.alive` pulse, its output file, or its newest
#     heartbeat between two watchdog passes. Nothing moving for MISS_LIMIT
#     passes is death, confirmed with one interop probe before a restart.
#   * Restarts are backed off exponentially (BACKOFF_BASE..BACKOFF_CAP) keyed
#     to consecutive failures, so a crash loop cannot become a powershell.exe
#     spawn loop — which would be its own denial of service on the one worker.
#   * Every restart is recorded. More than FLAP_N restarts inside FLAP_WINDOW
#     is a high-severity finding: a security monitor that keeps dying is a
#     detection, not an operational annoyance.
#   * The helper script is content-pinned. A change to the trusted source is
#     surfaced; a staged copy that does not match the source aborts the
#     restart instead of launching something unexpected.
#   * start() is lock-guarded and duplicate helpers are reconciled, because two
#     hooks writing one file double-count every keystroke.
#
# This adds no attack surface: it runs inside the existing 127.0.0.1-only
# daemon, keeps nothing resident of its own, and never elevates.

HEARTBEAT_S = 60
MISS_LIMIT = 2         # watchdog passes with nothing moving before "down"
START_GRACE = 120      # a fresh helper's pulse may not have propagated yet
BACKOFF_BASE = 20
BACKOFF_CAP = 600
FLAP_WINDOW = 6 * 3600
FLAP_N = 4
GIVEUP_FAILS = 8

READ_CAP = 8 * 1024 * 1024   # bytes of helper output read per pass; a runaway
                             # helper past this is itself a finding

_M_FAILS = "input_hook_fails"          # consecutive failed supervise cycles
_M_LASTTRY = "input_hook_last_try"     # ts of the last (re)start attempt
_M_RESTARTS = "input_hook_restarts"    # json list of recent restart ts
_M_OKSINCE = "input_hook_ok_since"     # ts we last became healthy
_M_SRCSHA = "input_hook_src_sha256"    # content pin of the trusted helper
_M_PROBE = "input_hook_probe"          # json snapshot for change-based liveness
_M_OVERSIZE = "input_hook_oversized_at"  # local ts the output file blew READ_CAP
_M_DUPES = "input_hook_dupe_pids"       # "<local ts>:<pid,pid>" seen this drain


def _sha256(path):
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


def _mget_int(store, key, default=0):
    try:
        return int(store.get_meta(key, default) or default)
    except (TypeError, ValueError):
        return default


def _newest_beat(store):
    row = store.db.execute("SELECT MAX(ts) t FROM input_beats").fetchone()
    return int(row["t"]) if row and row["t"] else 0


def _restart_log(store):
    try:
        return [int(x) for x in json.loads(store.get_meta(_M_RESTARTS, "[]")
                                           or "[]")]
    except (ValueError, TypeError):
        return []


def _pidfile_pid():
    try:
        return int(open(_pid_path()).read().strip())
    except (OSError, ValueError):
        return None


def _alive_path():
    _win, wsl_out = _paths()
    return os.path.splitext(wsl_out)[0] + ".alive"


def _alive_mtime():
    try:
        return os.path.getmtime(_alive_path())
    except OSError:
        return None


def liveness(store):
    """Is the helper alive — decided by *change*, not by any absolute clock.

    Every timestamp available from WSL (a heartbeat's embedded ts, a DrvFs
    file mtime) rides the Windows clock, so a skew there defeats any "is this
    recent?" test. What cannot be faked by a skew is motion: between two
    watchdog passes a live helper always advances its 10 s `.alive` pulse, its
    output file, or its newest heartbeat. Nothing advancing across N passes is
    death.

    Returns (state, misses) where state is "fresh", "stale" or "new" (first
    observation — no prior snapshot to compare against).
    """
    snap = {"alive": _alive_mtime(),
            "size": _jsonl_size(store),
            "beat": _newest_beat(store)}
    try:
        prev = json.loads(store.get_meta(_M_PROBE, "") or "{}")
    except ValueError:
        prev = {}
    if not prev:
        snap["misses"] = 0
        store.set_meta(_M_PROBE, json.dumps(snap))
        return "new", 0
    moved = (snap["alive"] != prev.get("alive")
             or (snap["size"] >= 0 and snap["size"] != prev.get("size"))
             or snap["beat"] != prev.get("beat"))
    misses = 0 if moved else int(prev.get("misses", 0)) + 1
    snap["misses"] = misses
    store.set_meta(_M_PROBE, json.dumps(snap))
    return ("fresh" if moved else "stale"), misses


def _verify_pin(store):
    """Surface a change to the trusted helper source.

    Not a verdict — a legitimate `git pull` and tampering look identical from
    here — but the code that gets launched changing without notice is worth
    seeing, and an unreadable source means we cannot restart from known-good.
    """
    cur = _sha256(HOOK_PS1)
    if not cur:
        return [_finding(
            "input", "high",
            "the input-hook helper script is missing or unreadable",
            f"{HOOK_PS1} could not be hashed — the monitor cannot be restarted "
            f"from a known-good copy", HOOK_PS1)]
    old = store.get_meta(_M_SRCSHA, "")
    if old != cur:
        store.set_meta(_M_SRCSHA, cur)
    if old and old != cur:
        return [_finding(
            "input", "medium",
            "the input-hook helper script changed on disk",
            f"sha256 {old[:12]} → {cur[:12]}. If you did not just update "
            f"Jarvis Origin, treat an unannounced change to a security monitor as "
            f"tampering", HOOK_PS1)]
    return []


def _staged_matches_source():
    """True if the copy powershell.exe will read is identical (BOM aside) to
    the in-repo helper — a staged file rewritten under us aborts the restart."""
    _win, wsl_out = _paths()
    staged = os.path.join(os.path.dirname(wsl_out), HELPER_NAME)
    try:
        with open(HOOK_PS1, "rb") as a, open(staged, "rb") as b:
            return a.read().decode("utf-8-sig") == b.read().decode("utf-8-sig")
    except (OSError, UnicodeError):
        return False


def _jsonl_size(store):
    try:
        _w, wsl_out = _paths()
        return os.path.getsize(wsl_out)
    except OSError:
        return -1


def _helper_count():
    """How many hook helpers are actually running. >1 is unexpected.

    Excludes this query's own shell — its command line contains the script
    name too, which is the trap the pid-file approach in `running()` was
    written to avoid.
    """
    d = collect_windows.ps_json(
        "$n = @(Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\""
        " | Where-Object { $_.CommandLine -like '*" + HELPER_NAME + "*' -and "
        "$_.ProcessId -ne $PID }).Count;"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{n=$n})))", timeout=60)
    try:
        return int((d or {}).get("n"))
    except (TypeError, ValueError):
        return -1


def _dupes(store):
    """(age_seconds, "pid,pid") if ingest saw >1 helper recently, else None."""
    v = store.get_meta(_M_DUPES, "")
    if not v or ":" not in v:
        return None
    ts, pids = v.split(":", 1)
    try:
        age = now() - int(ts)
    except ValueError:
        return None
    return (age, pids) if age < 180 else None


def _flap_finding(store):
    recent = [t for t in _restart_log(store) if now() - t < FLAP_WINDOW]
    if len(recent) < FLAP_N:
        return []
    hrs = max(1, (now() - min(recent)) // 3600)
    return [_finding(
        "input", "high",
        f"the injected-input monitor has restarted {len(recent)} times in {hrs}h",
        "a security monitor that keeps dying is itself the finding — something "
        "may be calling Stop-Process on it, or it is crashing on this host. "
        "Note what holds focus when it dies", "input_beats")]


def supervise(store, deep=False):
    """Keep the hook alive; make repeated failure loud. Returns (pids, findings).

    Healthy path is cheap: drain the helper's output, see a fresh heartbeat,
    return — no powershell.exe. Only a stale or absent heartbeat escalates to
    the interop-crossing probe and a backed-off restart.

    `deep` adds the one health check that does cross the interop boundary on a
    healthy host — the LowLevelHooksTimeout registry read — so the frequent
    watchdog can leave it to the slower full audit.
    """
    out = _verify_pin(store)
    ingest(store)
    if store.get_meta(_M_OVERSIZE):
        store.set_meta(_M_OVERSIZE, "")
        out.append(_finding(
            "input", "high",
            "the input hook's output file blew past its size cap",
            f"over {READ_CAP // (1024 * 1024)} MiB of helper output in one "
            f"interval — it is writing without bound, and the overflow was "
            f"dropped rather than loaded", "input.jsonl"))

    last_try = _mget_int(store, _M_LASTTRY)
    fails = _mget_int(store, _M_FAILS)

    # Two helpers writing the same file. Reconcile before anything else: stop
    # every hook, start exactly one.
    dup = _dupes(store)
    if dup:
        store.set_meta(_M_DUPES, "")
        _stop_all()
        store.set_meta(_M_LASTTRY, now())
        store.set_meta(_M_PROBE, "")
        err = start()
        store.set_meta(_M_FAILS, 0 if not err else fails + 1)
        out.append(_finding(
            "input", "high" if err else "medium",
            "duplicate input-hook helpers were running",
            f"heartbeats from pids {dup[1]} in one interval — they double-count "
            f"and corrupt the totals. Stopped all and started one"
            + (f"; restart failed: {err}" if err else ""), "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    state, misses = liveness(store)

    # "new" means no prior snapshot to diff against. Normally that earns one
    # grace pass — but if nothing is even on disk (no pid file, no pulse file,
    # empty output) there is nothing to wait for, so treat it as down.
    present = (os.path.exists(_pid_path()) or os.path.exists(_alive_path())
               or _jsonl_size(store) > 0)
    if state == "new" and not present:
        state, misses = "stale", MISS_LIMIT

    if state in ("fresh", "new"):
        # Alive. Reset the failure counter and re-emit any flap finding.
        if fails:
            store.set_meta(_M_FAILS, 0)
        if not _mget_int(store, _M_OKSINCE):
            store.set_meta(_M_OKSINCE, now())
        out += _flap_finding(store)
        latest = store.db.execute(
            "SELECT * FROM input_beats ORDER BY ts DESC LIMIT 1").fetchone()
        out += _latency_findings(store, latest, probe_registry=deep)
        out += _typing_findings(store, latest)
        pid = _pidfile_pid()
        embedded = _newest_beat(store)
        seen = f", last heartbeat stamped {iso(embedded)}" if embedded else ""
        out.append(_finding(
            "input", "ok", "the injected-input monitor is healthy",
            f"pid {pid or '?'} — pulse, output file or heartbeat advanced since "
            f"the last check{seen}", "inputwatch"))
        return ([pid] if pid else []), sort_findings(out)

    if last_try and now() - last_try < START_GRACE:
        out.append(_finding(
            "input", "low", "the injected-input monitor is starting",
            f"launched {now() - last_try}s ago; waiting for its first pulse",
            "inputwatch"))
        return [], sort_findings(out)

    if misses < MISS_LIMIT:
        out.append(_finding(
            "input", "medium",
            "the injected-input monitor has gone quiet",
            f"nothing has advanced for {misses} watchdog pass(es) — pulse, "
            f"output file and heartbeat all frozen. One more and it is cycled",
            "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    # Frozen for MISS_LIMIT passes. Confirm across the interop boundary.
    alive = bool(running())
    pid = _pidfile_pid()
    helpers = _helper_count()
    if helpers > 1:
        _stop_all()
        alive = False
        out.append(_finding(
            "input", "medium", f"{helpers} input-hook helpers were running",
            "more than one hook writing the same file — stopped all, starting "
            "one", "inputwatch"))
    elif alive:
        # Process up but everything frozen — the hook was removed or the loop
        # is wedged. Same remedy either way.
        out.append(_finding(
            "input", "high",
            "the input hook is running but has stopped watching",
            f"pid {pid} is alive, yet its pulse, output file and heartbeat have "
            f"all been frozen for {misses} passes — the low-level hook was "
            f"removed or the message loop is stuck. Cycling it", "inputwatch"))
        stop()
        alive = False

    if not collect_windows.available():
        out.append(_finding(
            "input", "medium",
            "the injected-input monitor is down and cannot be restarted",
            "the Windows interop bridge is unavailable — environmental, not "
            "necessarily tampering; will retry", "inputwatch"))
        return [], sort_findings(out)

    delay = min(BACKOFF_BASE * (2 ** fails), BACKOFF_CAP)
    if last_try and now() - last_try < delay:
        out.append(_finding(
            "input", "high" if fails >= FLAP_N else "medium",
            "the injected-input monitor is down",
            f"restart backed off — {fails} consecutive failures, next attempt "
            f"in {delay - (now() - last_try)}s", "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    store.set_meta(_M_LASTTRY, now())
    store.set_meta(_M_PROBE, "")          # next liveness() starts a clean baseline
    err = start()
    if not err and not _staged_matches_source():
        stop()
        err = "the staged helper does not match its trusted source"

    if err:
        n = fails + 1
        store.set_meta(_M_FAILS, n)
        sev = ("critical" if n >= GIVEUP_FAILS else
               "high" if n >= FLAP_N else "medium")
        out.append(_finding(
            "input", sev, "could not restart the injected-input monitor",
            f"{err} — {n} consecutive failures", "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    log = [t for t in _restart_log(store) if now() - t < 86400] + [now()]
    store.set_meta(_M_RESTARTS, json.dumps(log[-64:]))
    store.set_meta(_M_FAILS, 0)
    store.set_meta(_M_OKSINCE, 0)
    out.append(_finding(
        "input", "medium",
        "the injected-input monitor was down and has been restarted",
        "synthetic-input recording had stopped; a fresh hook is starting up",
        "inputwatch"))
    return [], sort_findings(out + _flap_finding(store))


def ensure():
    """Best-effort "make sure it is up" for callers without a Store handle."""
    pids = running()
    if pids:
        return pids
    start()
    return running()


def stop():
    pids = running()
    if not pids:
        return "not running"
    collect_windows.ps_json("Stop-Process -Id " + ",".join(str(p) for p in pids)
             + " -Force; [Convert]::ToBase64String([Text.Encoding]::UTF8"
               ".GetBytes((ConvertTo-Json @{ok=1})))", timeout=90)
    for p in (_pid_path(), _alive_path()):
        try:
            os.remove(p)
        except OSError:
            pass
    return ""  # note: under the daemon, the watchdog will start it again


def _stop_all():
    """Kill every hook helper, not just the one in the pid file.

    A race in `start()` (now locked) could once leave two helpers writing to
    the same file and double-counting. Reconciliation is: stop them all, clear
    the state files, and let the caller start exactly one.
    """
    collect_windows.ps_json(
        "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | "
        "Where-Object { $_.CommandLine -like '*" + HELPER_NAME + "*' -and "
        "$_.ProcessId -ne $PID } | ForEach-Object { Stop-Process -Id "
        "$_.ProcessId -Force -EA SilentlyContinue };"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{ok=1})))", timeout=90)
    for p in (_pid_path(), _alive_path(), _lock_path()):
        try:
            os.remove(p)
        except OSError:
            pass


_BEAT_COLS = ("real_keys", "injected_keys", "real_clicks", "injected_clicks",
              "real_moves", "injected_moves", "injected_keyups",
              "injected_move_bursts", "real_key_gaps", "real_key_sub20",
              "real_key_sub8", "cad_run_max", "lat_avg_ms", "lat_max_ms",
              "lat_over50", "lat_samples")
_BEAT_SQL = ("INSERT OR REPLACE INTO input_beats (ts," + ",".join(_BEAT_COLS)
             + ") VALUES (" + ",".join("?" * (len(_BEAT_COLS) + 1)) + ")")

_WINDOW_COLS = ("real_keys", "injected_keys", "real_key_gaps",
                "real_key_sub20", "real_key_sub8", "cad_run_max",
                "equals_keys", "slash_keys", "period_keys")
_WINDOW_SQL = ("INSERT OR REPLACE INTO input_typing_windows (ts,"
               + ",".join(_WINDOW_COLS) + ") VALUES ("
               + ",".join("?" * (len(_WINDOW_COLS) + 1)) + ")")


def ingest(store):
    """Fold new helper output into the database, then truncate the file.

    The read is capped: a helper writing without bound is a fault, and past the
    cap that fact is recorded rather than loaded into memory. Heartbeats from
    more than one PID in a drain flag a duplicate helper.
    """
    _win_out, wsl_out = _paths()
    if not os.path.exists(wsl_out):
        return 0
    try:
        size = os.path.getsize(wsl_out)
        with open(wsl_out, "r+", encoding="utf-8", errors="replace") as fh:
            body = fh.read(READ_CAP)
            fh.seek(0)
            fh.truncate()
    except OSError:
        return 0
    if size > READ_CAP:
        store.set_meta(_M_OVERSIZE, now())

    beats, windows, events, beat_pids = [], [], [], set()
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("kind") == "heartbeat":
            c = rec.get("counters") or {}
            ts = int(rec.get("ts") or now())
            beats.append((ts,)
                         + tuple(int(c.get(k) or 0) for k in _BEAT_COLS))
            window = rec.get("window") or {}
            if window:
                windows.append((ts,) + tuple(
                    int(window.get(k) or 0) for k in _WINDOW_COLS))
            if rec.get("pid"):
                beat_pids.add(int(rec["pid"]))
        else:
            events.append(
                (int(rec.get("ts") or now()), str(rec.get("kind") or "key")[:16],
                 int(rec.get("lower_il") or 0), str(rec.get("class") or "")[:24],
                 str(rec.get("fg") or "")[:64]))
    if beats:
        store.db.executemany(_BEAT_SQL, beats)
    if windows:
        store.db.executemany(_WINDOW_SQL, windows)
    if events:
        store.db.executemany(
            "INSERT INTO input_events(ts,kind,lower_il,class,fg) VALUES(?,?,?,?,?)",
            events)
    # Heartbeats from more than one PID in a single drain means two helpers are
    # writing to the same file and double-counting. Cheap and local — no
    # interop — so the healthy path can check it too.
    if len(beat_pids) > 1:
        store.set_meta(_M_DUPES,
                       f"{now()}:{','.join(str(p) for p in sorted(beat_pids))}")
    if beats or windows or events:
        # Minute windows give a useful 90-day baseline at only ~130k rows.
        # Raw cumulative beats and injected-event detail need much less history;
        # bounding all three keeps the SQLite file small indefinitely.
        stamp = now()
        store.db.execute("DELETE FROM input_typing_windows WHERE ts < ?",
                         (stamp - 90 * 86400,))
        store.db.execute("DELETE FROM input_beats WHERE ts < ?",
                         (stamp - 7 * 86400,))
        store.db.execute("DELETE FROM input_events WHERE ts < ?",
                         (stamp - 30 * 86400,))
        store.commit()
    return len(events)


def audit(store, hours=24, pids=None, supervised=False):
    out = []
    ingest(store)
    since = now() - hours * 3600

    beat = store.db.execute(
        "SELECT * FROM input_beats ORDER BY ts DESC LIMIT 1").fetchone()

    # When the supervisor has already run it owns the liveness and latency
    # narrative; audit adds only what it alone produces — the injected-event
    # breakdown below.
    if not supervised:
        if pids is None:
            pids = running()
        if not pids:
            out.append(_finding(
                "input", "medium", "the injected-input monitor is not running",
                "synthetic keystrokes are only visible from inside a live hook, "
                "so nothing is being recorded — this is not a clean result",
                "jarvis-origin inputwatch --start"))
        elif beat and now() - beat["ts"] > 300:
            out.append(_finding(
                "input", "high", "the input hook has stopped reporting",
                f"the helper is alive but its last heartbeat was "
                f"{iso(beat['ts'])} — a hook that was removed looks exactly "
                f"like a quiet keyboard", "inputwatch"))
        else:
            totals = (f"{beat['real_keys']} real keystrokes / "
                      f"{beat['injected_keys']} injected "
                      f"(+{beat['injected_keyups']} injected key-ups), "
                      f"{beat['real_moves']} real cursor moves / "
                      f"{beat['injected_moves']} injected in "
                      f"{beat['injected_move_bursts']} bursts"
                      if beat else "no counts yet")
            out.append(_finding(
                "input", "ok", "the injected-input monitor is running",
                f"pid {pids[0]} — {totals}", "inputwatch"))
        out += _latency_findings(store, beat)
        out += _typing_findings(store, beat)

    rows = store.db.execute(
        """SELECT fg, kind, class, lower_il, COUNT(*) n,
                  MIN(ts) first, MAX(ts) last
             FROM input_events WHERE ts>=?
            GROUP BY fg, kind, class, lower_il
            ORDER BY COUNT(*) DESC""", (since,)).fetchall()
    for r in rows:
        fg = (r["fg"] or "").lower()
        benign = any(b in fg for b in BENIGN_INJECTORS)
        if r["kind"] == "click" and benign:
            continue
        sev = ("low" if benign else
               "critical" if r["lower_il"] else
               "high" if r["kind"] == "key" else "medium")
        why = ("this program injects input as part of its normal job"
               if benign else
               "injected from a lower integrity level — the shape of one "
               "process driving another's window" if r["lower_il"] else
               "no hardware produced this event")
        out.append(_finding(
            "input", sev,
            f"{r['n']} injected {r['class'] or r['kind']}"
            f"{'s' if r['n'] > 1 else ''} while "
            f"{r['fg'] or 'an unknown window'} had focus",
            f"{why} — first {iso(r['first'])}, last {iso(r['last'])}",
            "input_events"))
    return sort_findings(out)


def _latency_findings(store, beat, probe_registry=True):
    """Is anything making the cursor and keyboard feel slow?

    Every low-level hook sits in a chain and delays each event until it
    returns. That is the mechanism behind "the cursor is slower than it used
    to be" — a keylogger, a screen recorder or an overlay doing work on the
    input thread shows up here as milliseconds.

    Windows drops a hook that exceeds `LowLevelHooksTimeout` (default 300ms),
    so software that wants to keep a slow hook alive has a reason to raise
    that value. An unexplained increase is worth seeing. That check reads the
    registry over the interop boundary, so `probe_registry=False` lets the
    frequent watchdog skip it and leave it to the full audit.
    """
    out = []
    if not beat or not beat["lat_samples"]:
        return out

    avg, mx = beat["lat_avg_ms"], beat["lat_max_ms"]
    over = beat["lat_over50"]
    pct = (100.0 * over / beat["lat_samples"]) if beat["lat_samples"] else 0

    if avg >= 30 or pct >= 10:
        sev = "high" if (avg >= 60 or pct >= 25) else "medium"
        out.append(_finding(
            "input", sev, f"input events are arriving {avg} ms late on average",
            f"peak {mx} ms; {over} of {beat['lat_samples']} events "
            f"({pct:.0f}%) took over 50 ms to reach this hook. Every low-level "
            f"hook in the chain delays input until it returns, so this is what "
            f"a keylogger, screen recorder or overlay feels like. Note that "
            f"Jarvis Origin's own hook is in that chain and contributes part of it — "
            f"stop it with `jarvis-origin inputwatch --stop` and see whether the "
            f"figure follows.", "input_beats"))
    else:
        out.append(_finding(
            "input", "ok", f"input latency is {avg} ms average, {mx} ms peak",
            f"{beat['lat_samples']} events sampled — nothing in the hook chain "
            f"is adding perceptible delay", "input_beats"))

    if not probe_registry:
        return out

    d = collect_windows.ps_json(
        "$v = (Get-ItemProperty 'HKCU:\\Control Panel\\Desktop' "
        "-Name LowLevelHooksTimeout -EA SilentlyContinue).LowLevelHooksTimeout;"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$v})))", timeout=60)
    t = (d or {}).get("t")
    if t and int(t) > 300:
        out.append(_finding(
            "input", "high", f"LowLevelHooksTimeout has been raised to {t} ms",
            "Windows removes a low-level hook that takes longer than this to "
            "return. Raising it above the 300 ms default keeps slow hooks "
            "alive — which is something a keylogger benefits from and normal "
            "software rarely needs",
            r"HKCU\Control Panel\Desktop"))
    return out


def _cadence_findings(beat):
    """Real keystrokes arriving faster or more evenly than a person can type.

    Hardware-level injection — a malicious HID filter driver, a BadUSB device,
    an IOCTL straight to kbdclass — sets no injected flag; the events are
    identical to human typing. Timing is the only tell it leaves: nobody holds
    a sub-8 ms inter-key cadence, or a long run of gaps all within 2 ms of each
    other. Key auto-repeat is already excluded on the helper side.
    """
    if not beat:
        return []
    gaps = beat["real_key_gaps"] or 0
    if gaps < 30:                       # too little typing to characterise
        return []
    sub8, sub20 = beat["real_key_sub8"] or 0, beat["real_key_sub20"] or 0
    run = beat["cad_run_max"] or 0
    p8, p20 = 100.0 * sub8 / gaps, 100.0 * sub20 / gaps

    if p8 >= 5 or run >= 40:
        extra = (f", and a run of {run} consecutive gaps stayed within 2 ms of "
                 f"each other" if run >= 20 else "")
        return [_finding(
            "input", "high",
            "real keystrokes are arriving faster than a human types",
            f"{sub8} of {gaps} inter-key gaps ({p8:.0f}%) were under 8 ms{extra}. "
            f"Driver- or hardware-level injection carries no injected flag — "
            f"cadence like this is the only signal it leaves.", "input_beats")]
    if p20 >= 25 or run >= 20:
        extra = f"; longest even run {run}" if run >= 10 else ""
        return [_finding(
            "input", "medium",
            "real keystrokes show a machine-like cadence",
            f"{sub20} of {gaps} gaps ({p20:.0f}%) were under 20 ms{extra} — fast "
            f"automation, a very fast typist, or a stuck repeat. Worth a look at "
            f"what had focus.", "input_beats")]
    return [_finding(
        "input", "ok", "keystroke cadence looks human",
        f"{gaps} inter-key gaps sampled, {p20:.0f}% under 20 ms, longest even "
        f"run {run}", "input_beats")]


def _typing_findings(store, beat):
    """Rolling, contentless typing anomalies from one-minute aggregates.

    This deliberately cannot answer "what was typed". It can answer whether a
    minute was implausibly dense, machine-fast, or dominated by the three key
    families the operator asked to watch (=, / and .).
    """
    rows = store.db.execute(
        "SELECT * FROM input_typing_windows WHERE ts >= ? ORDER BY ts DESC",
        (now() - 300,)).fetchall()
    if not rows:
        return _cadence_findings(beat)

    total = lambda key: sum(int(r[key] or 0) for r in rows)
    keys = total("real_keys")
    gaps = total("real_key_gaps")
    sub20 = total("real_key_sub20")
    sub8 = total("real_key_sub8")
    run = max((int(r["cad_run_max"] or 0) for r in rows), default=0)
    summary = {"real_key_gaps": gaps, "real_key_sub20": sub20,
               "real_key_sub8": sub8, "cad_run_max": run}
    out = _cadence_findings(summary) if gaps >= 30 else []

    labels = (("equals/plus", "equals_keys"),
              ("slash/question", "slash_keys"),
              ("period/greater-than", "period_keys"))
    for label, column in labels:
        count = total(column)
        share = 100.0 * count / keys if keys else 0.0
        # Coding naturally uses punctuation, so concentration alone is a low
        # signal. It becomes medium only alongside machine-fast cadence.
        if count >= 20 and share >= 35:
            machine_like = (sub8 >= 5 or run >= 20)
            out.append(_finding(
                "input", "medium" if machine_like else "low",
                f"typing is unusually concentrated on the {label} key",
                f"{count} of {keys} real key-down events ({share:.0f}%) in the "
                f"last five minutes used this physical key family"
                + (" alongside machine-like timing" if machine_like else
                   " — common while coding, but retained as an anomaly signal"),
                "input_typing_windows"))

    latest = int(rows[0]["real_keys"] or 0)
    baseline = [int(r[0]) for r in store.db.execute(
        "SELECT real_keys FROM input_typing_windows "
        "WHERE ts < ? AND ts >= ? AND real_keys > 0 ORDER BY ts DESC LIMIT 5000",
        (rows[0]["ts"], now() - 90 * 86400)).fetchall()]
    if len(baseline) >= 30:
        median = statistics.median(baseline)
        mad = statistics.median(abs(n - median) for n in baseline)
        threshold = max(600, median + 8 * max(mad, 5))
        if latest > threshold:
            out.append(_finding(
                "input", "medium", "typing volume spiked above its baseline",
                f"{latest} key-down events in one minute versus a median of "
                f"{median:.0f} across {len(baseline)} active baseline minutes; "
                "content was not recorded", "input_typing_windows"))
    return out


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))
