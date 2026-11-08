"""Sustained process consumption and whole-system capacity pressure."""

import json
import os
import shutil
import time

from . import monitor

_META = "resourcewatch_sample_v1"


def _finding(severity, title, detail, where="", host="wsl"):
    return {"category": "resource", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def _memory_pressure():
    try:
        values = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                name, value = line.split(":", 1)
                values[name] = int(value.split()[0]) * 1024
        return values["MemTotal"], values["MemAvailable"]
    except (OSError, ValueError, KeyError, IndexError):
        return 0, 0


def audit(store, hosts=("wsl", "win")):
    """Compare cumulative CPU counters with the prior five-minute sample."""
    sampled_at = time.time()
    processes = monitor.collect_all(hosts=hosts, with_sockets=False)
    try:
        previous = json.loads(store.get_meta(_META, "{}") or "{}")
    except (TypeError, ValueError):
        previous = {}
    elapsed = max(1.0, sampled_at - float(previous.get("ts", sampled_at)))
    cpu_count = max(1, os.cpu_count() or 1)
    old = previous.get("processes", {}) if isinstance(previous, dict) else {}
    current = {}
    findings = []

    for proc in processes:
        key = f"{proc.get('host')}:{proc.get('pid')}:{proc.get('fp')}"
        cpu_seconds = max(0.0, float(proc.get("cpu_seconds") or 0))
        rss = max(0, int(proc.get("rss_bytes") or 0))
        current[key] = {"cpu": cpu_seconds}
        prior = old.get(key) if isinstance(old, dict) else None
        cpu_pct = 0.0
        if prior is not None:
            cpu_pct = max(0.0, (cpu_seconds - float(prior.get("cpu", 0))) /
                              elapsed / cpu_count * 100)
        severe = rss >= 4 * 1024**3 or cpu_pct >= 50
        notable = rss >= 1536 * 1024**2 or cpu_pct >= 20
        if severe or notable:
            findings.append(_finding(
                "high" if severe else "medium", "resource-intensive process",
                f"{proc.get('name') or '?'} [pid {proc.get('pid')}] uses "
                f"{rss / 1024**3:.1f} GiB resident memory and {cpu_pct:.1f}% "
                f"of total CPU over the last {_duration(elapsed)}",
                proc.get("exe") or "", proc.get("host") or "wsl"))

    total, available = _memory_pressure()
    if total:
        pct = available / total * 100
        if pct < 10:
            findings.append(_finding(
                "high" if pct < 5 else "medium", "system memory pressure",
                f"only {available / 1024**3:.1f} GiB ({pct:.1f}%) remains available",
                "/proc/meminfo"))

    for path in ("/", "/mnt/c"):
        if not os.path.exists(path):
            continue
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            continue
        used = (usage.total - usage.free) / usage.total * 100 if usage.total else 0
        if used >= 85:
            findings.append(_finding(
                "high" if used >= 95 else "medium", "disk capacity pressure",
                f"{path} is {used:.1f}% full; low free space can stop logs, "
                "updates, quarantine, and collector snapshots", path))

    store.set_meta(_META, json.dumps({"ts": sampled_at, "processes": current}))
    findings.sort(key=lambda f: ({"high": 0, "medium": 1}.get(f["severity"], 9),
                                 f["title"], f["detail"]))
    if not findings:
        findings.append(_finding(
            "ok", "system resource headroom is healthy",
            f"{len(processes)} processes sampled; no sustained CPU, memory, or "
            "disk pressure crossed the reporting threshold"))
    return findings[:20]


def _duration(seconds):
    return f"{int(seconds)}s" if seconds < 120 else f"{int(seconds // 60)}m"
