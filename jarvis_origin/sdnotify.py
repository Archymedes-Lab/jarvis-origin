"""Minimal sd_notify client — no dependency on python-systemd.

systemd hands a service a datagram socket in $NOTIFY_SOCKET when the unit sets
`NotifyAccess`. Writing `READY=1` once and `WATCHDOG=1` on an interval lets the
manager tell the difference between "running" and "wedged": a process that has
stopped pinging within `WatchdogSec` is killed and restarted, which is the one
failure the rest of this codebase cannot catch itself — a scheduler thread that
deadlocks keeps the process alive and every snapshot frozen.

All calls are best-effort. If there is no socket (run by hand, not under
systemd) every function is a silent no-op.
"""

import os
import socket

_SOCK = None
_ADDR = None


def _ensure():
    global _SOCK, _ADDR
    if _SOCK is not None:
        return _SOCK
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return None
    # Abstract namespace sockets start with '@' -> NUL byte.
    _ADDR = "\0" + addr[1:] if addr.startswith("@") else addr
    try:
        _SOCK = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
    except OSError:
        _SOCK = None
    return _SOCK


def _send(msg: str) -> bool:
    sock = _ensure()
    if not sock:
        return False
    try:
        sock.sendto(msg.encode("utf-8"), _ADDR)
        return True
    except OSError:
        return False


def available() -> bool:
    return bool(os.environ.get("NOTIFY_SOCKET"))


def ready():
    _send("READY=1")


def watchdog():
    _send("WATCHDOG=1")


def status(text: str):
    _send("STATUS=" + text.replace("\n", " ")[:200])


def watchdog_usec() -> int:
    """WatchdogSec, in microseconds, as systemd exported it — 0 if disabled."""
    try:
        return int(os.environ.get("WATCHDOG_USEC", "0"))
    except ValueError:
        return 0
