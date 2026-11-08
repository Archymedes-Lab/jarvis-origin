"""Shared helpers: fingerprinting, IP classification, time."""

import hashlib
import ipaddress
import os
import re
import socket
import subprocess
import time

# Values that legitimately change between runs of the same program. Collapsing
# them keeps a process's fingerprint stable so restarts don't look like drift.
_VOLATILE = [
    (re.compile(r"/tmp/[^\s]*"), "/tmp/<tmp>"),
    (re.compile(r"/proc/\d+"), "/proc/<pid>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\b\d{4,}\b"), "<num>"),
    # Per-session random tokens in generated script names. Without this every
    # new shell session mints a fresh fingerprint for the same command and
    # reports it as drift forever, which is how a baseline system gets ignored.
    # Only the token is replaced — the directory stays in the fingerprint, so
    # something else appearing at that path is still unknown and still scored on
    # its own traits.
    (re.compile(r"(?<=-)[a-z0-9]{5,10}(?=\.(sh|ps1|bat|cmd)\b)", re.I), "<token>"),
    (re.compile(r"\s+"), " "),
]


def normalize_cmdline(cmdline: str) -> str:
    out = cmdline.strip()
    for pat, repl in _VOLATILE:
        out = pat.sub(repl, out)
    return out.strip()


def fingerprint(host: str, exe: str, cmdline: str, user: str) -> str:
    """Stable identity for 'this program, run this way, by this user'."""
    raw = "\x00".join([host, exe or "", normalize_cmdline(cmdline), user or ""])
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def now() -> int:
    return int(time.time())


def iso(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def classify_ip(ip: str) -> str:
    """Bucket an address so public egress stands out from local chatter."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_private:
        return "private"
    return "public"


_rdns_cache: dict[str, str] = {}


def reverse_dns(ip: str, timeout: float = 1.0) -> str:
    """Best-effort PTR lookup. Only called when --enrich is passed."""
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = ""
    finally:
        socket.setdefaulttimeout(old)
    _rdns_cache[ip] = name
    return name


def short(text: str, width: int = 70) -> str:
    text = (text or "").replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


# Directories that usrmerge collapsed. dpkg records exactly one spelling of a
# path and it is not always the one you have in hand: /usr/bin/fusermount3 is
# on disk, but dpkg knows it as /bin/fusermount3. Asking with the wrong form
# returns "no path found" for a perfectly packaged file — which reported a
# stock setuid binary as an unowned root backdoor.
_USRMERGE = (("/bin/", "/usr/bin/"), ("/sbin/", "/usr/sbin/"),
             ("/lib/", "/usr/lib/"), ("/lib64/", "/usr/lib64/"))


def dpkg_candidates(path: str) -> list:
    """Every spelling of this path that dpkg might have recorded."""
    out = [path]
    try:
        real = os.path.realpath(path)
        if real != path:
            out.append(real)
    except OSError:
        pass
    for cand in list(out):
        for bare, under_usr in _USRMERGE:
            if cand.startswith(bare):
                out.append(under_usr + cand[len(bare):])
            elif cand.startswith(under_usr):
                out.append(bare + cand[len(under_usr):])
    return list(dict.fromkeys(out))


def dpkg_owns(path: str) -> bool:
    """True when a package owns this file, under any of its path spellings.

    A False here is used to escalate findings, so a wrong False is expensive:
    it turns stock system files into critical alerts. When dpkg is missing or
    errors, this returns False and callers should treat that as "unknown",
    not as proof the file is unmanaged.
    """
    for cand in dpkg_candidates(path):
        try:
            r = subprocess.run(["dpkg", "-S", cand], capture_output=True,
                               text=True, timeout=8)
            if r.returncode == 0 and ":" in r.stdout:
                return True
        except (OSError, subprocess.SubprocessError):
            return False
    return False
