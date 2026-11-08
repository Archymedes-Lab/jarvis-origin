"""Evaluate stored indicators against what is actually on this machine.

intel.py answers "what is being used against machines like this one?".
This module answers the only question that matters: "is any of it here?"

Every check is a comparison against state jarvis-origin already collects — the process
baseline, the peer table, the filesystem — so a hunt costs almost nothing and
can run often. Indicators are compared as opaque data: never executed, never
interpolated into a shell, never used to build a command.

False positives are the failure mode that kills a tool like this, so matching
is exact and a second local check runs before anything is reported:

  * a path that exists is only reported if the package manager does not own it
  * a process name must match exactly, not as a substring
  * a hash match is reported at critical because a 256-bit collision is not a
    false positive

The ATT&CK side is different in kind. Technique IDs cannot be "found" on a
host, so instead they are compared against what jarvis-origin's own collectors check,
turning current intel into a gap list for the tool itself. coverage.py asks
whether jarvis-origin is running; gaps() asks whether it is looking at the right
things.
"""

import ipaddress
import os

from . import vet
from .detect import TRUSTED_PATHS
from .util import dpkg_owns, now

# Which jarvis-origin audit covers which ATT&CK technique. Parent technique ids cover
# their sub-techniques unless a sub-technique is listed on its own.
COVERAGE = {
    # Only what Jarvis Origin itself checks. Claiming a technique no shipped
    # collector looks at would turn a gap into false reassurance.
    "T1027":     "detect — obfuscated/encoded command lines",
    "T1036":     "detect — masquerading (name vs executable)",
    "T1059":     "detect — command and scripting interpreter",
    "T1105":     "detect / hunt — ingress tool transfer, known-bad file hashes",
    "T1218":     "detect — signed binary proxy execution",
    "T1071":     "monitor / hunt — application layer egress to known C2",
}

# Techniques worth naming explicitly as uncovered when intel raises them, with
# the reason they are hard rather than merely missing.
KNOWN_BLIND = {
    "T1555": "credential stores beyond browsers — Windows Credential Manager "
             "and OS keyrings are not read",
    "T1195": "supply chain compromise — installed packages are not verified",
    "T1554": "compromised host binary — no integrity baseline for system files",
    "T1505": "server software component — no web/server module auditing",
    "T1567": "exfiltration to web service — egress is seen but not classified",
    "T1611": "container escape — no container runtime auditing",
    "T1610": "malicious container deployment — no container runtime auditing",
    "T1003": "credential dumping — needs process-access and registry/file "
             "auditing, which Jarvis Origin does not ship",
}


def _finding(category, severity, title, detail, where="", host="wsl"):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


def _win_to_wsl(path):
    """C:\\Users\\x -> /mnt/c/Users/x so Windows paths are checkable from here."""
    p = path.replace("\\", "/")
    if len(p) > 2 and p[1] == ":" and p[2] == "/":
        return "/mnt/" + p[0].lower() + p[2:]
    return None


_dpkg_owns = dpkg_owns


def _sha256(path, cap=256 * 1024 * 1024):
    import hashlib
    try:
        if os.path.getsize(path) > cap:
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, ValueError):
        return ""


def _hash_cached(store, path):
    """Hash a file, reusing the stored digest while size and mtime are unchanged."""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    row = store.db.execute(
        "SELECT sha256,size,mtime FROM file_hashes WHERE path=?", (path,)
    ).fetchone()
    if row and row["size"] == st.st_size and row["mtime"] == int(st.st_mtime):
        return row["sha256"]
    digest = _sha256(path)
    if digest:
        store.db.execute(
            """INSERT INTO file_hashes(path,sha256,size,mtime,hashed_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(path) DO UPDATE SET
                   sha256=excluded.sha256, size=excluded.size,
                   mtime=excluded.mtime, hashed_at=excluded.hashed_at""",
            (path, digest, st.st_size, int(st.st_mtime), now()))
    return digest


def _active(store, kind):
    return store.db.execute(
        "SELECT norm, value, source_url, context, doc_count FROM indicators "
        "WHERE kind=? AND status='active'", (kind,)).fetchall()


# ── the checks ────────────────────────────────────────────────────────────

def check_peers(store):
    """Do any recorded network peers match attacker infrastructure?

    Written as indexed joins rather than by loading indicators into Python.
    At a few thousand records the difference is invisible; at half a million it
    is the difference between a hunt that runs every half hour and one that
    reads a hundred megabytes into memory to answer a question SQLite can
    answer from an index.
    """
    out = []

    # Addresses: one join, served entirely from the (kind, norm) unique index.
    for r in store.db.execute(
            """SELECT p.remote_ip ip, p.remote_port port, p.host host,
                      pr.name pname, i.context ctx, i.source_url src,
                      i.malware fam, i.source feed, i.confidence confidence
                 FROM peers p
                 JOIN indicators i
                   ON i.kind='ipv4' AND i.norm = p.remote_ip
                      AND i.status='active'
                LEFT JOIN procs pr ON pr.fp = p.fp
                WHERE p.scope='public'"""):
        # Re-vet at match time as well as ingestion time. The corpus is
        # persistent, so a newly learned shared-infrastructure exclusion must
        # take effect immediately rather than waiting for a manual re-vet.
        if not vet.vet_ipv4(r["ip"])[0]:
            continue
        label = r["fam"] or r["ctx"] or "listed in threat intelligence"
        severity = "critical" if r["confidence"] == "high" else "medium"
        qualifier = "known attacker" if severity == "critical" else "threat-intelligence"
        out.append(_finding(
            "c2 match", severity,
            f"contacted a {qualifier} IP: {r['ip']}",
            f"{r['pname'] or 'unknown process'} → {r['ip']}:{r['port']} — "
            f"{label} (via {r['feed']})", r["src"], r["host"]))

    # Domains: exact reverse-DNS match, then parent domains. Only the distinct
    # rdns values are walked, and each parent is a single index probe, so this
    # stays a few thousand lookups no matter how large the indicator set is.
    rdns_rows = store.db.execute(
        "SELECT DISTINCT rdns FROM peers WHERE scope='public' AND rdns != ''"
    ).fetchall()
    matched = {}
    for row in rdns_rows:
        host = (row["rdns"] or "").lower().rstrip(".")
        parts = host.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if not vet.vet_domain(parent)[0]:
                continue
            hit = store.db.execute(
                "SELECT context, source_url, malware, source, confidence FROM indicators "
                "WHERE kind='domain' AND norm=? AND status='active'",
                (parent,)).fetchone()
            if hit:
                matched[host] = (parent, hit)
                break
    for host, (parent, hit) in matched.items():
        severity = "critical" if hit["confidence"] == "high" else "medium"
        qualifier = "known attacker" if severity == "critical" else "threat-intelligence"
        for p in store.db.execute(
                """SELECT p.remote_ip ip, p.remote_port port, p.host host,
                          pr.name pname FROM peers p
                     LEFT JOIN procs pr ON pr.fp = p.fp
                    WHERE p.scope='public' AND lower(p.rdns) LIKE ?""",
                (host + "%",)):
            label = hit["malware"] or hit["context"] or "listed in threat intelligence"
            out.append(_finding(
                "c2 match", severity,
                f"contacted a {qualifier} domain: {parent}",
                f"{p['pname'] or 'unknown process'} → {host} "
                f"({p['ip']}:{p['port']}) — {label} (via {hit['source']})",
                hit["source_url"], p["host"]))

    # Ranges cannot be indexed by value, so they are bucketed by first octet.
    # A peer then only has to be tested against the handful of networks that
    # could possibly contain it instead of all of them.
    buckets = {}
    for r in _active(store, "cidr"):
        try:
            net = ipaddress.ip_network(r["norm"])
        except ValueError:
            continue
        if net.version != 4:
            continue
        first = int(str(net.network_address).split(".")[0])
        buckets.setdefault(first, []).append((net, r))
    if buckets:
        for p in store.db.execute(
                """SELECT p.remote_ip ip, p.remote_port port, p.host host,
                          pr.name pname FROM peers p
                     LEFT JOIN procs pr ON pr.fp = p.fp
                    WHERE p.scope='public'"""):
            try:
                addr = ipaddress.ip_address(p["ip"])
            except ValueError:
                continue
            if addr.version != 4:
                continue
            for net, hit in buckets.get(int(str(addr).split(".")[0]), ()):
                if addr in net:
                    out.append(_finding(
                        "c2 match", "high",
                        f"contacted a host in a flagged network: {net}",
                        f"{p['pname'] or 'unknown process'} → "
                        f"{p['ip']}:{p['port']} — "
                        f"{hit['context'] or 'listed range'}",
                        hit["source_url"], p["host"]))
                    break
    return out


def check_paths(store):
    """Does any attacker-dropped path actually exist here?"""
    out = []
    for r in _active(store, "path"):
        raw = r["norm"]
        candidates = []
        if raw.startswith("/"):
            candidates.append(("wsl", raw))
        win = _win_to_wsl(raw)
        if win:
            candidates.append(("win", win))
        for host, path in candidates:
            try:
                if not os.path.lexists(path):
                    continue
                if os.path.isdir(path) or not (
                        os.path.isfile(path) or os.path.islink(path)):
                    continue        # sockets, fifos and devices are not payloads
            except (OSError, ValueError):
                continue
            if host == "wsl" and _dpkg_owns(path):
                continue        # a package owns it: present by design
            out.append(_finding(
                "dropped file", "high",
                f"a file named in threat intelligence exists here: {raw}",
                (r["context"] or "listed as an attacker-created path")
                + " — verify before deleting; the name may simply collide",
                r["source_url"], host))
    return out


def check_processes(store):
    """Has anything with an attacker-associated name ever run here?

    This is the weakest indicator class by a wide margin. A writeup naming a
    binary the attacker abused puts that name in the feed, and if the name
    belongs to real software the match is meaningless. The first live run
    produced 1500 findings for `wslhost.exe` on exactly this mistake.

    So a name match alone is not evidence. It is only reported when the binary
    is somewhere a legitimate copy would not be — the same reasoning the path
    check applies with dpkg, and the reason severity here is capped below the
    hash and infrastructure checks.
    """
    out = []
    names = {r["norm"]: r for r in _active(store, "process")}
    if not names:
        return out
    for row in store.db.execute(
            "SELECT name, exe, host, cmdline, last_seen FROM procs"):
        name = (row["name"] or "").lower()
        stem = name.rsplit(".", 1)[0] if "." in name else name
        hit = names.get(name) or names.get(stem)
        if not hit:
            continue
        exe = (row["exe"] or "").lower().replace("\\", "/")
        if exe.startswith(TRUSTED_PATHS):
            continue        # the real binary, in the place it belongs
        sev = "high" if exe else "medium"
        out.append(_finding(
            "named process", sev,
            f"a process matching a known malware name ran: {row['name']}",
            (hit["context"] or "name listed in threat intelligence")
            + f" — {(row['cmdline'] or '')[:110]}",
            hit["source_url"] or (row["exe"] or ""), row["host"]))
    return out


def check_hashes(store, limit=1500):
    """Hash the executables jarvis-origin has seen and compare against sample digests."""
    out = []
    have = store.db.execute(
        "SELECT 1 FROM indicators WHERE kind='sha256' AND status='active' "
        "LIMIT 1").fetchone()
    if not have:
        return out
    seen = set()
    rows = store.db.execute(
        "SELECT DISTINCT exe, host FROM procs WHERE exe LIKE '/%' "
        "ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
    for row in rows:
        path = row["exe"]
        if not path or path in seen:
            continue
        seen.add(path)
        digest = _hash_cached(store, path)
        if not digest:
            continue
        hit = store.db.execute(
            "SELECT context, source_url, malware, source FROM indicators "
            "WHERE kind='sha256' AND norm=? AND status='active'",
            (digest,)).fetchone()
        if hit:
            label = hit["malware"] or hit["context"] or "listed in threat intelligence"
            out.append(_finding(
                "sample match", "critical",
                f"a file here matches a known malware sample: {os.path.basename(path)}",
                f"SHA-256 {digest} — {label} (via {hit['source']})",
                path, row["host"]))
    store.commit()
    return out


# Where a payload named only by filename has to live in order to work. A PAM
# backdoor must be on the PAM module path; a preloaded object must be findable
# by the loader; a rootkit module must be under the module tree. Hunting only
# these keeps the check bounded and cheap — a whole-filesystem sweep for
# attacker filenames would be both slow and a false-positive machine.
FILENAME_DIRS = (
    "/lib/security", "/usr/lib/security", "/lib/x86_64-linux-gnu/security",
    "/usr/lib/x86_64-linux-gnu/security", "/usr/local/lib", "/usr/local/bin",
    "/etc", "/etc/systemd/system", "/lib/systemd/system", "/etc/cron.d",
    "/tmp", "/var/tmp", "/dev/shm", "/run", "/opt", "/usr/lib/modules",
)


def check_filenames(store, max_entries=40000):
    """Look for attacker-named files in the places such payloads must live."""
    out = []
    names = {r["norm"]: r for r in _active(store, "filename")}
    if not names:
        return out

    scanned = 0
    for root in FILENAME_DIRS:
        if not os.path.isdir(root):
            continue
        # /lib/modules is deep and huge; everything else is one level.
        depth_cap = 3 if "modules" in root else 1
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.rstrip("/").count("/") - base_depth >= depth_cap:
                dirnames[:] = []
            for fn in filenames:
                scanned += 1
                if scanned > max_entries:
                    return out
                hit = names.get(fn.lower())
                if not hit:
                    continue
                full = os.path.join(dirpath, fn)
                if _dpkg_owns(full):
                    continue
                out.append(_finding(
                    "dropped file", "high",
                    f"a file named in threat intelligence is present: {fn}",
                    (hit["context"] or "filename listed in threat intelligence")
                    + " — no package owns this file",
                    full, "wsl"))
    return out


def _aggregate(findings):
    """Collapse repeats of one indicator into a single counted finding.

    The same C2 address seen by nineteen browser tabs is one fact, not
    nineteen. Reporting it nineteen times buries whatever else the hunt found.
    """
    groups = {}
    for f in findings:
        key = (f["category"], f["title"], f["host"])
        if key in groups:
            groups[key]["_n"] += 1
        else:
            groups[key] = {**f, "_n": 1}
    out = []
    for g in groups.values():
        n = g.pop("_n")
        if n > 1:
            g["detail"] = f"{g['detail']}  [seen {n}×]"
        out.append(g)
    return out


def hunt(store, hosts=("wsl", "win")):
    """Run every indicator check and record the hits."""
    findings = []
    for fn in (check_peers, check_paths, check_filenames, check_processes,
               check_hashes):
        try:
            findings += fn(store)
        except Exception as exc:      # one broken check must not hide the rest
            findings.append(_finding(
                "hunt", "medium", f"{fn.__name__} failed", str(exc)))
    findings = [f for f in findings if f["host"] in hosts or f["host"] == "wsl"]
    findings = _aggregate(findings)

    ts = now()
    for f in findings:
        if f["category"] == "hunt":
            continue
        store.db.execute(
            """INSERT INTO hunt_hits(ts,kind,value,host,severity,evidence,source_url)
               VALUES(?,?,?,?,?,?,?)""",
            (ts, f["category"], f["title"][:300], f["host"], f["severity"],
             f["detail"][:600], f["where"][:400]))
    store.set_meta("hunt_last_run", ts)
    store.commit()
    return findings


# Tactics whose techniques are defined by runtime behaviour rather than by
# anything left on disk. A monitor that samples state on an interval cannot
# see them at all — that is the sampling blind spot coverage.py already
# reports, not a missing collector. Listing them as work to do would bury the
# gaps that could actually be closed.
BEHAVIOURAL_TACTICS = {
    "discovery", "collection", "execution", "impact", "exfiltration",
    "lateral-movement", "privilege-escalation", "reconnaissance",
    "resource-development", "initial-access",
}

_INTERCEPT = None


def _intercept_active():
    """(active, name) — is a syscall-interception layer credited on this box?

    Kept as a seam: a collector that reads auditd or Sysmon for Linux could
    report itself here and move behavioural techniques from "not observable"
    to "covered". None ships, so the answer is always no.
    """
    # Jarvis Origin ships no interception collector, so it never credits one.
    # Behavioural techniques are reported as not observable, which is true.
    global _INTERCEPT
    if _INTERCEPT is None:
        _INTERCEPT = (False, "")
    return _INTERCEPT


def gaps(store, min_docs=1):
    """Techniques current intel is talking about, against what jarvis-origin checks.

    Three outcomes, and the distinction is the whole point of the report:

      * covered      — a collector already looks for this
      * closeable    — leaves host artefacts, nothing looks for them yet
      * behavioural  — needs syscall interception; no collector here can help

    Only the middle group is a work queue.
    """
    rows = store.db.execute(
        "SELECT norm, doc_count, context, source_url FROM indicators "
        "WHERE kind='attack' AND status='active' AND doc_count>=? "
        "ORDER BY doc_count DESC", (min_docs,)).fetchall()

    cat = {r["tid"]: (r["name"], r["tactics"]) for r in
           store.db.execute("SELECT tid,name,tactics FROM attack_techniques")}

    covered, closeable, behavioural = [], [], []
    for r in rows:
        tid, n = r["norm"], r["doc_count"]
        parent = tid.split(".")[0]
        where = COVERAGE.get(tid) or COVERAGE.get(parent)
        if where:
            covered.append((tid, n, where))
            continue
        name, tactics = cat.get(tid) or cat.get(parent) or ("", "")
        why = (KNOWN_BLIND.get(tid) or KNOWN_BLIND.get(parent)
               or "no collector checks this")
        if not name:
            behavioural.append((tid, n, "deprecated or unrecognised "
                                        "technique id", ""))
            continue
        tset = {t for t in (tactics or "").split(",") if t}
        if tset and tset <= BEHAVIOURAL_TACTICS:
            intercept_on, intercept_name = _intercept_active()
            if intercept_on:
                covered.append((tid, n,
                                f"{intercept_name} — syscall interception active"))
            else:
                behavioural.append((tid, n, "runtime behaviour — needs syscall "
                                            "interception (auditd/Sysmon)", name))
        else:
            closeable.append((tid, n, why, name))

    out = []
    for tid, n, why, name in closeable:
        # Weight by how many separate writeups raised it: a technique three
        # independent teams wrote about this year is a better use of an
        # afternoon than one mentioned once.
        sev = "high" if n >= 5 else "medium" if n >= 2 else "low"
        out.append(_finding(
            "coverage gap", sev, f"{tid} {name}".strip(),
            f"{why} — mentioned in {n} intelligence document{'s' if n > 1 else ''}; "
            "this is a detection coverage gap, not observed activity on this host"))
    for tid, n, why, name in behavioural:
        out.append(_finding(
            "not observable", "low", f"{tid} {name}".strip(),
            f"{why} — mentioned in {n} intelligence document{'s' if n > 1 else ''}; "
            "this is a visibility limitation, not observed activity on this host"))
    return out, covered, closeable


def sort_findings(findings):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    cat = {"c2 match": 0, "sample match": 1, "dropped file": 2,
           "named process": 3, "coverage gap": 4, "hunt": 5}
    return sorted(findings, key=lambda f: (order.get(f["severity"], 9),
                                           cat.get(f["category"], 9), f["title"]))
