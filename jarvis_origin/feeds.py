"""Bulk indicator feeds: volume that search cannot buy.

intel.py reads security writeups, which is the only way to learn *tradecraft* —
the path a rootkit drops, the unit file it installs, the technique it uses.
What writeups cannot give is coverage: a single article names a handful of
hashes, and paying a search API per document to accumulate tens of thousands of
them costs real money for data that is published free.

So the two halves are split by what each is actually good at:

    intel.py   narrative  ->  paths, filenames, techniques, persistence
    feeds.py   bulk       ->  hashes, domains, addresses, ranges, CVEs

Every feed here is public, unauthenticated, and refreshed by its publisher on
its own schedule — ThreatFox and URLhaus update continuously, CISA KEV when a
vulnerability starts being exploited, MITRE ATT&CK on release. Together they
put the knowledge base well past fifty thousand live records at no cost.

Feed data is more trustworthy than an extraction from prose: these are curated,
attributed, and confirmed-malicious. It is still not trusted. Everything goes
through the same vet.py gate, because a feed can carry a defanged placeholder
or a private address just as easily, and because the invariant that intel may
only ever ADD suspicion has to hold for every source without exception.
"""

import csv
import gzip
import io
import zipfile
import json
import re
import time
import urllib.error
import urllib.request

from . import vet
from .util import now

UA = "jarvis-origin-feeds/1.0 (+local host monitoring)"

# name -> (url, parser, interval_seconds, description)
FEEDS = {}


def feed(name, url, interval, desc, max_bytes=64 * 1024 * 1024):
    def wrap(fn):
        FEEDS[name] = {"url": url, "parse": fn, "interval": interval,
                       "desc": desc, "max_bytes": max_bytes}
        return fn
    return wrap


def fetch(url, max_bytes, timeout=180, max_inflated=512 * 1024 * 1024):
    """Download and transparently decompress. The full abuse.ch dumps ship as
    zip archives that expand roughly sevenfold, so the inflated size is capped
    separately from the download — otherwise a feed changing shape upstream
    could exhaust memory on a machine this is supposed to be protecting."""
    req = urllib.request.Request(url, headers={
        "User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(f"feed exceeds {max_bytes} bytes")
        if resp.headers.get("Content-Encoding") == "gzip" or raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            if not names:
                raise ValueError("empty zip archive")
            info = zf.getinfo(names[0])
            if info.file_size > max_inflated:
                raise ValueError(
                    f"archive inflates to {info.file_size} bytes, over cap")
            raw = zf.read(names[0])
    return raw


def _host(value):
    """Hostname out of a URL or host:port, or "" if there isn't one."""
    v = (value or "").strip().strip('"')
    v = re.sub(r"^[a-z0-9+.-]+://", "", v, flags=re.I)
    v = v.split("/")[0].split("?")[0]
    if v.count(":") == 1:
        v = v.split(":")[0]
    return v.strip("[]").lower()


def _rows(raw):
    """Iterate a commented CSV the way abuse.ch publishes them."""
    text = raw.decode("utf-8", "replace")
    body = "\n".join(l for l in text.splitlines()
                     if l.strip() and not l.lstrip().startswith("#"))
    return csv.reader(io.StringIO(body), skipinitialspace=True)


# ── the feeds ─────────────────────────────────────────────────────────────

@feed("threatfox", "https://threatfox.abuse.ch/export/csv/recent/", 3600,
      "abuse.ch ThreatFox — current C2 infrastructure, updated continuously")
def _threatfox(raw):
    out = []
    for row in _rows(raw):
        if len(row) < 9:
            continue
        value, ioc_type, family = row[2], row[3], (row[7] or "").strip()
        try:
            conf = int(row[9]) if len(row) > 9 and row[9].strip().isdigit() else 50
        except (ValueError, IndexError):
            conf = 50
        if conf < 50:
            continue                    # low-confidence entries are not worth the noise
        if ioc_type in ("url", "domain"):
            out.append(("domain", _host(value), family))
        elif ioc_type in ("ip:port", "ip"):
            out.append(("ipv4", _host(value), family))
        elif ioc_type == "sha256_hash":
            out.append(("sha256", value.strip(), family))
    return out


@feed("malwarebazaar", "https://bazaar.abuse.ch/export/txt/sha256/recent/", 3600,
      "abuse.ch MalwareBazaar — SHA-256 of recently submitted samples")
def _bazaar(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip().strip('"')
        if line and not line.startswith("#"):
            out.append(("sha256", line, ""))
    return out


@feed("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", 3600,
      "abuse.ch Feodo Tracker — botnet C2 servers")
def _feodo(raw):
    out = []
    for item in json.loads(raw.decode("utf-8", "replace")):
        if isinstance(item, dict) and item.get("ip_address"):
            out.append(("ipv4", item["ip_address"], item.get("malware") or ""))
    return out


@feed("urlhaus", "https://urlhaus.abuse.ch/downloads/csv_recent/", 3600,
      "abuse.ch URLhaus — hosts serving malware payloads")
def _urlhaus(raw):
    out = []
    for row in _rows(raw):
        if len(row) < 3:
            continue
        host = _host(row[2])
        if not host:
            continue
        tag = row[5] if len(row) > 5 else ""
        kind = "ipv4" if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else "domain"
        out.append((kind, host, tag))
    return out


@feed("openphish", "https://openphish.com/feed.txt", 10800,
      "OpenPhish — live phishing hosts")
def _openphish(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        host = _host(line)
        if host and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            out.append(("domain", host, "phishing"))
    return out


@feed("et-compromised",
      "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 10800,
      "Emerging Threats — currently compromised hosts")
def _et(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(("ipv4", line, "compromised host"))
    return out


@feed("spamhaus-drop", "https://www.spamhaus.org/drop/drop.txt", 86400,
      "Spamhaus DROP — networks under criminal control")
def _drop(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        out.append(("cidr", line.split(";")[0].strip(), "hijacked network"))
    return out


@feed("cisa-kev",
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      86400, "CISA KEV — vulnerabilities known to be exploited in the wild")
def _kev(raw):
    data = json.loads(raw.decode("utf-8", "replace"))
    out = []
    for v in data.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip()
        if cve:
            label = f"{v.get('vendorProject','')} {v.get('product','')}".strip()
            out.append(("cve", cve, label[:120]))
    return out




# ── full historical dumps ─────────────────────────────────────────────────
# The "recent" endpoints above keep the picture current; these carry the depth.
# They are large, so they refresh daily rather than hourly.

@feed("bazaar-full", "https://bazaar.abuse.ch/export/txt/sha256/full/", 86400,
      "abuse.ch MalwareBazaar — full sample corpus",
      max_bytes=48 * 1024 * 1024)
def _bazaar_full(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip().strip('"')
        if line and not line.startswith("#"):
            out.append(("sha256", line, ""))
    return out


@feed("threatfox-full", "https://threatfox.abuse.ch/export/csv/full/", 86400,
      "abuse.ch ThreatFox — full C2 corpus", max_bytes=32 * 1024 * 1024)
def _threatfox_full(raw):
    return _threatfox(raw)


@feed("urlhaus-full", "https://urlhaus.abuse.ch/downloads/csv/", 86400,
      "abuse.ch URLhaus — full payload-host corpus",
      max_bytes=32 * 1024 * 1024)
def _urlhaus_full(raw):
    return _urlhaus(raw)


@feed("ipsum", "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
      86400, "IPsum — addresses appearing on multiple public blocklists")
def _ipsum(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            continue
        # The second column is how many independent blocklists carry it. One
        # list alone is too often a scanner or a stale entry; two is a claim
        # with corroboration.
        if int(parts[1]) < 2:
            continue
        out.append(("ipv4", parts[0], f"on {parts[1]} blocklists"))
    return out


@feed("blocklist-de", "https://lists.blocklist.de/lists/all.txt", 10800,
      "blocklist.de — hosts observed attacking public services")
def _blocklist_de(raw):
    return [("ipv4", l.strip(), "attacking host")
            for l in raw.decode("utf-8", "replace").splitlines()
            if l.strip() and not l.startswith("#")]


@feed("cins", "https://cinsscore.com/list/ci-badguys.txt", 10800,
      "CINS Army — poor-reputation addresses")
def _cins(raw):
    return [("ipv4", l.strip(), "poor reputation")
            for l in raw.decode("utf-8", "replace").splitlines()
            if l.strip() and not l.startswith("#")]


@feed("binarydefense", "https://www.binarydefense.com/banlist.txt", 10800,
      "Binary Defense — artillery threat intelligence banlist")
def _bindef(raw):
    return [("ipv4", l.strip(), "banlist")
            for l in raw.decode("utf-8", "replace").splitlines()
            if l.strip() and not l.startswith("#")]


def _attack(raw, store):
    """MITRE ATT&CK is a catalogue, not a list of indicators — it gets a table."""
    data = json.loads(raw.decode("utf-8", "replace"))
    rows, ts = [], now()
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        tid = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id", "")
                break
        if not tid:
            continue
        tactics = ",".join(p.get("phase_name", "")
                           for p in obj.get("kill_chain_phases", []))
        rows.append((tid, obj.get("name", "")[:200], tactics,
                     ",".join(obj.get("x_mitre_platforms", []) or [])[:200], ts))
    store.db.executemany(
        """INSERT INTO attack_techniques(tid,name,tactics,platforms,updated)
           VALUES(?,?,?,?,?)
           ON CONFLICT(tid) DO UPDATE SET name=excluded.name,
               tactics=excluded.tactics, platforms=excluded.platforms,
               updated=excluded.updated""", rows)
    store.commit()
    return len(rows)


ATTACK_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
              "enterprise-attack/enterprise-attack.json")


# ── ingestion ─────────────────────────────────────────────────────────────

def ingest(store, name, spec, max_rows=250000):
    """Fetch one feed, vet every row, and upsert the survivors in one batch."""
    started = time.time()
    try:
        raw = fetch(spec["url"], spec["max_bytes"])
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            ValueError, TimeoutError) as exc:
        store.db.execute(
            """INSERT INTO feed_runs(name,last_run,rows,kept,bytes,error)
               VALUES(?,?,0,0,0,?)
               ON CONFLICT(name) DO UPDATE SET last_run=excluded.last_run,
                   error=excluded.error""", (name, now(), str(exc)[:200]))
        store.commit()
        return {"name": name, "error": str(exc)[:200], "rows": 0, "kept": 0}

    try:
        parsed = spec["parse"](raw)
    except Exception as exc:
        return {"name": name, "error": f"parse failed: {exc}", "rows": 0, "kept": 0}

    ts = now()
    batch, seen, rejected = [], set(), 0
    for kind, value, family in parsed[:max_rows]:
        norm, _why = vet.vet(kind, value)
        if not norm:
            rejected += 1
            continue
        key = (kind, norm)
        if key in seen:
            continue
        seen.add(key)
        batch.append((kind, str(value)[:512], norm, "high", name,
                      (family or "")[:120], (family or "")[:200],
                      spec["url"], ts, ts, name))

    sql = """INSERT INTO indicators(kind,value,norm,confidence,topic,context,
                                    malware,source_url,first_seen,last_seen,source)
             VALUES(?,?,?,?,?,?,?,?,?,?,?)
             ON CONFLICT(kind,norm) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 status='active',
                 doc_count=indicators.doc_count+1"""
    for i in range(0, len(batch), 20000):
        store.db.executemany(sql, batch[i:i + 20000])
        store.commit()
    store.db.execute(
        """INSERT INTO feed_runs(name,last_run,rows,kept,bytes,error)
           VALUES(?,?,?,?,?,'')
           ON CONFLICT(name) DO UPDATE SET last_run=excluded.last_run,
               rows=excluded.rows, kept=excluded.kept, bytes=excluded.bytes,
               error=''""",
        (name, ts, len(parsed), len(batch), len(raw)))
    store.commit()
    return {"name": name, "rows": len(parsed), "kept": len(batch),
            "rejected": rejected, "bytes": len(raw),
            "secs": round(time.time() - started, 1)}


def refresh(store, names=None, force=False, on_progress=None):
    """Run every feed that is due (or all of them, with force)."""
    results = []
    targets = names or list(FEEDS)
    for name in targets:
        spec = FEEDS.get(name)
        if not spec:
            continue
        if not force:
            row = store.db.execute(
                "SELECT last_run FROM feed_runs WHERE name=?", (name,)).fetchone()
            if row and now() - row["last_run"] < spec["interval"]:
                continue
        if on_progress:
            on_progress(name, spec["desc"])
        results.append(ingest(store, name, spec))
    return results


def refresh_attack(store, force=False):
    """Refresh the ATT&CK catalogue. Large and slow-moving, so monthly."""
    row = store.db.execute(
        "SELECT last_run FROM feed_runs WHERE name='attack'").fetchone()
    if row and not force and now() - row["last_run"] < 30 * 86400:
        return {"name": "attack", "skipped": True}
    try:
        raw = fetch(ATTACK_URL, 96 * 1024 * 1024, timeout=240)
        n = _attack(raw, store)
    except Exception as exc:
        return {"name": "attack", "error": str(exc)[:200]}
    store.db.execute(
        """INSERT INTO feed_runs(name,last_run,rows,kept,bytes,error)
           VALUES('attack',?,?,?,?,'')
           ON CONFLICT(name) DO UPDATE SET last_run=excluded.last_run,
               rows=excluded.rows, kept=excluded.kept, bytes=excluded.bytes,
               error=''""", (now(), n, n, len(raw)))
    store.commit()
    return {"name": "attack", "kept": n, "bytes": len(raw)}


def prune(store, days=90):
    """Retire feed indicators the publisher has stopped listing.

    C2 infrastructure is rented and recycled; an address that dropped off every
    feed three months ago is far more likely to be someone else's server now
    than to still be a threat. Writeup-derived indicators are never pruned —
    a malware sample's hash is true forever.
    """
    cutoff = now() - days * 86400
    cur = store.db.execute(
        "UPDATE indicators SET status='retired' "
        "WHERE source!='exa' AND status='active' AND last_seen < ?", (cutoff,))
    store.commit()
    return cur.rowcount


def status(store):
    rows = store.db.execute(
        "SELECT * FROM feed_runs ORDER BY name").fetchall()
    return [dict(r) for r in rows]
