"""SQLite-backed baseline of known-good processes and network peers."""

import os
import sqlite3

from .util import now

DEFAULT_DB = os.path.expanduser("~/.jarvis-origin/jarvis-origin.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS procs (
    fp          TEXT PRIMARY KEY,
    host        TEXT NOT NULL,
    name        TEXT,
    exe         TEXT,
    script      TEXT,
    cmdline     TEXT,
    user        TEXT,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    seen_count  INTEGER NOT NULL DEFAULT 1,
    approved    INTEGER NOT NULL DEFAULT 0,
    note        TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS peers (
    key         TEXT PRIMARY KEY,
    host        TEXT NOT NULL,
    fp          TEXT NOT NULL,
    remote_ip   TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    scope       TEXT NOT NULL,
    rdns        TEXT DEFAULT '',
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    seen_count  INTEGER NOT NULL DEFAULT 1,
    approved    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    host        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    kind        TEXT NOT NULL,
    fp          TEXT,
    pid         INTEGER,
    name        TEXT,
    exe         TEXT,
    cmdline     TEXT,
    user        TEXT,
    reasons     TEXT,
    remotes     TEXT,
    acked       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_peers_fp ON peers(fp);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);

-- Latest result per audit, so the dashboard always has something to draw even
-- while a slow collector is mid-run.
CREATE TABLE IF NOT EXISTS snapshots (
    kind       TEXT PRIMARY KEY,
    ts         INTEGER NOT NULL,
    duration   REAL NOT NULL DEFAULT 0,
    error      TEXT DEFAULT '',
    payload    TEXT NOT NULL
);

-- Severity counts over time, for the trend strip.
CREATE TABLE IF NOT EXISTS history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    critical   INTEGER NOT NULL DEFAULT 0,
    high       INTEGER NOT NULL DEFAULT 0,
    medium     INTEGER NOT NULL DEFAULT 0,
    low        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_history_ts ON history(ts DESC);

-- ── Threat intelligence ────────────────────────────────────────────────
-- Fetched security writeups. Text is kept only long enough to extract from;
-- what persists is the extraction, not the article.
CREATE TABLE IF NOT EXISTS intel_docs (
    url        TEXT PRIMARY KEY,
    title      TEXT DEFAULT '',
    published  TEXT DEFAULT '',
    topic      TEXT DEFAULT '',
    query      TEXT DEFAULT '',
    fetched_at INTEGER NOT NULL,
    text_len   INTEGER NOT NULL DEFAULT 0,
    n_indicators INTEGER NOT NULL DEFAULT 0
);

-- One observable extracted from a writeup. Never authoritative on its own:
-- an indicator can only ever raise suspicion, never clear it.
CREATE TABLE IF NOT EXISTS indicators (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    norm       TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    topic      TEXT DEFAULT '',
    context    TEXT DEFAULT '',
    source_url TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    doc_count  INTEGER NOT NULL DEFAULT 1,
    status     TEXT NOT NULL DEFAULT 'active',
    source     TEXT NOT NULL DEFAULT 'exa',
    malware    TEXT DEFAULT '',
    UNIQUE(kind, norm)
);

CREATE INDEX IF NOT EXISTS idx_ind_kind ON indicators(kind, status);

-- The ATT&CK catalogue, so a technique id can be shown with its real name and
-- gap analysis can talk about behaviour instead of numbers.
CREATE TABLE IF NOT EXISTS attack_techniques (
    tid       TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    tactics   TEXT DEFAULT '',
    platforms TEXT DEFAULT '',
    updated   INTEGER NOT NULL
);


-- Synthetic input. Only injected events are stored, never real keystrokes and
-- never what was typed — see jarvis_origin/win/inputhook.ps1 for why.
CREATE TABLE IF NOT EXISTS input_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    kind     TEXT NOT NULL,
    lower_il INTEGER NOT NULL DEFAULT 0,
    class    TEXT DEFAULT '',
    fg       TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_input_ts ON input_events(ts DESC);

-- Heartbeats, so a dead hook and a quiet keyboard are distinguishable.
CREATE TABLE IF NOT EXISTS input_beats (
    ts             INTEGER PRIMARY KEY,
    real_keys      INTEGER NOT NULL DEFAULT 0,
    injected_keys  INTEGER NOT NULL DEFAULT 0,
    real_clicks    INTEGER NOT NULL DEFAULT 0,
    injected_clicks INTEGER NOT NULL DEFAULT 0,
    real_moves     INTEGER NOT NULL DEFAULT 0,
    injected_moves INTEGER NOT NULL DEFAULT 0,
    injected_keyups     INTEGER NOT NULL DEFAULT 0,
    injected_move_bursts INTEGER NOT NULL DEFAULT 0,
    real_key_gaps  INTEGER NOT NULL DEFAULT 0,
    real_key_sub20 INTEGER NOT NULL DEFAULT 0,
    real_key_sub8  INTEGER NOT NULL DEFAULT 0,
    cad_run_max    INTEGER NOT NULL DEFAULT 0,
    lat_avg_ms     INTEGER NOT NULL DEFAULT 0,
    lat_max_ms     INTEGER NOT NULL DEFAULT 0,
    lat_over50     INTEGER NOT NULL DEFAULT 0,
    lat_samples    INTEGER NOT NULL DEFAULT 0
);

-- Privacy-safe typing history. One row describes a one-minute window; there
-- are no key codes, characters, window titles, clipboard values or command
-- lines. This is enough for cadence and volume anomaly detection without
-- turning the monitor into a keylogger. Raw windows are retained for 90 days.
CREATE TABLE IF NOT EXISTS input_typing_windows (
    ts             INTEGER PRIMARY KEY,
    real_keys      INTEGER NOT NULL DEFAULT 0,
    injected_keys  INTEGER NOT NULL DEFAULT 0,
    real_key_gaps  INTEGER NOT NULL DEFAULT 0,
    real_key_sub20 INTEGER NOT NULL DEFAULT 0,
    real_key_sub8  INTEGER NOT NULL DEFAULT 0,
    cad_run_max    INTEGER NOT NULL DEFAULT 0,
    equals_keys    INTEGER NOT NULL DEFAULT 0,
    slash_keys     INTEGER NOT NULL DEFAULT 0,
    period_keys    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_input_typing_ts
    ON input_typing_windows(ts DESC);


-- Per-feed bookkeeping: when it last ran, how big it was, whether it worked.
CREATE TABLE IF NOT EXISTS feed_runs (
    name      TEXT PRIMARY KEY,
    last_run  INTEGER NOT NULL,
    rows      INTEGER NOT NULL DEFAULT 0,
    kept      INTEGER NOT NULL DEFAULT 0,
    bytes     INTEGER NOT NULL DEFAULT 0,
    error     TEXT DEFAULT ''
);

-- A live match of an indicator against this machine.
CREATE TABLE IF NOT EXISTS hunt_hits (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    value     TEXT NOT NULL,
    host      TEXT NOT NULL,
    severity  TEXT NOT NULL,
    evidence  TEXT DEFAULT '',
    source_url TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_hits_ts ON hunt_hits(ts DESC);

-- Cache of file hashes so a hunt does not re-read every binary each pass.
CREATE TABLE IF NOT EXISTS file_hashes (
    path    TEXT PRIMARY KEY,
    sha256  TEXT NOT NULL,
    size    INTEGER NOT NULL,
    mtime   INTEGER NOT NULL,
    hashed_at INTEGER NOT NULL
);
"""


class Store:
    def __init__(self, path=DEFAULT_DB):
        self.path = os.path.expanduser(path)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        # The indicator tables grow into the hundreds of thousands of rows and
        # are written in large batches by the feeds while the dashboard reads
        # from another thread. WAL keeps readers from blocking on those writes;
        # the rest trades a little crash-durability for bulk-insert speed, which
        # is the right trade for a cache that can be rebuilt by re-fetching.
        for pragma in ("journal_mode=WAL", "synchronous=NORMAL",
                       "cache_size=-65536", "temp_store=MEMORY",
                       "mmap_size=268435456", "busy_timeout=10000"):
            try:
                self.db.execute(f"PRAGMA {pragma}")
            except sqlite3.Error:
                pass
        self.db.executescript(SCHEMA)
        self._migrate()
        self.db.commit()

    def _migrate(self):
        """Add columns introduced after a database was first created."""
        beat = {r[1] for r in self.db.execute("PRAGMA table_info(input_beats)")}
        for col in ("real_moves", "injected_moves", "lat_avg_ms", "lat_max_ms",
                    "lat_over50", "lat_samples", "injected_keyups",
                    "injected_move_bursts", "real_key_gaps", "real_key_sub20",
                    "real_key_sub8", "cad_run_max"):
            if col not in beat:
                self.db.execute(
                    f"ALTER TABLE input_beats ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
        typing = {r[1] for r in self.db.execute(
            "PRAGMA table_info(input_typing_windows)")}
        for col in ("equals_keys", "slash_keys", "period_keys"):
            if col not in typing:
                self.db.execute(
                    f"ALTER TABLE input_typing_windows ADD COLUMN {col} "
                    "INTEGER NOT NULL DEFAULT 0")
        have = {r[1] for r in self.db.execute("PRAGMA table_info(indicators)")}
        for col, decl in (("source", "TEXT NOT NULL DEFAULT 'exa'"),
                          ("malware", "TEXT DEFAULT ''")):
            if col not in have:
                self.db.execute(f"ALTER TABLE indicators ADD COLUMN {col} {decl}")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_ind_source "
                        "ON indicators(source, last_seen)")
        # hunt joins the peer table against indicators by address, so the
        # address needs its own index once peers number in the tens of
        # thousands. Without it every hunt is a full scan of peers.
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_peers_ip "
                        "ON peers(remote_ip)")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_peers_rdns "
                        "ON peers(rdns)")

    def close(self):
        self.db.close()

    # -- meta ---------------------------------------------------------------

    def get_meta(self, key, default=None):
        row = self.db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row["v"] if row else default

    def set_meta(self, key, value):
        self.db.execute(
            "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, str(value)),
        )
        self.db.commit()

    # -- processes ----------------------------------------------------------

    def known_fps(self):
        return {r["fp"] for r in self.db.execute("SELECT fp FROM procs")}

    def get_proc(self, fp):
        return self.db.execute("SELECT * FROM procs WHERE fp=?", (fp,)).fetchone()

    def upsert_proc(self, p, approved=0):
        """Record a sighting. An existing row keeps its approval and first_seen."""
        ts = now()
        self.db.execute(
            """INSERT INTO procs(fp,host,name,exe,script,cmdline,user,
                                 first_seen,last_seen,seen_count,approved)
               VALUES(?,?,?,?,?,?,?,?,?,1,?)
               ON CONFLICT(fp) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   seen_count=procs.seen_count+1""",
            (p["fp"], p["host"], p["name"], p["exe"], p.get("script", ""),
             p["cmdline"], p["user"], ts, ts, approved),
        )

    def set_approved(self, fp, approved=1, note=""):
        cur = self.db.execute(
            "UPDATE procs SET approved=?, note=? WHERE fp=?", (approved, note, fp)
        )
        self.db.commit()
        return cur.rowcount

    def list_procs(self, approved=None, limit=200):
        sql = "SELECT * FROM procs"
        args = []
        if approved is not None:
            sql += " WHERE approved=?"
            args.append(approved)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(limit)
        return self.db.execute(sql, args).fetchall()

    # -- network peers ------------------------------------------------------

    def upsert_peer(self, host, fp, ip, port, scope, rdns=""):
        """Returns True the first time this process talks to this peer."""
        key = f"{host}|{fp}|{ip}|{port}"
        ts = now()
        existing = self.db.execute("SELECT key FROM peers WHERE key=?", (key,)).fetchone()
        if existing:
            self.db.execute(
                "UPDATE peers SET last_seen=?, seen_count=seen_count+1 WHERE key=?", (ts, key)
            )
            return False
        self.db.execute(
            """INSERT INTO peers(key,host,fp,remote_ip,remote_port,scope,rdns,
                                 first_seen,last_seen)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (key, host, fp, ip, port, scope, rdns, ts, ts),
        )
        return True

    def list_peers(self, scope=None, limit=200):
        sql = ("SELECT p.*, pr.name AS pname, pr.exe AS pexe FROM peers p "
               "LEFT JOIN procs pr ON pr.fp = p.fp")
        args = []
        if scope:
            sql += " WHERE p.scope=?"
            args.append(scope)
        sql += " ORDER BY p.last_seen DESC LIMIT ?"
        args.append(limit)
        return self.db.execute(sql, args).fetchall()

    # -- events -------------------------------------------------------------

    def add_event(self, ev):
        self.db.execute(
            """INSERT INTO events(ts,host,severity,kind,fp,pid,name,exe,
                                  cmdline,user,reasons,remotes)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ev["ts"], ev["host"], ev["severity"], ev["kind"], ev.get("fp"),
             ev.get("pid"), ev.get("name"), ev.get("exe"), ev.get("cmdline"),
             ev.get("user"), ev.get("reasons", ""), ev.get("remotes", "")),
        )

    def list_events(self, limit=50, severity=None, since=None):
        sql = "SELECT * FROM events WHERE 1=1"
        args = []
        if severity:
            sql += " AND severity=?"
            args.append(severity)
        if since:
            sql += " AND ts>=?"
            args.append(since)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        return self.db.execute(sql, args).fetchall()

    def commit(self):
        self.db.commit()

    # -- dashboard snapshots ------------------------------------------------

    def save_snapshot(self, kind, payload, duration=0.0, error=""):
        """Store the latest result for one audit, plus a severity data point."""
        import json as _json

        self.db.execute(
            """INSERT INTO snapshots(kind,ts,duration,error,payload)
               VALUES(?,?,?,?,?)
               ON CONFLICT(kind) DO UPDATE SET
                   ts=excluded.ts, duration=excluded.duration,
                   error=excluded.error, payload=excluded.payload""",
            (kind, now(), duration, error, _json.dumps(payload, default=str)),
        )
        counts = {}
        if isinstance(payload, list):
            for f in payload:
                sev = (f or {}).get("severity")
                if sev in ("critical", "high", "medium", "low"):
                    counts[sev] = counts.get(sev, 0) + 1
        self.db.execute(
            """INSERT INTO history(ts,kind,critical,high,medium,low)
               VALUES(?,?,?,?,?,?)""",
            (now(), kind, counts.get("critical", 0), counts.get("high", 0),
             counts.get("medium", 0), counts.get("low", 0)),
        )
        # Keep the trend strip bounded; a week of points is plenty.
        self.db.execute("DELETE FROM history WHERE ts < ?", (now() - 7 * 86400,))
        self.db.commit()

    def get_snapshots(self):
        import json as _json

        out = {}
        for r in self.db.execute("SELECT * FROM snapshots"):
            try:
                payload = _json.loads(r["payload"])
            except Exception:
                payload = []
            out[r["kind"]] = {"ts": r["ts"], "duration": r["duration"],
                              "error": r["error"], "findings": payload}
        return out

    def get_history(self, hours=24):
        rows = self.db.execute(
            """SELECT ts, SUM(critical) c, SUM(high) h, SUM(medium) m, SUM(low) l
               FROM history WHERE ts >= ? GROUP BY ts/900 ORDER BY ts""",
            (now() - hours * 3600,),
        ).fetchall()
        return [{"ts": r["ts"], "critical": r["c"], "high": r["h"],
                 "medium": r["m"], "low": r["l"]} for r in rows]
