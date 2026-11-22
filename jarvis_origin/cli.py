"""Command-line interface for jarvis-origin."""

import argparse
import json
import sys
import time

from . import (alert, collect_windows, coverage, detect, feeds, fixit, hunt,
               intel, inputwatch, monitor, resourcewatch)
from .store import DEFAULT_DB, Store
from .util import iso, now, short

C = {
    "critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m",
    "low": "\033[90m", "ok": "\033[32m", "dim": "\033[90m", "bold": "\033[1m",
    "reset": "\033[0m",
}


def color(text, key, on=True):
    return f"{C[key]}{text}{C['reset']}" if on and key in C else text


def _tty():
    return sys.stdout.isatty()


def _hosts(args):
    if args.host == "all":
        return ("wsl", "win")
    return (args.host,)


# ---------------------------------------------------------------------------


def cmd_baseline(args, store):
    if args.reset:
        store.db.execute("DELETE FROM procs")
        store.db.execute("DELETE FROM peers")
        store.commit()
        print("Cleared the previous baseline.")
    print("Learning the current state as your known-good baseline…")
    res = monitor.scan(store, hosts=_hosts(args), enrich=False, learn=True)
    store.set_meta("baseline_at", now())
    total = len(store.known_fps())
    print(f"  {res['scanned']} processes captured, {total} unique fingerprints approved.")
    print(f"  Database: {store.path}")
    print("\nFrom now on, anything new shows up as drift. Re-run `jarvis-origin baseline` "
          "after you install software you trust — it adds to what's already there.")


def cmd_scan(args, store):
    if not store.get_meta("baseline_at"):
        print(color("No baseline yet — everything will look new. "
                    "Run `jarvis-origin baseline` first.\n", "medium", _tty()))
    res = monitor.scan(store, hosts=_hosts(args), enrich=args.enrich)

    if args.json:
        print(json.dumps(res, default=str, indent=2))
        return

    print(monitor.summarize(res))
    findings = res["findings"]
    if args.severity:
        keep = {"critical": 0, "high": 1, "medium": 2, "low": 3}[args.severity]
        findings = [f for f in findings if monitor.SEV_ORDER[f["severity"]] <= keep]

    if not findings:
        print(color("  no drift, no suspicious traits.", "ok", _tty()))
    for f in findings[: args.limit]:
        _print_finding(f)

    if res["new_public_peers"]:
        print(f"\n{color('New external peers', 'bold', _tty())} "
              f"({len(res['new_public_peers'])} first-time public IPs):")
        for p in res["new_public_peers"][: args.limit]:
            proc = p["proc"]
            rd = f"  {p.get('rdns')}" if p.get("rdns") else ""
            print(f"  {p['ip']}:{p['port']}  ←  {proc['name']} "
                  f"[{proc['host']}/{proc['pid']}]{rd}")

    if len(findings) > args.limit:
        print(f"\n  … {len(findings) - args.limit} more (use --limit)")


def _print_finding(f):
    t = _tty()
    sev = f["severity"]
    tag = color(f" {sev.upper():8} ", sev, t)
    flag = "NEW" if f["unknown"] else "   "
    print(f"\n{tag} {flag} {color(f['name'], 'bold', t)} "
          f"[{f['host']}/{f['pid']}] {color(f['user'] or '-', 'dim', t)}")
    print(f"          exe   {short(f['exe'] or f.get('script') or '-', 96)}")
    print(f"          cmd   {short(f['cmdline'], 96)}")
    if f["reasons"]:
        print(f"          why   {detect.explain(f['reasons'])}")
    for r in f["remotes"][:6]:
        rd = f"  ({r['rdns']})" if r.get("rdns") else ""
        mark = color("→ PUBLIC", "high", t) if r["scope"] == "public" else "→"
        print(f"          net   {mark} {r['ip']}:{r['port']} "
              f"{r['proto']}/{r['state']}{rd}")
    print(f"          fp    {f['fp']}")


def cmd_watch(args, store):
    print(f"Watching every {args.interval}s — Ctrl-C to stop.  "
          f"(hosts: {'+'.join(_hosts(args))})")
    if args.interval < 30 and "win" in _hosts(args):
        print(color("  note: Windows collection takes a few seconds per pass; "
                    "intervals under 30s will lag.", "dim", _tty()))
    try:
        while True:
            res = monitor.scan(store, hosts=_hosts(args), enrich=args.enrich)
            alerts = [f for f in res["findings"]
                      if monitor.SEV_ORDER[f["severity"]] <= 2]  # medium and worse
            if alerts or res["new_public_peers"]:
                print("\n" + monitor.summarize(res))
                for f in alerts[: args.limit]:
                    _print_finding(f)
                for p in res["new_public_peers"][:10]:
                    print(f"          new peer {p['ip']}:{p['port']} ← "
                          f"{p['proc']['name']}")
            elif args.verbose:
                print(monitor.summarize(res))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")


SECTION = {
    # module category -> heading shown above that group
    "spyware": "MONITORING SOFTWARE — things built to watch you",
    "access": "DEVICE & ACCOUNT ACCESS — mic, camera, logons",
    "input": "INPUT & AUDIO CONTROL — what can move your volume or type for you",
    "signing": "AUTOSTART CODE SIGNING — who vouches for what starts with Windows",
    "av": "ANTIVIRUS — what Defender already found",
    "clickfix": "PASTED COMMANDS — the Run dialog and PowerShell history",
    "extension": "BROWSER EXTENSIONS — what can read your sessions",
    "staging": "STAGED FILES — recent unsigned executables",
    "loader": "LOADER ABUSE — code injected into other processes",
    "collectors": "COLLECTOR HEALTH — is every check actually running?",
    "daemon": "CONTINUITY — is the monitor running, and will it survive a reboot?",
    "visibility": "BLIND SPOTS — what this system currently cannot see",
    "limits": "BY DESIGN — what this approach can never see",
    "byovd": "KERNEL INTEGRITY — vulnerable drivers and what blocks them",
    "ads": "ALTERNATE DATA STREAMS — files hidden inside other files",
    "lnk": "SHORTCUTS — what they show versus what they run",
    "c2": "DEAD-DROP C2 — commands and exfil over reputable services",
    "unicode": "INVISIBLE CHARACTERS — displayed text that is not executed text",
    "logon": "LOGON CHAIN",
    "com": "COM REGISTRATIONS",
    "privileged": "PRIVILEGED PLUMBING — code loaded by system services",
    "masquerade": "MASQUERADING & PARENTAGE",
    "history": "EXECUTION HISTORY",
    "flash": "WINDOW FLASHES — autostart entries that show a console window",
    "ran": "WHAT ACTUALLY RAN THIS BOOT",
    "boot": "BOOT",
    "inbound": "INBOUND CONNECTIONS — traffic initiated from outside",
    "rules": "FIREWALL RULES",
    "posture": "FIREWALL POSTURE",
}


def _report(findings, verbose=False, severity=None, sev_order=None,
            show_ok=False, empty="nothing found"):
    """Shared renderer for the audit-style commands."""
    t = _tty()
    sev_order = sev_order or {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
    if severity:
        findings = [f for f in findings
                    if sev_order.get(f["severity"], 9) <= sev_order[severity]]
    if not show_ok and not verbose:
        findings = [f for f in findings if f["severity"] != "ok"]

    counts, last = {}, None
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        cat = f.get("category", "")
        if cat != last:
            heading = SECTION.get(cat, cat.upper())
            if heading:
                print(f"\n{color(heading, 'bold', t)}")
            last = cat
        sev = f["severity"]
        tag = (color("  ok  ", "ok", t) if sev == "ok"
               else color(f" {sev[:4].upper():4} ", sev, t))
        host = f.get("host", "")
        print(f"  {tag} [{host}] {f['title']}: {f['detail']}")
        where = f.get("where") or f.get("evidence") or ""
        if verbose and where:
            print(f"          {color(where, 'dim', t)}")
        fix = fixit.suggest(f)
        if fix:
            print(f"          {color('fix: ' + fix, 'ok', t)}")

    if not findings:
        print(color(f"  {empty}", "ok", t))
    tally = "  ".join(f"{k}={counts[k]}" for k in
                      ("critical", "high", "medium", "low") if k in counts)
    print(f"\n{len([f for f in findings if f['severity'] != 'ok'])} findings   "
          f"{tally or 'none'}")
    return counts


def cmd_coverage(args, store):
    print("Auditing the monitor itself — what is blind, stale or not running…\n")
    findings = coverage.sort_findings(coverage.audit(db_path=store.path))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=coverage.SEV_ORDER, show_ok=True,
            empty="coverage is complete")


def cmd_serve(args, store):
    from . import server
    store.close()  # the daemon opens its own handles per thread
    server.serve(db_path=args.db, port=args.port, hosts=_hosts(args))


def _scan_findings(store, hosts):
    from .server import scan_findings
    return scan_findings(monitor.scan(store, hosts=hosts))


def cmd_investigate(args, store):
    """Everything at once, for when you think something is actually wrong."""
    t = _tty()
    hosts = _hosts(args)
    sections = [
        ("PROCESSES & NETWORK", lambda: _scan_findings(store, hosts)),
        ("RESOURCE PRESSURE", lambda: resourcewatch.audit(store, hosts=hosts)),
        ("SYNTHETIC INPUT", lambda: inputwatch.audit(store)),
        ("THREAT-INTEL MATCHES", lambda: hunt.sort_findings(
            hunt.hunt(store, hosts=hosts))),
    ]
    worst = {}
    for title, fn in sections:
        print(f"\n{color('━' * 72, 'dim', t)}")
        print(color(title, "bold", t))
        print(color("━" * 72, "dim", t))
        try:
            findings = fn()
        except Exception as exc:  # one failing collector must not kill the report
            print(color(f"  section failed: {exc}", "medium", t))
            continue
        for f in findings:
            f.setdefault("category", "")
        counts = _report(findings, verbose=args.verbose,
                         severity=args.severity or "medium")
        for k, v in counts.items():
            worst[k] = worst.get(k, 0) + v

    print(f"\n{color('━' * 72, 'dim', t)}")
    tally = "  ".join(f"{k}={worst[k]}" for k in
                      ("critical", "high", "medium", "low") if k in worst)
    print(f"{color('TOTAL', 'bold', t)}   {tally or 'nothing at medium or above'}")


def cmd_intel(args, store):
    """Refresh the threat-intelligence knowledge base."""
    t = _tty()
    if args.set_key:
        path = intel.save_key(args.set_key)
        print(f"key stored in {path} (mode 0600, outside the repository)")
        return
    if args.revet:
        st = intel.revet(store)
        print(f"re-vetted {st['checked']} indicators — "
              f"{st['dropped']} dropped, {st['moved']} reclassified")
        for why, n in sorted(st["reasons"].items(), key=lambda kv: -kv[1])[:12]:
            print(f"  {n:4}  {why}")
        return
    if args.show:
        info = intel.summary(store)
        print(f"documents     {info['docs']}")
        print(f"indicators    {info['total']} active")
        for kind, n in sorted(info["by_kind"].items(), key=lambda kv: -kv[1]):
            print(f"  {kind:10} {n}")
        last = info["last_refresh"]
        print(f"last refresh  {iso(last) if last else 'never'}")
        print(f"api spend     ${info['spend']:.3f} total")
        return

    topics = args.topic or None
    if args.all:
        topics = list(intel.CORPUS)
    label = ", ".join(topics) if topics else "the least recently refreshed topic"
    print(f"Fetching threat intelligence for {label}…\n")

    def progress(topic, query):
        print(color(f"  [{topic}] {short(query, 64)}", "dim", t))

    try:
        stats = intel.refresh(store, topics=topics, per_query=args.results,
                              days=args.days, on_progress=progress)
    except intel.IntelError as exc:
        print(color(f"intel refresh failed: {exc}", "high", t))
        return 1

    print()
    print(f"  {stats['queries']} queries · {stats['docs']} documents "
          f"· ${stats['cost']:.3f}")
    print(f"  {stats['kept']} indicators kept, {stats['rejected']} rejected "
          f"of {stats['seen']} candidates")
    if stats["not_research"]:
        print(color(f"  {stats['not_research']} documents were not threat research",
                    "dim", t))
    if args.verbose and stats["reasons"]:
        print(color("\n  why candidates were rejected:", "dim", t))
        for why, n in sorted(stats["reasons"].items(), key=lambda kv: -kv[1])[:12]:
            print(color(f"    {n:4}  {why}", "dim", t))
    for err in stats["errors"]:
        print(color(f"  {err}", "medium", t))


def cmd_inputwatch(args, store):
    """Synthetic keystrokes and clicks — input no hardware produced."""
    t = _tty()
    if args.start:
        err = inputwatch.start()
        print(color(f"  {err}", "medium", t) if err
              else "  injected-input monitor started")
        if err and err != "already running":
            return 1
    if args.stop:
        err = inputwatch.stop()
        print(f"  {err or 'injected-input monitor stopped'}")
        return
    findings = inputwatch.audit(store, hours=args.hours)
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            sev_order=inputwatch.SEV_ORDER, show_ok=True,
            empty="no synthetic input recorded")


def cmd_feeds(args, store):
    """Refresh the free bulk indicator feeds."""
    t = _tty()
    if args.status:
        rows = feeds.status(store)
        if not rows:
            print("no feed has run yet — run `jarvis-origin feeds`")
            return
        for r in rows:
            when = iso(r["last_run"]) if r["last_run"] else "never"
            line = (f"  {r['name']:16} {when}  {r['kept']:>7} kept "
                    f"of {r['rows']:>7}  {r['bytes'] / 1024:>8.0f} KiB")
            print(line + (color("  " + r["error"], "high", t) if r["error"] else ""))
        return
    if args.prune:
        n = feeds.prune(store, days=args.days)
        print(f"retired {n} feed indicators not seen in {args.days} days")
        return

    print("Refreshing bulk indicator feeds…\n")

    def progress(name, desc):
        print(color(f"  {name:16} {desc}", "dim", t))

    results = feeds.refresh(store, names=args.feed or None, force=args.force,
                            on_progress=progress)
    if args.attack or args.force:
        print(color("  attack           MITRE ATT&CK technique catalogue", "dim", t))
        results.append(feeds.refresh_attack(store, force=args.force))

    print()
    total = 0
    for r in results:
        if r.get("skipped"):
            continue
        if r.get("error"):
            print(color(f"  {r['name']:16} failed: {r['error']}", "medium", t))
            continue
        total += r.get("kept", 0)
        print(f"  {r['name']:16} {r.get('kept', 0):>7} kept "
              f"of {r.get('rows', 0):>7} rows")
    if not results:
        print("  every feed is still within its refresh interval "
              "(use --force to override)")
    else:
        print(f"\n  {total} indicators added or refreshed")


def cmd_hunt(args, store):
    """Check every stored indicator against this machine."""
    info = intel.summary(store)
    if not info["total"]:
        print("no indicators yet — run `jarvis-origin intel` first")
        return
    print(f"Hunting {info['total']} indicators from {info['docs']} writeups "
          f"across {'+'.join(_hosts(args))}…\n")
    findings = hunt.sort_findings(hunt.hunt(store, hosts=_hosts(args)))
    if args.json:
        print(json.dumps(findings, indent=2))
        return
    _report(findings, verbose=args.verbose, severity=args.severity,
            empty="no indicator matched anything on this machine")


def cmd_gaps(args, store):
    """What current intel talks about that no collector checks."""
    t = _tty()
    findings, covered, closeable = hunt.gaps(store, min_docs=args.min_docs)
    if args.json:
        print(json.dumps({"gaps": findings,
                          "covered": [{"id": c[0], "docs": c[1], "by": c[2]}
                                      for c in covered]}, indent=2))
        return
    total = len(covered) + len(closeable)
    if not total:
        print("no ATT&CK techniques in the knowledge base yet — run `jarvis-origin intel`")
        return
    pct = 100.0 * len(covered) / total
    print(f"of the techniques in current intel that leave host artifacts, "
          f"{len(covered)} of {total} are covered ({pct:.0f}%)\n")
    _report(findings, verbose=args.verbose, severity=args.severity,
            empty="every technique in current intel is covered")
    if args.verbose and covered:
        print(color("\n  already covered:", "dim", t))
        for tid, n, where in covered[:40]:
            print(color(f"    {tid:11} ×{n:<3} {where}", "dim", t))


def cmd_procs(args, store):
    rows = store.list_procs(approved=args.approved, limit=args.limit)
    print(f"{'FP':<18}{'HOST':<6}{'APPR':<6}{'SEEN':<6}{'LAST':<21}NAME / CMD")
    for r in rows:
        print(f"{r['fp']:<18}{r['host']:<6}{'yes' if r['approved'] else 'no':<6}"
              f"{r['seen_count']:<6}{iso(r['last_seen']):<21}"
              f"{short(r['name'] + '  ' + (r['cmdline'] or ''), 60)}")
    print(f"\n{len(rows)} rows")


def cmd_peers(args, store):
    rows = store.list_peers(scope=args.scope, limit=args.limit)
    print(f"{'REMOTE':<44}{'SCOPE':<10}{'HOST':<6}{'SEEN':<6}{'LAST':<21}PROCESS")
    for r in rows:
        endpoint = f"{r['remote_ip']}:{r['remote_port']}"
        print(f"{endpoint:<44}{r['scope']:<10}{r['host']:<6}{r['seen_count']:<6}"
              f"{iso(r['last_seen']):<21}{short(r['pname'] or r['fp'], 30)}"
              f"{('  ' + r['rdns']) if r['rdns'] else ''}")
    print(f"\n{len(rows)} rows")


def cmd_events(args, store):
    since = now() - args.since * 3600 if args.since else None
    rows = store.list_events(limit=args.limit, severity=args.severity, since=since)
    t = _tty()
    for r in rows:
        tag = color(f" {r['severity'][:4].upper():4} ", r["severity"], t)
        print(f"{iso(r['ts'])} {tag} [{r['host']}/{r['pid']}] {r['name']} "
              f"— {detect.explain((r['reasons'] or '').split(',')) if r['reasons'] else r['kind']}")
        if args.verbose:
            print(f"    {short(r['cmdline'] or '', 110)}")
    print(f"\n{len(rows)} events")


def cmd_approve(args, store):
    n = 0
    for fp in args.fingerprint:
        n += store.set_approved(fp, 1, args.note)
    print(f"approved {n} fingerprint(s)")


def cmd_alert(args, store):
    """Outbound email alerts through Resend — status, or a test send."""
    if args.test:
        print("Sending a test alert…")
        err = alert.test(store)
        print(color(f"  {err}", "high", _tty()) if err
              else "  sent — check the inbox")
        return 1 if err else 0
    s = alert.status(store)
    t = _tty()
    on = color("enabled", "ok", t) if s["enabled"] else color(
        "not configured", "medium", t)
    print(f"alerts        {on}")
    print(f"transport     Resend  (key {'present' if s['have_key'] else 'missing'})")
    print(f"from          {s['from'] or '—'}")
    print(f"to            {', '.join(s['to']) or '—'}")
    print(f"min severity  {s['min_severity']}  (outage findings always page)")
    print(f"resend after  {s['resend_after'] // 3600}h while still firing")
    print(f"outage resend every {s['outage_resend_after'] // 60}m, widening to "
          f"{alert.OUTAGE_RESEND_CAP // 60}m")
    print(f"on clear      {'yes' if s['on_clear'] else 'no'}")
    print(f"retries       {s['send_attempts']} attempts per email")
    cap = s["hourly_cap"] or "unlimited"
    print(f"hourly cap    {cap}  (outages: {s['outage_hourly_cap']}) — "
          f"{s['sent_last_hour']} sent in the last hour")
    print(f"last sent ok  {iso(s['last_ok']) if s['last_ok'] else '—'}")
    print(f"5h report     last sent "
          f"{iso(s['report_last_ok']) if s['report_last_ok'] else '—'}")
    print(f"AI depth      {s['advisory_model'] if s['advisory_ai'] else 'not configured'}")
    if s["report_last_error"]:
        print(color(f"report error  {s['report_last_error']}", "high", t))
    if s["last_error"]:
        print(color(f"last error    {s['last_error']}", "high", t))
    if s["capped_at"]:
        print(color(f"last capped   {iso(s['capped_at'])}", "medium", t))
    if s["outages"]:
        print(color("ACTIVE OUTAGES — JARVIS-1 is not watching something:", "high", t))
        for k in s["outages"]:
            print(color(f"  ! {k.replace('|', ' — ')}", "high", t))
    if s["active"]:
        print("active alerts:")
        for k in s["active"]:
            print(f"  - {k.replace('|', ' — ')}")
    if not s["enabled"]:
        print(f"\nSet resend_api_key, alert_from and alert_to in "
              f"{alert.CONFIG_PATH} (0600). alert_from must be a "
              f"Resend-verified sender.")


def cmd_status(args, store):
    b = store.get_meta("baseline_at")
    total = len(store.known_fps())
    appr = len(store.list_procs(approved=1, limit=100000))
    ev = store.list_events(limit=1)
    print(f"database      {store.path}")
    print(f"baseline      {iso(int(b)) if b else 'not taken — run `jarvis-origin baseline`'}")
    print(f"fingerprints  {total} known, {appr} approved")
    print(f"peers         {len(store.list_peers(limit=100000))} recorded")
    print(f"last event    {iso(ev[0]['ts']) if ev else '—'}")
    print(f"windows side  "
          f"{'reachable' if collect_windows.available() else 'unavailable'}")


# ---------------------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(
        prog="jarvis-origin",
        description="Watch processes, network peers, injected input and threat intel "
                    "across WSL and Windows.",
    )
    p.add_argument("--db", default=DEFAULT_DB, help="database path")
    p.add_argument("--host", choices=["wsl", "win", "all"], default="all")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline", help="record the current state as known-good")
    b.add_argument("--reset", action="store_true",
                   help="forget the old baseline first instead of adding to it")
    b.set_defaults(fn=cmd_baseline)

    s = sub.add_parser("scan", help="one pass: report drift and suspicious traits")
    s.add_argument("--enrich", action="store_true", help="reverse-DNS public IPs")
    s.add_argument("--json", action="store_true")
    s.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(fn=cmd_scan)

    w = sub.add_parser("watch", help="scan continuously")
    w.add_argument("-i", "--interval", type=int, default=60)
    w.add_argument("--enrich", action="store_true")
    w.add_argument("-v", "--verbose", action="store_true", help="print quiet passes too")
    w.add_argument("--limit", type=int, default=10)
    w.set_defaults(fn=cmd_watch)


    cv = sub.add_parser("coverage",
                        help="self-audit: blind spots, stale collectors, failures")
    cv.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    cv.add_argument("-v", "--verbose", action="store_true")
    cv.add_argument("--json", action="store_true")
    cv.set_defaults(fn=cmd_coverage)


    sv = sub.add_parser("serve",
                        help="run the 24/7 daemon and local dashboard")
    sv.add_argument("-p", "--port", type=int, default=8790)
    sv.set_defaults(fn=cmd_serve)

    inv = sub.add_parser("investigate",
                         help="run every audit at once — start here if you suspect something")
    inv.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    inv.add_argument("-v", "--verbose", action="store_true")
    inv.set_defaults(fn=cmd_investigate)


    it2 = sub.add_parser("intel",
                         help="refresh the threat-intelligence knowledge base")
    it2.add_argument("--topic", action="append",
                     choices=sorted(intel.CORPUS),
                     help="refresh only this topic (repeatable)")
    it2.add_argument("--all", action="store_true", help="refresh every topic")
    it2.add_argument("--results", type=int, default=6,
                     help="results per query (default 6)")
    it2.add_argument("--days", type=int, default=365,
                     help="only consider writeups published in the last N days")
    it2.add_argument("--set-key", metavar="KEY", help="store the Exa API key")
    it2.add_argument("--revet", action="store_true",
                     help="re-judge stored indicators against the current rules")
    it2.add_argument("--show", action="store_true",
                     help="show what the knowledge base holds")
    it2.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    it2.add_argument("-v", "--verbose", action="store_true")
    it2.add_argument("--json", action="store_true")
    it2.set_defaults(fn=cmd_intel)


    iw = sub.add_parser("inputwatch",
                        help="detect keystrokes and clicks no hardware produced")
    iw.add_argument("--start", action="store_true", help="start the hook helper")
    iw.add_argument("--stop", action="store_true", help="stop the hook helper")
    iw.add_argument("--hours", type=int, default=24,
                    help="how far back to report (default 24)")
    iw.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    iw.add_argument("-v", "--verbose", action="store_true")
    iw.add_argument("--json", action="store_true")
    iw.set_defaults(fn=cmd_inputwatch)


    fd = sub.add_parser("feeds",
                        help="refresh free bulk indicator feeds (no API key)")
    fd.add_argument("--feed", action="append", choices=sorted(feeds.FEEDS),
                    help="refresh only this feed (repeatable)")
    fd.add_argument("--force", action="store_true",
                    help="refresh even if not yet due")
    fd.add_argument("--attack", action="store_true",
                    help="also refresh the MITRE ATT&CK catalogue")
    fd.add_argument("--status", action="store_true", help="show feed health")
    fd.add_argument("--prune", action="store_true",
                    help="retire feed indicators no longer listed")
    fd.add_argument("--days", type=int, default=90,
                    help="staleness threshold for --prune (default 90)")
    fd.set_defaults(fn=cmd_feeds)

    hu = sub.add_parser("hunt",
                        help="check stored indicators against this machine")
    hu.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    hu.add_argument("-v", "--verbose", action="store_true")
    hu.add_argument("--json", action="store_true")
    hu.set_defaults(fn=cmd_hunt)

    gp = sub.add_parser("gaps",
                        help="techniques in current intel that nothing checks")
    gp.add_argument("--min-docs", type=int, default=1,
                    help="only techniques seen in at least N writeups")
    gp.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    gp.add_argument("-v", "--verbose", action="store_true")
    gp.add_argument("--json", action="store_true")
    gp.set_defaults(fn=cmd_gaps)

    pr = sub.add_parser("procs", help="list fingerprints in the baseline")
    pr.add_argument("--approved", type=int, choices=[0, 1])
    pr.add_argument("--limit", type=int, default=60)
    pr.set_defaults(fn=cmd_procs)

    pe = sub.add_parser("peers", help="list observed network peers")
    pe.add_argument("--scope", choices=["public", "private", "loopback"])
    pe.add_argument("--limit", type=int, default=60)
    pe.set_defaults(fn=cmd_peers)

    e = sub.add_parser("events", help="recent alerts")
    e.add_argument("--limit", type=int, default=40)
    e.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    e.add_argument("--since", type=int, metavar="HOURS")
    e.add_argument("-v", "--verbose", action="store_true")
    e.set_defaults(fn=cmd_events)

    a = sub.add_parser("approve", help="mark fingerprints as known-good")
    a.add_argument("fingerprint", nargs="+")
    a.add_argument("--note", default="")
    a.set_defaults(fn=cmd_approve)

    st = sub.add_parser("status", help="show what JARVIS-1 knows so far")
    st.set_defaults(fn=cmd_status)


    al = sub.add_parser("alert",
                        help="email alerts via Resend: status, or --test")
    al.add_argument("--test", action="store_true",
                    help="send a test alert to the configured recipients")
    al.set_defaults(fn=cmd_alert)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    store = Store(args.db)
    try:
        args.fn(args, store)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
