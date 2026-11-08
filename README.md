# Jarvis Origin

**Where ARGUS-1 began.** Jarvis Origin is the first version of the monitor that
grew into ARGUS-1, opened up as a reference for anyone building honest host
security tooling.

A small, dependency-free host monitor for **WSL2 + Windows** machines. It watches
what runs and where it connects, notices keyboard and mouse input that no human
produced, checks the machine against current threat intelligence, and tells you
plainly when it cannot see something.

Pure Python 3 standard library: no packages to install, no agent framework, no
cloud service. Nothing leaves the machine unless you configure it to: the
bulk indicator feeds, the optional Exa research search, and optional email alerts.

> **Status:** an early, single-machine monitor shared as a reference
> implementation. It is useful, honest about its limits, and not a replacement
> for an EDR. Read [What it does not do](#what-it-does-not-do) first.

## Start here

```bash
git clone <this repository> jarvis-origin && cd jarvis-origin
python3 -m unittest discover -s tests   # 35 tests, under a second
./install.sh --service                   # run it continuously; dashboard at http://127.0.0.1:8790
jarvis-origin investigate                   # or a one-off report in the terminal
```

Requires Python 3.10+. On WSL2 the Windows side is reached through
`powershell.exe` over the interop bridge; on plain Linux the Windows checks
report themselves as unavailable instead of clean.

## The commands

| command | what it does |
|---|---|
| `jarvis-origin baseline` | record the processes running now as known-good |
| `jarvis-origin scan` / `watch` | one pass (or a loop): drift from the baseline plus suspicious traits |
| `jarvis-origin serve` | the scheduler and the local dashboard |
| `jarvis-origin investigate` | everything at once, for when something feels wrong |
| `jarvis-origin feeds` | refresh the free public indicator feeds (~400k indicators) |
| `jarvis-origin intel` | refresh the research knowledge base (Exa, metered, budgeted) |
| `jarvis-origin hunt` | compare every stored indicator against this machine |
| `jarvis-origin gaps` | ATT&CK techniques current research raises that nothing here covers |
| `jarvis-origin inputwatch` | the injected-input monitor: status, start, stop, audit |
| `jarvis-origin coverage` | audit the monitor itself: is every collector fresh, what is blind |
| `jarvis-origin procs` / `peers` / `events` / `approve` / `status` | inspect and curate the baseline |
| `jarvis-origin alert` | email alert status, or `--test` |

## The dashboard

`jarvis-origin serve` runs a scheduler and a local web page. It is plain
`http.server` + SQLite + one self-contained HTML file — no framework, no build
step, no CDN, and no dependency beyond the Python standard library. For a
security tool that is the point: every dependency is code you have to trust, and
this one is meant to tell you when something untrustworthy is running.

Three things shaped the design:

- **Collectors have wildly different costs.** Reading `/proc` takes 20ms; a
  PowerShell audit takes 10–60s because crossing the WSL interop boundary
  dominates everything else. So each job runs on its own interval — processes
  every 60s, the input watchdog every 45s, the threat-intel hunt every 30min,
  bulk feeds hourly.
- **Jobs never run concurrently.** A single worker runs them one at a time; two
  simultaneous `powershell.exe` launches are slower than running them back to
  back and fight over the same interop pipe.
- **The page never waits for a scan.** Every request is served from the last
  stored snapshot, so the dashboard is instant even mid-audit, and a restart
  redraws immediately from SQLite instead of showing a blank page.

The listener binds `127.0.0.1` with no option to change it. A page listing your
running processes and external peers is exactly what an attacker would like to
read.

### Running 24/7

`./install.sh --service` installs a systemd **user** service with
`Restart=on-failure`. Nothing needs sudo. Two WSL-specific gotchas that the
installer calls out:

1. **Linger.** Without it, systemd tears down your user manager when your last
   shell exits — closing your terminal would stop the daemon.
   ```bash
   sudo loginctl enable-linger $USER
   ```
2. **WSL itself.** WSL only runs while Windows keeps it running. Run
   `./install.sh --windows` for the one-time PowerShell command that registers a
   hidden logon task to start WSL; systemd and linger take it from there.

## Knowing what to look for

Every static check encodes what was worth looking for on the day it was
written. Attacker tradecraft moves; a static detector quietly ages into a
detector of last year's problems. `intel` keeps a knowledge base of current
published research, `hunt` compares it against this machine, and `gaps` reports
what current tradecraft nothing here can see.

The knowledge comes from Exa's search API, restricted to a list of publishers
that do primary host-based research. Each result is passed back through the
same API with a JSON schema attached, so what returns is structured artefacts —
paths, hashes, domains, registry keys, ATT&CK technique ids — rather than
article text to parse. The API key lives in `~/.jarvis-origin/config.json` at mode
0600, never in the repository.

### Why none of it is trusted

This is the only part of Jarvis Origin that takes input from the internet, and it does
so in a security tool whose entire value is being right about what is running.
Two things are wrong with the input by construction: the articles are written by
strangers, and the extraction is done by a language model that fills empty
fields with plausible filler.

That is not hypothetical. One real article in testing produced `evil.com`,
`192.168.1.100`, `gdb`, `strace`, a bare `/tmp/`, and two "SHA-256" values that
turned out to be the digests of the empty string. Every one of those is
syntactically perfect. Loaded straight into a detector on a developer's
workstation, that single article would have flagged the debugger on every use
and pinned a permanent alert on a directory that is supposed to contain files.

So `vet.py` sits between the feed and the database, and it is deliberately the
dumbest code in the project — no network, no model, no learning. It drops
digests of empty input, non-public addresses, reserved example domains, kernel
symbols filed as process names, stock PAM modules, path fragments like `/proc`
that exist on every machine, and anything holding a redaction marker. On the
first real corpus run it rejected roughly a quarter of all candidates.

Two invariants hold no matter what the feed says:

- **Intel may only ever add suspicion.** Nothing fetched can approve a process,
  clear a finding, or lower a severity. The worst a poisoned feed can achieve is
  wasting your attention; it can never create a blind spot.
- **Nothing fetched is ever executed.** Indicators are compared as data — never
  interpolated into a shell, never used to build a command.

When the rules get tighter, `jarvis-origin intel --revet` re-judges everything already
stored, so the knowledge base is never stuck at the quality of the rules that
were in force the day it was fetched.

### Turning knowledge into a check

`hunt` only compares against state Jarvis Origin already collects, so it is cheap
enough to run every half hour:

| indicator | checked against | severity on match |
|---|---|---|
| SHA-256 | digests of executables in the baseline, cached by size and mtime | critical |
| domain / IPv4 | the recorded peer table, including reverse DNS | critical |
| absolute path | the filesystem, skipping anything a package owns | high |
| filename | only the directories such a payload must live in to work | high |
| process name | exact matches in the process baseline | high |

Two second-guards keep the false-positive rate down: a path that `dpkg` owns is
never reported, because a package putting a file where it belongs is not an
intrusion, and a directory is never reported as a dropped file.

The filename check exists because the best indicator from the first real run —
`pam_security.so`, a PAM backdoor named in six separate writeups — arrived with
no path at all. Hunting bare filenames across a whole filesystem would be slow
and noisy, so it looks only where such a payload has to be to function: the PAM
module paths, the loader paths, the systemd unit directories, the world-writable
drops.

### Gaps: pointing the tool at its own blind spots

ATT&CK technique ids cannot be "found" on a host, so they are used differently.
`gaps` compares the techniques current research is discussing against the
techniques Jarvis Origin's collectors actually cover, and reports the difference,
weighted by how many independent writeups raised each one. A technique three
teams wrote about this year is a better use of an afternoon than one mentioned
once.

This is the counterpart to `coverage`. `coverage` asks whether Jarvis Origin is
running; `gaps` asks whether it is looking at the right things — and answers
with a work queue rather than a warning.

### Cost

Searches are metered. One topic refresh is roughly five cents; the full corpus
is under forty. The daemon refreshes one topic at a time on a six-hour timer, so
the corpus rotates itself over about two days. A daily budget, default `$0.50`
and settable as `daily_budget` in `~/.jarvis-origin/config.json`, is enforced before
each query rather than reported after it — a metered API on a 24/7 timer is
otherwise a standing invitation to a surprise bill.

## Volume: the bulk feeds

Search buys *tradecraft* — the path a rootkit drops, the unit file it installs.
It is a poor way to buy *coverage*: a writeup names a handful of hashes, and
paying a metered API per document to accumulate tens of thousands of them costs
real money for data that is already published free.

So `feeds` carries the volume and `intel` carries the narrative:

| | source | gives |
|---|---|---|
| `intel` | Exa over ~60 research publishers | paths, filenames, techniques, persistence |
| `feeds` | 15 public feeds, no authentication | hashes, domains, addresses, ranges, CVEs |

The feeds are abuse.ch (ThreatFox, MalwareBazaar, URLhaus, Feodo), CISA KEV,
Spamhaus DROP, OpenPhish, Emerging Threats, blocklist.de, CINS, Binary Defense,
IPsum, and the MITRE ATT&CK catalogue. Together they hold **just under 400,000
live indicators**, refreshed on each publisher's own cadence — ThreatFox and
URLhaus update continuously, CISA KEV when exploitation starts.

Feed data is better than an extraction from prose: curated, attributed,
confirmed malicious. It still goes through the same `vet.py` gate, because a
feed can carry a private address or a defanged placeholder too, and because the
"intel may only add suspicion" invariant has to hold for every source without
exception.

Everything ages. `feeds --prune` retires feed indicators no publisher has
listed for 90 days, because C2 infrastructure is rented and recycled and an
address that fell off every list three months ago is more likely to be someone
else's server now. Writeup-derived indicators are never pruned: a sample's hash
is true forever.

### Staying fast at that size

Holding 400,000 records is easy. Querying them on a 30-minute timer without the
machine noticing is the part that needed design.

The first version loaded every indicator into Python dictionaries and compared
in a loop. At sixteen thousand records that was invisible; at four hundred
thousand it would have read a hundred megabytes into memory to answer a
question SQLite can answer from an index. `hunt` is now written as indexed
joins against the `(kind, norm)` unique index, with three consequences:

- addresses match in a single join
- reverse-DNS names walk only their own parent domains — a handful of index
  probes each, regardless of how many domains are stored
- file hashes probe the index per file rather than loading every digest

Network ranges are the exception, because a CIDR cannot be indexed by value, so
they are bucketed by first octet and a peer is only tested against the handful
of networks that could contain it.

The database runs in WAL mode so the dashboard reads while feeds write. Bulk
inserts go in 20,000-row chunks.

The result is that a hunt across 397,000 indicators takes **0.4 seconds** —
the same as it took across 16,000.

## Input that no human produced

Windows tags every keyboard and mouse event that did not come from real
hardware. `LLKHF_INJECTED` marks anything delivered through `SendInput` or
`keybd_event`; `LLKHF_LOWER_IL_INJECTED` additionally marks input injected by a
process at a lower integrity level than the window receiving it, which is the
shape of one program driving another's UI. Those flags are visible only from
inside a low-level hook, so `inputwatch` manages a small resident helper that
installs one.

Three costs, all real, all worth stating before you turn it on.

**It is an agent.** Everything else here samples state and exits. This runs
resident, and if it dies the record stops — so it emits a heartbeat, because
otherwise "no injected input" and "not watching" look identical.

**It does not record what you type.** A low-level keyboard hook sees every
keystroke, and one that stored key values would be a keylogger writing your
passwords to a SQLite file. Real keystrokes are counted and nothing else.
Injected events store a coarse class (`enter`, `character`, `navigation`), the
flags, and the focused window. Enough to say *something typed Enter into your
terminal at 03:14*; not enough to reconstruct a sentence.

Real typing is retained only as one aggregate SQLite row per minute: total
key-downs, cadence buckets, and counts for the `=/+`, `/?`, and `./>` physical
key families. There is no order, shift state or surrounding text, so a password
cannot be reconstructed. The daemon uses those 90 days of bounded history as a
personal baseline and reports volume spikes, machine-fast cadence, or unusual
concentration on those punctuation keys. Injected presses of the same keys are
stored as coarse classes and remain high-signal events.

**Injected does not mean malicious.** Password-manager auto-type, AutoHotkey,
on-screen keyboards, RDP, screen sharing and some IDE features all inject
legitimately, and the flag says nothing about *which* process did it — the
foreground window is only a weak correlate. This reports evidence with the
context to judge it, not a verdict.

### Why the cursor feels slow

Every low-level hook sits in a chain, and each one delays every event until it
returns. That is the mechanism behind "the mouse is slower than it used to be":
a keylogger, screen recorder or overlay doing work on the input thread shows up
as milliseconds on every movement.

So the hook measures it rather than guessing — the delta between when Windows
generated an event and when this hook received it, reported as average, peak,
and the share of events over 50 ms. Jarvis Origin's own hook is in that chain and
contributes part of the figure, which is why the finding says so and tells you
to stop it and re-measure.

It also reads `LowLevelHooksTimeout`. Windows silently removes a hook that
takes longer than that to return, default 300 ms, so software wanting to keep a
slow hook alive has a motive to raise it. An unexplained increase is a finding.

### Keeping the hook up

The helper is Windows-side and does not survive a reboot, a WSL restart or
being killed — and anything that wants to drive this machine unseen has a
direct motive to kill it. So the daemon runs an `input_hook` watchdog every
45 seconds:

- **Liveness is the heartbeat, not the PID.** A hung hook still has a PID and a
  forged pid file still names one. Past 90 s without a heartbeat the watchdog
  crosses the interop boundary once to tell "process gone" (restart now) from
  "process alive, drain delayed by a slow collector" (wait); past ~210 s an
  alive-but-silent helper is treated as a removed hook and cycled.
- **Restarts back off exponentially** (20 s to 10 min) keyed to consecutive
  failures, so a crash loop cannot become a `powershell.exe` spawn loop.
- **Repeated failure is itself a finding.** More than four restarts in six
  hours is reported `high`: a security monitor that keeps dying is a detection,
  not an operational annoyance. Eight consecutive failed restarts is `critical`.
- **The helper only ever touches its own process.** It is staged and found as
  `jarvis-origin-inputhook.ps1`, so reconciliation can never match — and stop — a
  hook helper that belongs to another tool on the same machine.
- **The helper script is content-pinned.** A change to the trusted source is
  surfaced; a staged copy that does not match it aborts the restart rather than
  launching something unexpected.

The healthy path is local-only — drain the output file, check the heartbeat
age — so running it every 45 s costs about 25 ms and no interop round trip.

## Alerts: being told when it stops

The dashboard is only useful when you are looking at it. `jarvis-origin alert` adds an
outbound path for the findings that matter when you are not — a collector that
crashed, a monitor that stopped recording, anything `critical`.

It is off until you configure it, and it is the one component besides `intel`
that reaches the network on its own. It sends through [Resend](https://resend.com)
over HTTPS, standard library only. Put this in `~/.jarvis-origin/config.json` (kept
`0600`):

```json
{
  "resend_api_key": "re_...",
  "alert_from": "Jarvis Origin <jarvis-origin@yourdomain.com>",
  "alert_to": "you@example.com",
  "alert_min_severity": "high",
  "alert_resend_after": 21600,
  "alert_on_clear": true,
  "alert_hourly_cap": 12,
  "advisory_model": "gpt-5.6-luna",
  "openai_api_key": "sk-...",
  "intel_topics_per_run": 2,
  "intel_results_per_query": 6,
  "intel_lookback_days": 365,
  "daily_budget": 2.0
}
```

`alert_from` must be a sender Resend has verified for your domain; `alert_to`
takes a string or a list. The key may also come from `$JARVIS_ORIGIN_RESEND_KEY`, and
it is only ever sent in the `Authorization` header of the one request to
`api.resend.com` — never logged, never in the body.

Every finding has a stable key, so an alert pages you once when it fires, again
after `alert_resend_after` if it is *still* firing, and once when it clears —
not on every 45-second watchdog tick. Findings that mean "Jarvis Origin itself is not
watching something" page regardless of `alert_min_severity`, because a
monitoring gap is the one class of finding whose whole point is that nothing
else will tell you. `alert_hourly_cap` is a hard ceiling; anything past it is
suppressed and noted in the next mail.

Independently of event alerts, `jarvis-origin serve` sends a detailed security advisory
every five hours through the same configured Resend recipient. It reports which
collectors are current, stale, failing, or missing; ranks active findings by
severity; attaches a concrete safe next action where one is known; names
visibility gaps and design limits; and lists explicit clean/protected checks.
Volatile process command lines and peer details remain local rather than being
copied into routine email.

The HTML report is deterministic by default. For an additional evidence-bound
AI assessment, add paid OpenAI API credits and configure `advisory_model` plus
`openai_api_key` (or provide `JARVIS_ORIGIN_OPENAI_KEY` to the service). Jarvis Origin uses
the Responses API with storage disabled and sends only redacted findings—never
credential values or raw process command lines. If credits, model access, or
the API are unavailable, the report says so and the deterministic report still
sends. Exa breadth is separately bounded by `intel_topics_per_run`,
`intel_results_per_query`, `intel_lookback_days`, and the hard `daily_budget`.
Complete security cannot be guaranteed; each report distinguishes verified
controls from recommendations and blind spots.

```bash
jarvis-origin alert            # show configuration and any active alerts
jarvis-origin alert --test     # send a test message to the configured recipients
```

## Auditing the monitor itself

`jarvis-origin coverage` answers the question that decides what every other module's
silence is worth: *can this system currently see?*

The failure it exists to prevent has already happened here once. The daemon ran
for hours reporting every Windows collector as healthy while the interop socket
was dead — each job had a timestamp, each timestamp looked recent, and every one
of them was a stale snapshot being re-read. **A clean report and no report look
identical unless something is specifically checking.** So:

- a collector that has never produced a result is reported as *missing*, not
  clean;
- a result older than twice its own interval is *stale*, and stale is a failure;
- a check that could not run says so where its result would have been;
- degraded coverage names what specifically is invisible because of it — not
  "running unprivileged" but *which* checks that costs.

It also verifies the continuity chain end to end (service active, enabled,
linger on) and restates the limits that no amount of work here removes: this
samples rather than intercepts, it has no kernel component, and WSL is not a
security boundary.

## Security of the dashboard itself

Binding to `127.0.0.1` is **not** sufficient on its own. A page you visit can
point a hostname it controls at `127.0.0.1` (DNS rebinding); the browser then
treats it as same-origin with the dashboard and can read every response — which
for this tool is a complete map of the machine's processes and external peers.
So:

- the `Host` header is validated against an allowlist, which is what actually
  defeats rebinding;
- `/api/run` is POST-only and rejects cross-site requests via `Sec-Fetch-Site`;
- a strict CSP forbids the page from loading anything external.

## How it decides something is unauthorized

Two independent signals combine into one severity, which is what keeps a
baseline system from either screaming at every software update or going quiet
when something hides behind an approved name:

1. **Drift** — the process fingerprint (executable + normalized command line +
   user) is not in the approved baseline. A new invocation of `/usr/bin/tail`
   is logged quietly; a new binary running out of a home or temp directory is
   not.
2. **Traits** — what the process looks like regardless of the baseline:
   encoded command lines, `curl | sh` pipelines, execution from world-writable
   directories, a deleted executable still running, a name that doesn't match
   its binary, listening on all interfaces, egress to public IPs.

A trait on an approved process still gets flagged.

## What it does not do

- It is **not** a kernel-level EDR. It samples on an interval, so a process
  that starts and exits between passes is missed. For gap-free Linux execution
  logging, pair it with `auditd`.
- Without elevation, other users' command lines and protected-process
  identities are unreadable — `coverage` says so rather than reporting a clean
  result it can't actually see.
- WSL is not a security boundary. Anything in WSL can read and write `/mnt/c`,
  and the Windows side can see into WSL. Treat findings on either host as
  findings about one machine.
- It does not audit persistence or autostart locations, firewall and security
  posture, kernel integrity, memory, or credentials on disk. `gaps` lists the
  ATT&CK techniques current research raises that nothing here covers, so the
  boundary is stated rather than implied.
- A suspicious process is shown on the dashboard but does not send an email on
  its own; a match against a known indicator (`hunt`) does.


## Files

```
jarvis_origin/
  cli.py            command line
  server.py         scheduler (one worker, per-job intervals) + loopback dashboard
  store.py          SQLite (WAL) — baseline, peers, snapshots, indicators
  monitor.py        process + connection sampling;  detect.py  suspicious traits
  collect_linux.py  /proc;  collect_windows.py  powershell.exe over WSL interop
  resourcewatch.py  CPU / memory pressure and the processes behind it
  inputwatch.py     injected-input monitor;  win/inputhook.ps1  the hook helper
  intel.py          research knowledge base;  feeds.py  bulk public feeds
  vet.py            the gate every indicator passes before it is stored
  hunt.py           indicators vs this machine, and the ATT&CK gap report
  coverage.py       self-audit: freshness, blind spots, stated limits
  alert.py          email alerts and the five-hourly advisory;  fixit.py  safe next steps
  static/dashboard.html   the whole UI, one self-contained file
tests/              python3 -m unittest discover -s tests
```

## Contributing and licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions
are welcome under the Developer Certificate of Origin; see
[CONTRIBUTING.md](CONTRIBUTING.md). Please report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

The public feeds and APIs Jarvis Origin can query are downloaded at run time on
your machine and are governed by their publishers' own terms; check them before
any commercial use.

---

Jarvis Origin is maintained by the makers of ARGUS-1. It is the starting point,
not the product: ARGUS-1 is developed separately and is not open source.
