"""Threat intelligence acquisition: turn published security research into
candidate indicators this machine can actually check.

The pipeline is deliberately one-directional and lossy:

    Exa search  ->  structured extraction  ->  vet.py  ->  indicators table
                                                  |
                                            most things die here

What survives is never authoritative. An indicator is a reason to go and look
at something, evaluated against the live system by hunt.py. Nothing fetched is
executed, and nothing fetched can clear an existing finding — see vet.py for
why that invariant is the whole design.

Two things dominate output quality, in this order:

  1. **Which sources are searched.** An early test run without a source
     allowlist returned a 2007 academic paper on registry forensics as the top
     hit for a Linux rootkit query. The allowlist below is the single highest
     leverage knob in this file.
  2. **What the extraction is told to refuse.** Language models fill empty
     fields with plausible filler: `evil.com`, `192.168.1.100`, and the SHA-256
     of the empty string all arrived from one real article. The prompt spends
     most of its length on refusal rules for that reason.
"""

import json
import os
import stat
import time
import urllib.error
import urllib.request

from . import vet
from .util import now

API_URL = "https://api.exa.ai/search"
CONFIG_PATH = os.path.expanduser("~/.jarvis-origin/config.json")

# Publishers that do primary host-based threat research and publish concrete
# artefacts rather than commentary. Anything outside this list is not searched:
# the goal is indicators for a specific machine, not security news.
SOURCES = [
    "elastic.co", "research.intezer.com", "unit42.paloaltonetworks.com",
    "securelist.com", "welivesecurity.com", "blog.talosintelligence.com",
    "sysdig.com", "thedfirreport.com", "redcanary.com", "huntress.com",
    "volexity.com", "sentinelone.com", "cloud.google.com", "aquasec.com",
    "securitylabs.datadoghq.com", "microsoft.com", "crowdstrike.com",
    "trendmicro.com", "research.checkpoint.com", "blog.sekoia.io",
    "zscaler.com", "proofpoint.com", "cybereason.com", "wiz.io",
    "objective-see.org", "jpcert.or.jp", "cisa.gov", "attack.mitre.org",
    "malwarebytes.com", "sophos.com", "group-ib.com", "socradar.io",
    "bitdefender.com", "fortinet.com", "splunk.com", "binarly.io",
    "eclypsium.com", "orca.security", "snyk.io", "socket.dev",
    "securityintelligence.com", "research.nccgroup.com", "labs.withsecure.com",
    "rapid7.com", "reversinglabs.com", "lab52.io", "team-cymru.com",
    "blog.qualys.com", "akamai.com", "varonis.com", "esentire.com",
    "expel.com", "dragos.com", "sigmahq.io", "abuse.ch", "netskope.com",
    "arcticwolf.com", "kroll.com", "secureworks.com", "hunt.io",
]

# The corpus is grouped so a refresh can run one topic at a time and keep the
# per-run cost bounded. Queries are phrased as descriptions of the document
# wanted, which is what Exa's neural index is built to match — not keywords.
CORPUS = {
    "linux-malware": [
        "technical analysis of new Linux malware with indicators of compromise and persistence details",
        "Linux rootkit using eBPF or loadable kernel module to hide processes, with detection guidance",
        "Linux persistence via systemd unit, cron, or shared library preloading observed in the wild",
        "malware abusing memfd_create or fileless in-memory execution on Linux",
    ],
    "windows-malware": [
        "Windows malware technical analysis with registry persistence keys and file paths",
        "Windows scheduled task and service persistence used by a named threat actor",
        "bring your own vulnerable driver attack technical breakdown with driver names",
        "NTFS alternate data stream and COM hijacking persistence observed in intrusions",
    ],
    "spyware": [
        "commercial spyware or stalkerware technical analysis with host artifacts",
        "infostealer malware analysis listing browser credential theft file paths",
        "keylogger and screen capture malware technical indicators of compromise",
        "remote access trojan analysis with command and control infrastructure details",
    ],
    "infiltration": [
        "initial access technique analysis phishing to code execution with artifacts",
        "supply chain compromise of npm or PyPI package with malicious payload analysis",
        "living off the land binary abuse for execution and defense evasion",
        "credential theft and lateral movement techniques observed in real intrusions",
    ],
    "forensics": [
        "digital forensics incident response artifacts for detecting host compromise",
        "Windows event log and prefetch forensic artifacts proving execution",
        "Linux forensic triage of a compromised host what artifacts to collect",
        "anti-forensics and log tampering techniques used by intruders",
    ],
    "offensive": [
        "penetration testing tradecraft and command and control framework detection",
        "red team persistence tradecraft and the artifacts it leaves behind",
        "post exploitation tooling analysis with host-based detection opportunities",
    ],
    "wsl-and-dev": [
        "attacks abusing Windows Subsystem for Linux for evasion and persistence",
        "malware targeting developer workstations source code and CI credentials",
        "malicious VSCode extension or IDE plugin analysis with indicators",
        "container escape and Docker socket abuse technical analysis",
    ],
    "exploited": [
        "actively exploited vulnerability with observed in the wild exploitation artifacts",
        "CISA known exploited vulnerability technical analysis and detection",
    ],
    "ransomware": [
        "ransomware technical analysis with encryption routine and host artifacts",
        "ransomware affiliate intrusion timeline from initial access to deployment",
        "data extortion group tradecraft and staging tooling analysis",
    ],
    "apt-tradecraft": [
        "nation state threat actor campaign technical analysis with host indicators",
        "espionage implant technical breakdown with persistence and C2 details",
        "threat actor tooling overlap and infrastructure analysis report",
    ],
    "c2-frameworks": [
        "command and control framework beacon analysis and host-based detection",
        "Cobalt Strike Sliver or Mythic implant artifacts and detection guidance",
        "malleable C2 profile and traffic detection engineering analysis",
    ],
    "credential-theft": [
        "credential dumping technique analysis with artifacts and detection",
        "browser cookie and session token theft malware technical analysis",
        "cloud credential and API token theft from developer machines",
        "SSH key and CI secret theft technique analysis",
    ],
    "cloud-container": [
        "container escape and Kubernetes attack technical analysis with artifacts",
        "cloud instance metadata service abuse and credential theft analysis",
        "malicious container image and registry supply chain analysis",
    ],
    "firmware-hardware": [
        "UEFI bootkit or firmware implant technical analysis with detection",
        "malicious signed driver and rootkit loading technique analysis",
        "hardware implant and peripheral attack technical research",
    ],
    "browser-attacks": [
        "malicious browser extension technical analysis with permissions and indicators",
        "browser exploitation and drive-by compromise technical breakdown",
        "clipboard hijacking and browser injection malware analysis",
    ],
    "detection-engineering": [
        "detection engineering rules Sigma or YARA for recent malware family",
        "hunting queries and behavioural detection logic for persistence techniques",
        "EDR telemetry analysis and detection opportunities for evasive malware",
    ],
    "mercenary-spyware": [
        "mercenary spyware forensic analysis with indicators of compromise and infrastructure",
        "Pegasus NSO Group forensic traces process names and network indicators",
        "Candiru DevilsTongue Windows spyware technical analysis with artifacts",
        "FinFisher FinSpy implant technical analysis persistence and C2",
        "Predator Intellexa spyware infrastructure domains and addresses",
        "commercial surveillance vendor implant technical breakdown host artifacts",
        "zero-click exploit chain forensic artifacts left on the device",
        "state sponsored surveillance implant network infrastructure attribution",
        "spyware validator server and anonymised infrastructure IP analysis",
        "forensic methodology for detecting targeted surveillance on a workstation",
    ],
    "backdoors": [
        "SSH backdoor authorized_keys and sshd configuration tampering analysis",
        "web shell and server backdoor technical analysis with detection",
        "reverse shell persistence in shell profile cron or systemd analysis",
        "OpenSSH and PAM backdoor implant technical breakdown",
        "setuid binary and sudoers backdoor privilege persistence analysis",
        "hidden local account and rogue administrator creation detection",
        "backdoored package or dependency with malicious postinstall analysis",
        "firmware and bootloader backdoor persistence technical analysis",
    ],
    "wireless": [
        "rogue access point evil twin attack detection and artifacts",
        "wifi deauthentication attack and forced reconnection technique analysis",
        "ARP spoofing and gateway impersonation detection on a workstation",
        "captive portal and DNS hijack man in the middle wireless attack",
    ],
    "memory-forensics": [
        "detecting unbacked executable memory and reflective DLL injection on Windows",
        "userland API hooking detection comparing ntdll in memory against disk",
        "direct and indirect syscall invocation used to bypass EDR hooks",
        "shellcode detection in process memory technical analysis",
        "process hollowing and module stomping detection technique",
        "memory forensics triage of a live Windows host for injected code",
        "detecting manual mapping and module overwriting by implants",
    ],
    "exploit-mitigations": [
        "Windows process mitigation policies CFG ACG CET shadow stack bypass",
        "control flow integrity and shadow stack enforcement on Windows workstations",
        "SMEP SMAP and hardware exploit mitigation verification techniques",
        "kernel exploit primitives and mitigation bypass technical analysis",
    ],
    "input-injection": [
        "malware using SendInput or keybd_event to drive the user interface",
        "detecting synthetic keystroke injection and UI automation abuse",
        "HID emulation BadUSB attack detection and host artifacts",
    ],
    "interception": [
        "TLS interception rogue root certificate installed by malware analysis",
        "malware modifying proxy settings PAC file or WPAD for traffic interception",
        "port forwarding tunnelling and firewall bypass technique analysis",
        "network boundary bypass via portproxy or filtering platform filters",
        "DNS hijacking and hosts file modification by implants",
    ],
    "network-attacks": [
        "lateral movement and network protocol abuse technical analysis",
        "DNS tunnelling and covert channel exfiltration technique analysis",
        "edge device and VPN appliance compromise technical analysis",
    ],
}

# ── The extraction prompt ─────────────────────────────────────────────────
#
# Every rule here exists because its absence produced a specific bad result in
# testing. Notably: naming the target platform in the prompt caused the model
# to echo "Windows 11 workstation with WSL2" back as extracted data, so the
# prompt now says nothing about the machine it defends.
EXTRACTION_PROMPT = """\
You are extracting host-based detection content from a security research \
article for an automated defensive agent. The output is machine-consumed. \
Precision matters far more than recall: a wrong indicator causes a false alarm \
on a production workstation, while a missing one costs nothing.

COPY, DO NOT COMPOSE. Every value must appear verbatim in the article. Do not \
infer, generalise, normalise, complete, or reconstruct any value. If you are \
recalling it from knowledge of this malware family rather than reading it in \
this text, omit it.

OMIT ANY VALUE THAT IS NOT A REAL OBSERVED ARTEFACT. Specifically omit: \
redacted or partially redacted values, anything containing angle brackets or \
ellipses, illustrative examples such as evil.com or example.com, RFC1918 and \
loopback addresses used in lab writeups, and digests of empty or placeholder \
input. An empty array is a correct and expected answer. Never fill a field to \
avoid leaving it empty.

SEPARATE ATTACKER ARTEFACTS FROM ABUSED LEGITIMATE ONES. A path, process, or \
key only belongs in an attacker_* field if the article says the attacker \
created, dropped, or controls it. If the article describes the attacker abusing \
software that is legitimately present on a normal system - a debugger, a shell, \
a signed system binary, a package manager - put its name in abused_legitimate \
and nowhere else. This distinction is critical: the consuming system treats \
attacker_* values as things that should not exist on a clean machine.

REFANG defanged notation: evil[.]com becomes evil.com, hxxp becomes http.

EXCLUDE the publishing vendor's own domains, cited reference links, social \
media links, and any infrastructure belonging to the researchers.

PREFER SPECIFICITY. A full absolute path is worth more than a bare filename. A \
full registry path is worth more than a hive name. If only a vague reference \
exists, omit it rather than guessing the rest.

If the article is not primary threat research containing concrete artefacts - \
if it is a product announcement, an opinion piece, a conference recap, or a \
listing page - set is_threat_research to false and leave every array empty.\
"""

EXTRACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "is_threat_research": {
            "type": "boolean",
            "description": "True only for primary research containing concrete artefacts.",
        },
        "threat_name": {
            "type": "string",
            "description": "Malware family, tool, or campaign name as written. Empty if unnamed.",
        },
        "platforms": {
            "type": "array", "items": {"type": "string"},
            "description": "Operating systems the article says are affected.",
        },
        "attack_technique_ids": {
            "type": "array", "items": {"type": "string"},
            "description": "MITRE ATT&CK technique IDs stated in the article, e.g. T1053.005.",
        },
        "attacker_file_paths": {
            "type": "array", "items": {"type": "string"},
            "description": "Absolute paths the attacker created or dropped.",
        },
        "attacker_process_names": {
            "type": "array", "items": {"type": "string"},
            "description": "Names of attacker-controlled binaries or services.",
        },
        "registry_keys": {
            "type": "array", "items": {"type": "string"},
            "description": "Full registry paths the attacker created or modified.",
        },
        "domains": {
            "type": "array", "items": {"type": "string"},
            "description": "Attacker-controlled domains, refanged.",
        },
        "ipv4": {
            "type": "array", "items": {"type": "string"},
            "description": "Attacker-controlled IPv4 addresses, refanged.",
        },
        "sha256": {
            "type": "array", "items": {"type": "string"},
            "description": "SHA-256 digests of attacker samples. Omit other hash lengths.",
        },
        "cves": {
            "type": "array", "items": {"type": "string"},
            "description": "CVE identifiers the article says were exploited.",
        },
        "abused_legitimate": {
            "type": "array", "items": {"type": "string"},
            "description": "Legitimate software the attacker abused rather than installed.",
        },
        "persistence_mechanisms": {
            "type": "array", "items": {"type": "string"},
            "description": "One short phrase per mechanism describing how it survives reboot.",
        },
        "detection_guidance": {
            "type": "array", "items": {"type": "string"},
            "description": "Concrete, checkable detection advice. One idea per string.",
        },
    },
    "required": ["is_threat_research"],
}

# Which schema field feeds which indicator kind in the store.
FIELD_KINDS = {
    "attacker_file_paths": "path",
    "attacker_process_names": "process",
    "registry_keys": "regkey",
    "domains": "domain",
    "ipv4": "ipv4",
    "sha256": "sha256",
    "attack_technique_ids": "attack",
    "cves": "cve",
}


class IntelError(RuntimeError):
    pass


class BudgetExceeded(IntelError):
    pass


# A metered API on a 24/7 timer is a standing invitation to a surprise bill, so
# spend is capped per day and the cap is enforced before each query rather than
# reported after the fact.
DEFAULT_DAILY_BUDGET = 0.50


def _today():
    return time.strftime("%Y%m%d")


def daily_budget():
    try:
        with open(CONFIG_PATH) as fh:
            return float(json.load(fh).get("daily_budget", DEFAULT_DAILY_BUDGET))
    except (OSError, ValueError, TypeError):
        return DEFAULT_DAILY_BUDGET


def spent_today(store):
    return float(store.get_meta(f"intel_spend_{_today()}", 0) or 0)


def _charge(store, amount):
    key = f"intel_spend_{_today()}"
    store.set_meta(key, round(spent_today(store) + float(amount or 0), 4))


# ── credentials ───────────────────────────────────────────────────────────

def load_key():
    """API key from the environment, else from a 0600 file outside the repo.

    The repository is public. The key never goes in a tracked file, and the
    config lives beside the database in ~/.jarvis-origin rather than in the checkout.
    """
    env = os.environ.get("JARVIS_ORIGIN_EXA_KEY", "").strip()
    if env:
        return env
    try:
        with open(CONFIG_PATH) as fh:
            return (json.load(fh).get("exa_api_key") or "").strip()
    except (OSError, ValueError):
        return ""


def save_key(key):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    cfg = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as fh:
                cfg = json.load(fh)
        except ValueError:
            cfg = {}
    cfg["exa_api_key"] = key.strip()
    fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    return CONFIG_PATH


# ── transport ─────────────────────────────────────────────────────────────

def _post(payload, key, timeout=90):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        API_URL, data=body, method="POST",
        headers={"x-api-key": key, "Content-Type": "application/json",
                 "User-Agent": "jarvis-origin-intel/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise IntelError(f"HTTP {exc.code}: {detail}") from None
    except urllib.error.URLError as exc:
        raise IntelError(f"network error: {exc.reason}") from None
    except (TimeoutError, OSError) as exc:
        raise IntelError(f"request failed: {exc}") from None


def search(query, key, num_results=6, days=365, domains=None):
    """One Exa search with structured extraction attached to every result."""
    start = time.strftime(
        "%Y-%m-%dT00:00:00.000Z", time.gmtime(time.time() - days * 86400))
    payload = {
        "query": query,
        "type": "auto",
        "numResults": max(1, min(int(num_results), 25)),
        "startPublishedDate": start,
        "includeDomains": domains if domains is not None else SOURCES,
        "contents": {
            "summary": {"query": EXTRACTION_PROMPT, "schema": EXTRACTION_SCHEMA},
        },
    }
    return _post(payload, key)


# ── ingestion ─────────────────────────────────────────────────────────────

def _parse_summary(raw):
    """Extraction comes back as a JSON string. Anything else is discarded."""
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def _as_list(value):
    """Fields come back as null, a string, or a list depending on the article."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str) and v.strip()]
    return []


def ingest_result(store, result, topic, query, stats):
    """Vet one article's extraction and fold the survivors into the store."""
    url = (result.get("url") or "").strip()
    if not url:
        return 0
    data = _parse_summary(result.get("summary"))
    if not data:
        stats["unparsed"] += 1
        return 0
    if not data.get("is_threat_research"):
        stats["not_research"] += 1
        return 0

    ts = now()
    threat = (data.get("threat_name") or "").strip()[:120]
    context_bits = _as_list(data.get("persistence_mechanisms"))[:2]
    context = (threat + (" — " if threat and context_bits else "")
               + "; ".join(context_bits))[:400]

    kept = 0
    for field, kind in FIELD_KINDS.items():
        for raw in _as_list(data.get(field))[:60]:
            k = kind
            # A ".so"/".ko" named as a process is really a file to hunt for,
            # not a process to match — reroute rather than discard it.
            if kind == "process" and raw.strip().lower().endswith(
                    (".so", ".ko", ".dll", ".dylib")):
                k = "filename"
            norm, why = vet.vet(k, raw)
            stats["seen"] += 1
            if not norm:
                stats["rejected"] += 1
                stats["reasons"][why] = stats["reasons"].get(why, 0) + 1
                continue
            # ATT&CK ids and CVEs describe technique, not attacker
            # infrastructure, so they are always safe to keep at high
            # confidence. Everything else starts as a lead, not a verdict.
            conf = "high" if k in ("attack", "cve", "sha256") else "medium"
            store.db.execute(
                """INSERT INTO indicators(kind,value,norm,confidence,topic,
                                          context,source_url,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(kind,norm) DO UPDATE SET
                       last_seen=excluded.last_seen,
                       doc_count=indicators.doc_count+1""",
                (k, raw[:512], norm, conf, topic, context, url, ts, ts),
            )
            kept += 1
            stats["kept"] += 1

    store.db.execute(
        """INSERT INTO intel_docs(url,title,published,topic,query,fetched_at,
                                  text_len,n_indicators)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(url) DO UPDATE SET
               fetched_at=excluded.fetched_at,
               n_indicators=excluded.n_indicators""",
        (url, (result.get("title") or "")[:300],
         (result.get("publishedDate") or "")[:32], topic, query[:300],
         ts, len(result.get("text") or ""), kept),
    )
    stats["docs"] += 1
    return kept


def refresh(store, topics=None, per_query=6, days=365, key=None, on_progress=None):
    """Run part of the corpus and ingest what comes back.

    Defaults to a single topic per call so the daemon spreads cost over time
    rather than spending the whole corpus in one burst.
    """
    key = key or load_key()
    if not key:
        raise IntelError(
            "no Exa API key configured — run: jarvis-origin intel --set-key <key>")

    budget = daily_budget()
    already = spent_today(store)
    if already >= budget:
        raise BudgetExceeded(
            f"daily API budget reached (${already:.3f} of ${budget:.2f}) — "
            f"raise `daily_budget` in {CONFIG_PATH} or wait for tomorrow")

    names = list(topics) if topics else [_next_topic(store)]
    stats = {"seen": 0, "kept": 0, "rejected": 0, "docs": 0, "unparsed": 0,
             "not_research": 0, "queries": 0, "errors": [], "cost": 0.0,
             "reasons": {}, "topics": names}

    for topic in names:
        for query in CORPUS.get(topic, []):
            if on_progress:
                on_progress(topic, query)
            if spent_today(store) >= budget:
                stats["errors"].append(
                    f"stopped early: daily budget ${budget:.2f} reached")
                break
            try:
                res = search(query, key, num_results=per_query, days=days)
            except IntelError as exc:
                stats["errors"].append(f"{topic}: {exc}")
                continue
            stats["queries"] += 1
            cost = float((res.get("costDollars") or {}).get("total") or 0.0)
            stats["cost"] += cost
            _charge(store, cost)
            for result in res.get("results", []):
                ingest_result(store, result, topic, query, stats)
            store.commit()
        store.set_meta(f"intel_topic_{topic}", now())

    store.set_meta("intel_last_refresh", now())
    store.set_meta("intel_spend_total",
                   round(float(store.get_meta("intel_spend_total", 0) or 0)
                         + stats["cost"], 4))
    store.commit()
    return stats


def daemon_options(store):
    """Bounded Exa breadth for unattended refreshes.

    The daily dollar brake remains authoritative. These knobs let a user buy
    broader/fresher intelligence without changing code or allowing an
    unbounded scheduled search.
    """
    try:
        with open(CONFIG_PATH) as fh:
            conf = json.load(fh) or {}
    except (OSError, ValueError):
        conf = {}
    try:
        topic_count = max(1, min(int(conf.get("intel_topics_per_run", 2)), 6))
    except (TypeError, ValueError):
        topic_count = 2
    try:
        results = max(1, min(int(conf.get("intel_results_per_query", 6)), 25))
    except (TypeError, ValueError):
        results = 6
    try:
        days = max(7, min(int(conf.get("intel_lookback_days", 365)), 1825))
    except (TypeError, ValueError):
        days = 365
    ages = []
    for topic in CORPUS:
        last = int(store.get_meta(f"intel_topic_{topic}", 0) or 0)
        ages.append((last, topic))
    ages.sort()
    return {
        "topics": [topic for _last, topic in ages[:topic_count]],
        "per_query": results,
        "days": days,
    }


def _next_topic(store):
    """Least recently refreshed topic, so the corpus rotates on its own."""
    ages = []
    for topic in CORPUS:
        last = int(store.get_meta(f"intel_topic_{topic}", 0) or 0)
        ages.append((last, topic))
    ages.sort()
    return ages[0][1]


def revet(store):
    """Re-judge every stored indicator against the current rules.

    The gate gets tighter as bad extractions are found. Without this, the first
    poisoned batch stays live forever and the knowledge base is only ever as
    good as the rules on the day it was fetched.
    """
    stats = {"checked": 0, "dropped": 0, "moved": 0, "reasons": {}}
    rows = store.db.execute(
        "SELECT id, kind, value, norm, status FROM indicators").fetchall()
    for r in rows:
        stats["checked"] += 1
        kind = r["kind"]
        raw = r["value"]
        if kind == "process" and raw.strip().lower().endswith(
                (".so", ".ko", ".dll", ".dylib")):
            kind = "filename"
        norm, why = vet.vet(kind, raw)
        if not norm:
            if r["status"] != "rejected":
                store.db.execute(
                    "UPDATE indicators SET status='rejected' WHERE id=?", (r["id"],))
                stats["dropped"] += 1
                stats["reasons"][why] = stats["reasons"].get(why, 0) + 1
            continue
        if kind != r["kind"] or norm != r["norm"]:
            # Moving a row can collide with an existing one; drop it if so.
            try:
                store.db.execute(
                    "UPDATE indicators SET kind=?, norm=?, status='active' WHERE id=?",
                    (kind, norm, r["id"]))
                stats["moved"] += 1
            except Exception:
                store.db.execute("DELETE FROM indicators WHERE id=?", (r["id"],))
        elif r["status"] == "rejected":
            store.db.execute(
                "UPDATE indicators SET status='active' WHERE id=?", (r["id"],))
    store.commit()
    return stats


def summary(store):
    """What the knowledge base currently holds."""
    rows = store.db.execute(
        "SELECT kind, COUNT(*) n FROM indicators WHERE status='active' "
        "GROUP BY kind ORDER BY n DESC").fetchall()
    docs = store.db.execute("SELECT COUNT(*) n FROM intel_docs").fetchone()["n"]
    return {
        "docs": docs,
        "by_kind": {r["kind"]: r["n"] for r in rows},
        "total": sum(r["n"] for r in rows),
        "last_refresh": int(store.get_meta("intel_last_refresh", 0) or 0),
        "spend": float(store.get_meta("intel_spend_total", 0) or 0),
        "spend_today": spent_today(store),
        "budget": daily_budget(),
    }
