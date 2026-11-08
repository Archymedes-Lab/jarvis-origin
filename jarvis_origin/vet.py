"""The gate between what the internet says and what this machine acts on.

Threat intelligence arrives as prose written by strangers and is summarised by
a language model. Both halves of that pipeline are wrong sometimes, and they
are wrong in a specific, dangerous direction: they produce indicators that look
exactly like real ones.

A single observed extraction returned `evil.com`, `192.168.1.100`, `gdb`,
`strace`, bare `/tmp/`, and two "SHA-256" values that are the digests of the
empty string. Every one of those is syntactically perfect. Loaded into a
detection engine on a developer's workstation, that one article would flag the
debugger on every use and pin a permanent alert on a directory that is supposed
to be full of files.

So nothing extracted is trusted. Every candidate passes through here first, and
this module is deliberately the least clever code in the project: no network,
no model, no heuristics that "learn". Just explicit rules about what cannot
possibly be a useful indicator on this machine.

Two invariants hold everywhere downstream:

  * Intel may only ever ADD suspicion. No fetched content can approve a
    process, clear a finding, or lower a severity. The worst a poisoned feed
    can do is waste your attention; it can never create a blind spot.
  * Nothing fetched is ever executed, interpolated into a shell, or used as a
    path to open. Indicators are compared as data and only as data.
"""

import ipaddress
import re

# Digests of empty or trivial input. These appear constantly in generated
# output as filler and would otherwise match any zero-length file on disk.
JUNK_DIGESTS = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256("")
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                          # sha1("")
    "d41d8cd98f00b204e9800998ecf8427e",                                  # md5("")
    "0000000000000000000000000000000000000000000000000000000000000000",
}

# Text that marks a value as redacted, templated, or illustrative rather than
# observed. Any of these anywhere in a value disqualifies it outright.
PLACEHOLDER_MARKS = (
    "<", ">", "redacted", "example", "placeholder", "your", "sample",
    "xxx", "...", "[pid]", "{", "}", "n/a", "todo", "insert", "attacker",
    "malicious-", "victim", "changeme", "foo", "bar", "abcd1234",
)

# Domains that exist to be examples, plus the publishers whose own links
# saturate every writeup they appear in.
DOMAIN_DENY = {
    "example.com", "example.org", "example.net", "evil.com", "bad.com",
    "malicious.com", "attacker.com", "c2.com", "test.com", "domain.com",
    "localhost", "yourdomain.com", "company.com", "contoso.com",
    # Security publishers and infrastructure — cited, never the threat.
    "elastic.co", "intezer.com", "paloaltonetworks.com", "securelist.com",
    "welivesecurity.com", "talosintelligence.com", "sysdig.com",
    "thedfirreport.com", "redcanary.com", "huntress.com", "volexity.com",
    "sentinelone.com", "crowdstrike.com", "mandiant.com", "aquasec.com",
    "datadoghq.com", "microsoft.com", "google.com", "github.com",
    "virustotal.com", "mitre.org", "attack.mitre.org", "cisa.gov",
    "twitter.com", "x.com", "linkedin.com", "youtube.com", "medium.com",
    "wikipedia.org", "cloudflare.com", "amazonaws.com", "akamai.net",
    "trendmicro.com", "kaspersky.com", "eset.com", "sophos.com",
    "checkpoint.com", "proofpoint.com", "zscaler.com", "wiz.io",
    "cybereason.com", "malwarebytes.com", "sekoia.io", "group-ib.com",
    "objective-see.org", "recordedfuture.com", "splunk.com", "fortinet.com",
    "securityintelligence.com", "nccgroup.com", "withsecure.com", "rapid7.com",
    "reversinglabs.com", "lab52.io", "team-cymru.com", "qualys.com",
    "akamai.com", "varonis.com", "esentire.com", "expel.com", "dragos.com",
    "sigmahq.io", "abuse.ch", "netskope.com", "arcticwolf.com", "kroll.com",
    "secureworks.com", "hunt.io", "binarly.io", "eclypsium.com", "snyk.io",
    "socket.dev", "orca.security", "socradar.io", "bitdefender.com",
    "jpcert.or.jp", "ibm.com", "vmware.com", "oracle.com", "apple.com",
    "mozilla.org", "debian.org", "ubuntu.com", "kernel.org", "python.org",
    "npmjs.com", "pypi.org", "docker.com", "kubernetes.io", "openai.com",
    "anthropic.com", "chatgpt.com", "claude.ai", "netmon.azure.com",
    "cloudflare-dns.com", "slack.com", "atlassian.com", "gitlab.com",
}

DOMAIN_DENY_TLD = {"example", "test", "invalid", "localhost", "local", "internal", "arpa"}

# Public "what is my IP" and geolocation services. Malware calls these to work
# out where it landed, so they show up throughout detection rules as suspicious
# network connections — but a package manager, a VPN client, a CI runner and
# half of npm call them too. On a developer workstation a match here proves
# nothing, and the alert would fire forever.
DUAL_USE_DOMAINS = {
    "ipify.org", "api.ipify.org", "ip-api.com", "edns.ip-api.com", "ipinfo.io",
    "icanhazip.com", "ifconfig.me", "ifconfig.co", "ipecho.net", "eth0.me",
    "checkip.dyndns.org", "dyndns.org", "curlmyip.com", "freegeoip.app",
    "db-ip.com", "bigdatacloud.net", "api.bigdatacloud.net", "geoipy.com",
    "getip.pro", "2ip.ua", "api.2ip.ua", "canireachthe.net", "seeip.org",
    "myexternalip.com", "wtfismyip.com", "ipapi.co", "ipwhois.io", "ident.me",
    "whatismyipaddress.com", "api.myip.com", "ipconfig.io", "ipv4.icanhazip.com",
    "checkip.amazonaws.com", "ipv6.icanhazip.com", "ip.sb", "myip.com",
}

# Package registries and their CDNs. These appear throughout URLhaus and
# ThreatFox because attackers genuinely host payloads on them — but the
# hostname is identical for every user on earth, so matching it flags every
# `npm install`, `pip install` and `go get`. The first Sysmon run produced five
# criticals and every one was a package registry.
#
# This is a different case from SHARED_HOSTING below, where the *subdomain* is
# per-tenant and therefore specific: `x7f2q.trycloudflare.com` identifies one
# tunnel, while `raw.githubusercontent.com` identifies nobody. So these are
# denied along with their subdomains.
PACKAGE_INFRA = {
    "githubusercontent.com", "codeload.github.com", "github.com",
    "registry.npmjs.org", "registry.yarnpkg.com", "npmjs.org", "npmjs.com",
    "pythonhosted.org", "pypi.org", "pypi.python.org",
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "jsdelivr.com",
    "crates.io", "static.crates.io", "proxy.golang.org", "sum.golang.org",
    "ghcr.io", "docker.io", "docker.com", "quay.io", "gcr.io",
    "packages.microsoft.com", "archive.ubuntu.com", "security.ubuntu.com",
    "deb.debian.org", "ppa.launchpad.net", "rubygems.org", "nuget.org",
    "maven.apache.org", "repo1.maven.org", "packagist.org", "hex.pm",
    "goproxy.io", "sourceforge.net", "fastly.net", "jsdelivr.b-cdn.net",
    "objects.githubusercontent.com", "release-assets.githubusercontent.com",
    "raw.githubusercontent.com", "files.pythonhosted.org",
    "huggingface.co", "cdn-lfs.huggingface.co", "ollama.com", "ollama.ai",
}

# Shared hosting, CDNs and tunnels. These are denied as an EXACT match only,
# never as a parent of their subdomains — the distinction matters because
# `trycloudflare.com` is not an indicator but `x7f2q.trycloudflare.com` is a
# specific tunnel, and blanket-denying the parent would throw away a whole
# class of real C2 while blanket-allowing it would flag every Discord upload.
SHARED_HOSTING = {
    "cloudfront.net", "blogspot.com", "wordpress.com", "weebly.com",
    "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "azurewebsites.net", "sharepoint.com", "firebaseapp.com",
    "firebasestorage.googleapis.com", "storage.googleapis.com",
    "discordapp.com", "discord.com", "t.me", "telegram.me", "bit.ly",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org",
    "no-ip.com", "ddns.net", "glitch.me", "repl.co", "surge.sh",
    "githubusercontent.com", "gitlab.io", "github.io", "s3.amazonaws.com",
    "dropbox.com", "onedrive.live.com", "drive.google.com", "mediafire.com",
}

# Programs a developer runs on purpose. Threat writeups name these constantly,
# because attackers abuse them — but on this machine their presence is not
# evidence of anything, and alerting on them trains the operator to ignore the
# tool. Abuse of these is what the trait rules in detect.py are for.
PROCESS_DENY = {
    # shells and core userland
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "busybox",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "conhost.exe", "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe",
    "services.exe", "winlogon.exe", "wininit.exe", "dllhost.exe", "rundll32",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "systemd", "init", "kthreadd", "kworker", "cron", "crond", "dbus-daemon",
    "sshd", "ssh", "su", "sudo", "login", "agetty", "dhclient", "rsyslogd",
    # interpreters and runtimes
    "python", "python3", "python.exe", "perl", "ruby", "node", "node.exe",
    "java", "java.exe", "php", "lua", "deno", "bun", "go", "dotnet",
    # developer tooling — the class that burned us in testing
    "gdb", "lldb", "strace", "ltrace", "ptrace", "objdump", "readelf", "nm",
    "git", "make", "cmake", "gcc", "g++", "clang", "ld", "as", "cargo",
    "rustc", "npm", "npx", "yarn", "pnpm", "pip", "pip3", "docker", "podman",
    "kubectl", "code", "code.exe", "vim", "nvim", "nano", "emacs",
    "curl", "wget", "tar", "gzip", "unzip", "openssl", "nc", "socat",
    "ps", "top", "htop", "ls", "cat", "grep", "awk", "sed", "find", "which",
    "frida", "frida-agent", "frida-gadget", "frida-server",
    # this machine's own furniture
    "jarvis-origin", "claude", "codex", "firefox.exe", "msedge.exe", "chrome.exe",
    "ollama", "ollama.exe", "wsl.exe", "wslservice.exe", "onedrive.exe",
    "chrome", "chromium", "firefox", "msedge", "brave", "opera", "safari",
    "systemctl", "journalctl", "unshare", "nsenter", "setsid", "runc",
    "containerd", "dockerd", "snapd", "packagekitd", "gnome-shell", "Xorg",
    "puppeteer", "playwright", "electron", "webpack", "esbuild", "vite",
}

# Kernel and pseudo-filesystem interfaces. Real malware touches these, but so
# does every process on the system, so their presence proves nothing.
PATH_DENY_PREFIX = (
    "/proc/", "/sys/", "/dev/pts/", "/dev/null", "/dev/zero", "/dev/random",
    "/dev/urandom", "/run/user/", "/run/systemd/", "/run/lock/", "/var/run/",
    "/run/docker.sock", "/var/lib/docker/", "/etc/passwd", "/etc/shadow",
    "/etc/hosts", "/etc/resolv.conf", "/etc/fstab", "/etc/ld.so.cache",
)

# Where installed software legitimately lives. An indicator pointing here is
# either a false positive or an attacker replacing a system binary — and the
# latter is a job for integrity checking, not for string matching a path that
# is supposed to exist.
PATH_DENY_TRUSTED = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/",
    "/usr/share/", "/usr/local/lib/", "/etc/ssl/", "/var/log/",
    "c:/windows/system32/", "c:/windows/syswow64/", "c:/program files/",
    "c:/program files (x86)/",
)

# Extensions that carry code or declare a persistence unit. A full path ending
# in one of these is worth matching even inside a trusted directory: the
# directory is legitimate precisely because that is where such a payload hides.
# /lib/modules/ is where a kernel-module rootkit lives; rejecting the whole
# prefix would have thrown away a real, specific rootkit filename.
# Directories where a payload can hide *because* the directory is legitimate:
# a kernel module must be under the module tree, a PAM backdoor on the PAM
# path, a rogue unit in a unit directory. The payload-extension carve-out below
# applies only here. Without this restriction it also excused every .dll and
# .exe under C:\Windows\System32, which flagged printui.dll on a clean box.
CARVEOUT_DIRS = (
    "/lib/modules/", "/usr/lib/modules/", "/lib/security/",
    "/usr/lib/security/", "/lib/systemd/", "/usr/lib/systemd/",
    "/etc/", "/usr/local/lib/", "/usr/local/bin/",
)

PAYLOAD_EXT = (
    ".ko", ".so", ".service", ".timer", ".socket", ".mount", ".path",
    ".sh", ".bash", ".py", ".pl", ".rb", ".lua", ".js", ".jar",
    ".exe", ".dll", ".sys", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".hta",
    ".elf", ".bin", ".dat", ".tmp", ".rules",
)

# Kernel symbols, syscall names and /proc field names. Writeups are full of
# these and an extraction happily files them as process names. They can never
# match a real process, and short ones ("mem") risk colliding with one.
KERNEL_SYM = re.compile(r"^(__|sys_|ksys_|do_|vfs_|_raw_|k?probe|security_)|_sys_")
SYSCALL_WORDS = {
    "memfd_create", "tracerpid", "getdents", "getdents64", "ptrace", "execve",
    "openat", "mmap", "mprotect", "kallsyms", "ftrace", "kprobe", "uprobe",
    "seccomp", "prctl", "ioctl", "setuid", "capset", "bpf", "mem", "maps",
    "status", "comm", "cmdline", "environ", "stat", "fd", "exe", "root",
}

# Shared objects that are supposed to be there. A PAM backdoor is detected by
# a module that should NOT exist, so the stock module names must never become
# indicators.
LIBRARY_DENY = {
    "pam_unix.so", "pam_deny.so", "pam_permit.so", "pam_env.so",
    "pam_limits.so", "pam_systemd.so", "pam_loginuid.so", "pam_motd.so",
    "pam_mail.so", "pam_keyinit.so", "pam_selinux.so", "pam_cap.so",
    "pam_faillock.so", "pam_succeed_if.so", "pam_nologin.so",
    "libc.so", "libc.so.6", "libpthread.so", "libdl.so", "libm.so",
    "ld.so", "ld-linux.so", "ld-linux-x86-64.so.2", "libnss_files.so",
}

# Public infrastructure that is globally routable and therefore passes every
# structural test, but can never be an indicator. A TrickBot writeup described
# DNS tunnelling *through* Google Public DNS and the extraction filed 8.8.8.8
# as attacker infrastructure; on a live machine that matched every DNS query
# and produced nineteen criticals in the first hunt. An indicator that would
# fire on every machine on earth is a bug, not a detection.
PUBLIC_INFRA_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "9.9.9.10",
    "149.112.112.112", "149.112.112.9", "208.67.222.222", "208.67.220.220",
    "76.76.2.0", "76.76.10.0", "94.140.14.14", "94.140.15.15", "64.6.64.6",
    "64.6.65.6", "8.26.56.26", "8.20.247.20", "185.228.168.9",
    "185.228.169.9", "4.2.2.1", "4.2.2.2", "168.95.1.1", "114.114.114.114",
    "223.5.5.5", "180.76.76.76", "77.88.8.8", "156.154.70.1",
}

# An address on a shared reverse proxy/CDN is not tenant-specific evidence.
# Threat feeds legitimately contain these when a malicious site is behind the
# provider, but the same anycast address simultaneously serves ordinary users.
# Matching the bare address would therefore accuse unrelated traffic. Keep
# this list aligned with Cloudflare's authoritative /ips-v4 endpoint.
CLOUDFLARE_IPV4 = tuple(ipaddress.ip_network(value) for value in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
))

# Windows components that appear in writeups constantly because attackers abuse
# them, and that are present on every Windows install by definition.
WINDOWS_SYSTEM_BIN = {
    "wslhost.exe", "wslservice.exe", "wsl.exe", "msedgewebview2.exe",
    "runtimebroker.exe", "searchhost.exe", "searchindexer.exe", "taskhostw.exe",
    "sihost.exe", "ctfmon.exe", "fontdrvhost.exe", "dwm.exe", "spoolsv.exe",
    "audiodg.exe", "wmiprvse.exe", "smartscreen.exe", "lsaiso.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe", "lockapp.exe",
    "applicationframehost.exe", "systemsettings.exe", "useroobebroker.exe",
    "textinputhost.exe", "widgets.exe", "backgroundtaskhost.exe",
    "wudfhost.exe", "taskmgr.exe", "msiexec.exe", "wusa.exe", "control.exe",
    "regedit.exe", "notepad.exe", "calc.exe", "mspaint.exe", "mmc.exe",
    "consent.exe", "dashost.exe", "sppsvc.exe", "trustedinstaller.exe",
    "tiworker.exe", "compattelrunner.exe", "usoclient.exe", "mousocoreworker.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe", "msmpeng.exe",
    "nissrv.exe", "mpcmdrun.exe", "wermgr.exe", "werfault.exe", "sdclt.exe",
    "certutil.exe", "bitsadmin.exe", "esentutl.exe", "expand.exe",
    "makecab.exe", "extrac32.exe", "findstr.exe", "forfiles.exe", "print.exe",
    "replace.exe", "xcopy.exe", "robocopy.exe", "reg.exe", "sc.exe",
    "schtasks.exe", "net.exe", "net1.exe", "netsh.exe", "at.exe", "wmic.exe",
    "vssadmin.exe", "bcdedit.exe", "cipher.exe", "fsutil.exe", "takeown.exe",
    "icacls.exe", "whoami.exe", "tasklist.exe", "taskkill.exe", "ping.exe",
    "nslookup.exe", "ipconfig.exe", "arp.exe", "route.exe", "netstat.exe",
    "searchprotocolhost.exe", "searchfilterhost.exe", "printui.exe",
    "printfilterpipelinesvc.exe", "conhost.exe", "openwith.exe",
    "rundll32.exe", "regsvr32.exe", "odbcconf.exe", "installutil.exe",
    "msbuild.exe", "cmstp.exe", "pcalua.exe", "presentationhost.exe",
}

# Names too generic to identify anything. A writeup naming the malware's
# process "System" or "updater.exe" is describing camouflage, not an
# indicator — matching on it flags the Windows kernel process and every
# auto-updater on the machine. This is the third distinct false positive the
# process kind produced, and the pattern is always the same: the name is real,
# but it is not *distinctive*.
GENERIC_PROCESS = {
    "system", "system.exe", "systeminfo", "updater", "updater.exe", "update",
    "update.exe", "installer", "installer.exe", "setup", "setup.exe",
    "uninstall", "uninstaller", "service", "service.exe", "services",
    "host", "host.exe", "agent", "agent.exe", "client", "client.exe",
    "server", "server.exe", "helper", "helper.exe", "launcher", "launcher.exe",
    "monitor", "monitor.exe", "manager", "manager.exe", "daemon", "worker",
    "main", "main.exe", "app", "app.exe", "run", "run.exe", "start",
    "loader", "loader.exe", "driver", "driver.exe", "tool", "tools",
    "backup", "backup.exe", "sync", "sync.exe", "config", "settings",
    "default", "temp", "test", "debug", "release", "build", "data",
    "svchost", "svchost.exe", "explorer", "explorer.exe", "winlogon",
    "shell", "shell.exe", "cmdline", "process", "task", "tasks", "job",
    "network", "security", "defender", "antivirus", "scanner", "scan",
}

HEX64 = re.compile(r"^[a-f0-9]{64}$")
ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
)
# A filename worth matching on: has a stem and looks like a program or script.
FILENAME_RE = re.compile(r"^[a-z0-9._-]{3,64}$")


def refang(value: str) -> str:
    """Undo the defanging conventions writeups use so links are not clickable."""
    v = value.strip().strip('.,;:"\'()[]<>')
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = v.replace("[:]", ":").replace("[/]", "/").replace("[@]", "@")
    v = re.sub(r"^h(xx|XX)p", "http", v)
    v = re.sub(r"^(https?)\[:\]//", r"\1://", v)
    return v.strip()


def _has_placeholder(value: str) -> bool:
    low = value.lower()
    return any(mark in low for mark in PLACEHOLDER_MARKS)


def vet_sha256(value: str):
    v = refang(value).lower()
    if not HEX64.match(v):
        return None, "not a 64-character hex digest"
    if v in JUNK_DIGESTS:
        return None, "digest of empty input"
    if len(set(v)) < 6:
        return None, "degenerate digest"
    return v, ""


def vet_ipv4(value: str):
    v = refang(value)
    # Strip anything that is plainly a URL rather than a bare address.
    v = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return None, "not an IP address"
    if not addr.is_global:
        # Private, loopback, link-local, multicast and reserved ranges are
        # either lab artefacts or this machine's own network.
        return None, "not a public address"
    if str(addr) in PUBLIC_INFRA_IPS:
        return None, "public DNS or shared infrastructure"
    if any(addr in network for network in CLOUDFLARE_IPV4):
        return None, "shared Cloudflare anycast address"
    return str(addr), ""


def vet_domain(value: str):
    v = refang(value).lower()
    v = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0].rstrip(".")
    if _has_placeholder(v):
        return None, "placeholder value"
    if not DOMAIN_RE.match(v):
        return None, "not a well-formed domain"
    tld = v.rsplit(".", 1)[-1]
    if tld in DOMAIN_DENY_TLD:
        return None, "reserved example TLD"
    if v in DOMAIN_DENY:
        return None, "publisher or example domain"
    if v in SHARED_HOSTING:
        return None, "shared hosting root, not a specific host"
    parts_pi = v.split(".")
    for i in range(len(parts_pi) - 1):
        if ".".join(parts_pi[i:]) in PACKAGE_INFRA:
            return None, "package registry or its CDN, used by everyone"
    if v in DUAL_USE_DOMAINS:
        return None, "public IP-lookup service, used by benign software too"
    parts_du = v.split(".")
    for i in range(len(parts_du) - 1):
        if ".".join(parts_du[i:]) in DUAL_USE_DOMAINS:
            return None, "public IP-lookup service, used by benign software too"
    # Also reject any subdomain of a denied registrable domain. SHARED_HOSTING
    # is deliberately excluded here: its subdomains are exactly what we want.
    parts = v.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in DOMAIN_DENY:
            return None, "publisher or example domain"
    return v, ""


def vet_cidr(value: str):
    """A network range, for feeds that publish blocks rather than addresses."""
    v = refang(value)
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        return None, "not a network range"
    if not net.is_global:
        return None, "not a public range"
    if net.prefixlen < 8:
        return None, "range too broad to be actionable"
    return str(net), ""


def vet_path(value: str):
    v = refang(value)
    if _has_placeholder(v):
        return None, "placeholder value"
    norm = v.replace("\\", "/").lower()
    if "/" not in norm:
        return None, "bare filename, not a path"
    if norm.endswith("/"):
        return None, "directory, not a file"
    base = norm.rsplit("/", 1)[-1]
    if len(base) < 3:
        return None, "no usable filename"
    # A single-component absolute path is almost always a fragment of a longer
    # one that the extraction clipped — "/tmp", "/proc", "/modules". Those name
    # directories that exist on every machine, so keeping them would guarantee
    # a false positive on the first hunt.
    comps = [c for c in norm.split("/") if c]
    if len(comps) < 2 and not norm.endswith(PAYLOAD_EXT):
        return None, "too shallow to identify a file"
    if norm.startswith(PATH_DENY_PREFIX):
        return None, "kernel or pseudo-filesystem path"
    if norm.startswith(PATH_DENY_TRUSTED) and not (
            norm.startswith(CARVEOUT_DIRS) and norm.endswith(PAYLOAD_EXT)):
        # Inside an installed-software directory and not one of the few places
        # a dropped payload has to live: this is a system file's own path.
        return None, "path owned by installed software"
    if len(norm) > 260:
        return None, "implausibly long path"
    return v, ""


def vet_process(value: str):
    v = refang(value).lower()
    if _has_placeholder(v):
        return None, "placeholder value"
    if "/" in v or "\\" in v:
        v = v.replace("\\", "/").rsplit("/", 1)[-1]
    if v.endswith((".so", ".ko", ".dll", ".dylib")) or ".so." in v:
        # A shared object or kernel module is a file, not a process name;
        # matching it against the process table can only ever misfire.
        return None, "shared library or module, not a process"
    if not FILENAME_RE.match(v):
        return None, "not a plausible process name"
    if len(v) < 4:
        return None, "too short to match unambiguously"
    if KERNEL_SYM.search(v) or v in SYSCALL_WORDS:
        return None, "kernel symbol or syscall name"
    stem = v.rsplit(".", 1)[0]
    for form in (v, stem, stem + ".exe"):
        if form in PROCESS_DENY or form in WINDOWS_SYSTEM_BIN:
            return None, "legitimate system or developer tool"
        if form in GENERIC_PROCESS:
            return None, "name too generic to identify anything"
    return v, ""


def vet_filename(value: str):
    """A bare filename, kept only when it is specific enough to hunt for.

    This exists for the artefact class that has no path in the writeup but is
    still worth finding: a PAM module, a preloaded object, a dropped kernel
    module. hunt.py looks for these only in the handful of directories where
    such a payload has to live to work, never across the whole filesystem.
    """
    v = refang(value).lower()
    if _has_placeholder(v):
        return None, "placeholder value"
    if "/" in v or "\\" in v:
        v = v.replace("\\", "/").rsplit("/", 1)[-1]
    if not FILENAME_RE.match(v):
        return None, "not a plausible filename"
    if len(v) < 5:
        return None, "too short to match unambiguously"
    if v in LIBRARY_DENY or v in PROCESS_DENY:
        return None, "stock system component"
    if KERNEL_SYM.search(v) or v in SYSCALL_WORDS:
        return None, "kernel symbol or syscall name"
    if "." not in v:
        return None, "no extension, too generic to hunt by name"
    return v, ""


def vet_regkey(value: str):
    v = refang(value)
    if _has_placeholder(v):
        return None, "placeholder value"
    norm = v.replace("/", "\\").upper()
    if not norm.startswith(("HKLM", "HKCU", "HKCR", "HKU", "HKEY_")):
        return None, "not a registry path"
    if norm.count("\\") < 2:
        return None, "too shallow to be specific"
    return v, ""


def vet_attack(value: str):
    v = refang(value).upper()
    if not ATTACK_ID.match(v):
        return None, "not an ATT&CK technique id"
    return v, ""


def vet_cve(value: str):
    v = refang(value).upper()
    if not CVE_ID.match(v):
        return None, "not a CVE identifier"
    return v, ""


VETTERS = {
    "sha256": vet_sha256,
    "ipv4": vet_ipv4,
    "domain": vet_domain,
    "path": vet_path,
    "process": vet_process,
    "filename": vet_filename,
    "cidr": vet_cidr,
    "regkey": vet_regkey,
    "attack": vet_attack,
    "cve": vet_cve,
}


def vet(kind: str, value: str):
    """Return (normalised_value, "") if usable, else (None, reason_rejected)."""
    fn = VETTERS.get(kind)
    if not fn:
        return None, f"unknown indicator kind: {kind}"
    if not isinstance(value, str) or not value.strip():
        return None, "empty value"
    if len(value) > 512:
        return None, "implausibly long value"
    try:
        return fn(value)
    except Exception as exc:            # a bad candidate must never crash a refresh
        return None, f"vetting error: {exc}"
