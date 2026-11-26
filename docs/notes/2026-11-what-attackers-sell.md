# What attackers were selling in November 2026, and how to protect yourself

These notes come from one defensive sweep on 26 November 2026. It covered 35 searches
of a public index of Tor sites (Ahmia) and the 100 latest posts on ransomware leak sites
(as indexed by ransomware.live).

How the sweep was done:

* Only titles and short snippets were read.
* No forum was joined or logged into, and no onion page was opened.
* Nothing was bought.

**Everything below is a claim made by criminals and has not been verified.** Many
listings are clearly scams: identical storefronts under different names, keyword-stuffed
pages and fake "services". Treat each item as a trend, never as an indicator to block.

The patterns are worth knowing because most of them can be defended against with things
you can do today.

## 1. AI attack kits are cheap

* Source code for an LLM-driven attack framework was offered on a Chinese-language dark
  market for about 300 USDT. It was pitched as "even a beginner can become a hacker".
* "ML hacker for hire" listings and the FraudGPT/WormGPT family of criminal chatbots
  were still being advertised.

**What it means.** Reconnaissance, exploitation and data triage now happen at machine
speed and cost the attacker almost nothing. A small business is as worthwhile a target
as a large one.

**What to do.**

* Patch anything that faces the internet first: VPNs, firewalls, remote-access tools,
  web apps.
* Assume a newly published bug is scanned for within hours.
* Watch for bursts: many different system commands from one process within a minute is
  not what a person typing looks like.

## 2. The market is about logging in, not breaking in

The most common recent listings:

* **Session-cookie theft and replay**, sold as "skips 2FA". A stolen browser session is
  already signed in.
* **OAuth token and app-consent theft.** A malicious "app" you once approved keeps
  reading your mail after you change your password.
* **Infostealer log feeds**: passwords, cookies and wallet files taken from infected
  computers.
* **SIM swaps through a carrier insider.** Some include a "port back", so the victim
  never notices that their number moved.
* **Footholds on VPN appliances** and remote-desktop access, sold per company.

**What to do.**

* Prefer **passkeys** or hardware security keys. Remove **SMS** as a second factor
  wherever you can.
* Ask your mobile carrier for a **port-out or SIM lock** with its own PIN.
* Review the apps you have granted access to, and remove anything you do not recognise:
  * Google: myaccount.google.com/connections
  * Microsoft personal accounts: account.live.com/consent/Manage
  * Work tenants: Entra ID, Enterprise applications
* After removing a suspicious app or recovering an account, **sign out all other
  sessions**. A password change alone does not kill a stolen cookie.
* Do not save passwords in a browser on a machine where you install untrusted software.
  Infostealers read the browser stores first.
* Keep VPN appliances patched. Put multi-factor authentication on every remote-access
  path, and keep management interfaces off the internet.

## 3. ClickFix moved to the File Explorer address bar ("FileFix")

ClickFix lures show a fake error or CAPTCHA page and ask you to press Win+R and paste
"a fix". FileFix is the same trick through **File Explorer's address bar**.

* The lure seen here was a fake Facebook account-suspension notice asking you to "open
  the shared file".
* The pasted text is really a command. It is usually padded with spaces and ends in
  `# C:\some\fake\path.docx`, so only the harmless-looking path is visible in the bar.

**The rule to teach everyone:** no real website, account notice or support page ever
asks you to paste something into Run, File Explorer's address bar, a terminal or
PowerShell.

**Check your own Windows machine.** Both keys are plain text, readable by the user:

```powershell
# What was typed into Win+R
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
# What was typed into File Explorer's address bar
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
```

Folder paths are normal. Look for anything that starts a program, such as `powershell`,
`cmd /c`, `mshta`, `curl` or `finger`, especially one with a web address,
`-enc`/`-EncodedCommand`, `iwr`/`iex`, or a long run of spaces before a `#`. If you find
one you did not type yourself:

1. Disconnect the computer from the network.
2. Change your passwords from a different device.
3. Treat the computer as compromised.

**For defenders.**

* Alert on `powershell`, `mshta` or `cmd` started by `explorer.exe` with a URL or
  encoded payload on the command line.
* Read TypedPaths alongside RunMRU in your triage tooling.
* Constrained Language Mode, or blocking `mshta.exe` where it is not needed, removes the
  most common payloads.

## 4. AI assistant data is now loot

One ransomware crew posted machine-written, itemised inventories of stolen data. In one
case the inventory included **customer chat transcripts and the caches behind an AI
search feature**. Coding assistants keep full transcripts on disk, and those transcripts
often contain pasted API keys, source code and internal URLs.

**Where this data lives** (common defaults):

* Claude Code: `~/.claude/projects/`, with credentials in `~/.claude/.credentials.json`.
* Codex CLI: `~/.codex/sessions/` and `~/.codex/history.jsonl`, with credentials in
  `~/.codex/auth.json`.
* Local vector stores: Chroma (`chroma.sqlite3`), LanceDB (`*.lance`), FAISS (`*.faiss`),
  Qdrant (`storage/`).

**What to do.**

* Restrict these directories to your user only. On Linux and macOS:
  `chmod 700 ~/.claude ~/.codex`.
* Keep them out of shared folders, unencrypted backups and anything a web server can
  serve.
* Don't paste secrets into assistants. If you already have, rotate those secrets and
  delete the old sessions.
* Monitor bulk access, not single reads. A `tar`, `zip`, `Compress-Archive`, `curl`,
  `rsync` or `rclone` command that names these paths is worth an alert. A person
  searching one file with `grep` is not.
* Know the limit of that alert: a program that opens the files directly never shows the
  path on a command line. File-access auditing is the only way to see that.

## 5. Phone spyware is a commodity

Android remote-access kits (SpyNote, CraxsRat, and "Pathfinder", which claimed iOS
support) were sold openly. They mostly arrive as an app the victim is persuaded to
install, or one installed by someone with brief access to the phone. Once installed,
they abuse **Accessibility** permissions to read the screen and approve their own
prompts.

**Check an Android phone.**

* Settings → Accessibility (installed or downloaded apps): disable and remove anything
  you did not deliberately turn on.
* Settings → Security → Device admin apps: the same.
* Settings → Apps → Special app access → Install unknown apps: turn this off for every
  app.
* Keep Google Play Protect on, and leave USB or wireless debugging off unless you are
  developing.

**On an iPhone:**

* Keep iOS updated.
* Remove configuration profiles you don't recognise (Settings → General → VPN & Device
  Management).
* If you are at higher risk, turn on Lockdown Mode.

**On a computer that phones plug into**, an `adb install … .apk` you did not run is
worth investigating.

## 6. Turning off the defences is sold as a service

Listings offered "EDR eviction", that is getting endpoint protection removed or bypassed
so a payload survives, as well as "fully undetectable" crypters.

**What to do.**

* Do not rely on a single security product.
* Alert when protection stops, not only when it detects something.
* Send logs somewhere the attacker cannot reach from the machine: another machine, a
  phone, or a hosted log.

## Short checklist

- [ ] Passkeys or security keys on email, cloud and banking; no SMS codes
- [ ] Carrier port-out / SIM lock PIN set
- [ ] Third-party app grants reviewed on Google and Microsoft; other sessions signed out
- [ ] Everyone knows the paste rule (section 3); RunMRU and TypedPaths checked
- [ ] AI assistant directories restricted to your user and excluded from shared backups
- [ ] Internet-facing devices patched; remote access behind multi-factor authentication
- [ ] Android: Accessibility, Device admin and unknown-sources settings reviewed
- [ ] An alert that fires when your monitoring or antivirus stops

## Limits of these notes

* They come from one sweep of public index metadata and can be wrong.
* Groups and tools change names quickly.
* No sample was obtained or analysed.
* Leak-site victims are deliberately not named here.

Corrections and additions are welcome as issues or pull requests.
