"""Remediation commands for findings that have one.

Not every finding has a fix that is a command — a coverage gap means "write a
collector," a suspicious process means "go look at it," not "run this." This
module only speaks up when there is a real, safe, single next step, and stays
silent otherwise rather than inventing one.

Matching is on the finding's title (a prefix or substring, whichever the
collector's wording needs) plus, where the command has to be parameterised,
a bit of the detail text. Getting the match wrong just means no suggestion is
shown — never a wrong command attached to the wrong finding — so match tightly
enough to be certain, not just to be broad.
"""


# Only findings Jarvis Origin itself raises have a rule here: the bridge and the
# daemon's own health (coverage.py).
_RULES = [
    (lambda t, d, w: "interop bridge" in t.lower() or "bridge is down" in d.lower(),
     lambda t, d, w: "from Windows (not inside WSL): wsl --shutdown"),

    (lambda t, d, w: t == "the monitor is not running",
     lambda t, d, w: "systemctl --user restart jarvis-origin.service"),

    (lambda t, d, w: t == "the monitor will not start on boot",
     lambda t, d, w: "systemctl --user enable jarvis-origin.service"),

    (lambda t, d, w: t.startswith("collector") and t.endswith("crashed"),
     lambda t, d, w: "systemctl --user restart jarvis-origin.service  "
                     "(then `jarvis-origin coverage` to confirm it stuck)"),
]


def suggest(finding):
    """Return a command string for this finding, or "" if there is none."""
    title = finding.get("title", "")
    detail = finding.get("detail", "")
    where = finding.get("where", "")
    for pred, fix in _RULES:
        try:
            if pred(title, detail, where):
                return fix(title, detail, where)
        except Exception:
            continue
    return ""
