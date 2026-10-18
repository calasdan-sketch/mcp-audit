"""Score servers from findings and render reports."""

from __future__ import annotations

import sys

from . import discovery, redact

DEDUCTIONS = {"critical": 40, "high": 20, "medium": 10, "low": 5}

#: The check id of every finding about what a server says of its tools (the
#: --deep description scan); a report that has none of them for a server whose
#: tools were read says so in its own words (see _deep_line).
DESCRIPTION_CHECK = "tool-description-injection"

# Report glyphs and their ASCII stand-ins. A Windows console or pipe often
# runs cp1252, which cannot encode the check mark or the box-drawing rule:
# printing them there raised UnicodeEncodeError and killed the report.
_ASCII_SYMBOLS = {"✓": "[ok]", "─": "-", "·": "*", "—": "--"}


def sym(s: str) -> str:
    """`s` if the current stdout can encode it, else ASCII stand-ins."""
    enc = getattr(sys.stdout, "encoding", None)
    if not enc:
        return s  # e.g. io.StringIO: takes any str
    try:
        s.encode(enc)
    except (UnicodeEncodeError, LookupError):
        return "".join(_ASCII_SYMBOLS.get(ch)
                       or ch.encode("ascii", "replace").decode("ascii")
                       for ch in s)
    return s


def score(findings: list[dict]) -> tuple[int, str]:
    s = 100
    for f in findings:
        s -= DEDUCTIONS.get(f.get("severity", "low"), 5)
    s = max(0, s)
    grade = "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"
    # Severity floor: any single critical finding caps the grade at D, no
    # matter how few findings there are (a lone critical still scores 60).
    if grade in ("A", "B", "C") and any(
            f.get("severity") == "critical" for f in findings):
        grade = "D"
    return s, grade


def summarize(results: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        for f in r["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {
        "servers": len(results),
        "findings": sum(counts.values()),
        "by_severity": counts,
    }


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _deep_line(r: dict) -> "str | None":
    """What the report says of a server whose tools --deep read when what
    they say raised nothing. Not "no findings": that would speak for the
    whole server, and the scanner only knows some patterns."""
    read = r.get("deep_read")
    if read is None or any(f["check"] == DESCRIPTION_CHECK
                           for f in r["findings"]):
        return None
    if not read:
        return "deep: the server lists no tools, so there was nothing to read"
    return (f"deep: {read} tool{'' if read == 1 else 's'} read, no known "
            "poisoning patterns matched (heuristic - this is not proof of "
            "safety)")


def render_human(results: list[dict], warnings: list[dict] | None = None,
                 n_configs: int = 0, configs: list[dict] | None = None) -> str:
    """Render the human report.

    warnings: discovery warnings for config files that existed but were
    skipped (unparseable, unreadable, unknown/unsupported shape).
    n_configs: how many configs were actually discovered and parsed.
    configs: the discovered configs themselves; each one that parsed but
    holds no servers gets an info line ("0 servers configured") so a known
    client with nothing installed reads as exactly that, not as skipped.
    When zero configs were discovered the report says so plainly — a
    confident "no findings" is never emitted for unscanned configs. Nor is it
    for a server whose tools --deep read: that line says what was read and
    that the scan is a heuristic.

    Names, paths and messages come from the configs being audited. Each is
    sanitized where it is placed in the report: a control or bidi character
    in one is spelled out (\\x1b), and a line break in a name cannot start a
    line of its own and fake a result. The finished report is sanitized
    again as a backstop.
    """
    s = redact.sanitize
    warnings = warnings or []
    rule = sym("─")
    lines = ["", f"{rule * 2} mcp-audit {rule * 39}"]
    for w in warnings:
        lines.append(f"  [!] skipped {s(w['path'])} <{s(w['client'])}>: "
                     f"{s(w['reason'])}")
    managed: set = set()
    for c in configs or []:
        if discovery.is_managed_client(c["client"]):
            # one line per file, whatever it holds: the organization's servers
            # are not the ones this person wrote
            if c["path"] not in managed:
                managed.add(c["path"])
                count = sum(len(g.get("servers") or {}) for g in configs
                            if g["path"] == c["path"])
                lines.append(
                    f"  [i] managed config present: {s(c['path'])} "
                    f"<{s(c['client'])}> - set by your organization, "
                    f"{count} server(s); --fix never rewrites it")
        elif not c.get("servers"):
            lines.append(f"  [i] {s(c['path'])} <{s(c['client'])}>: "
                         "0 servers configured")
    if not results:
        if n_configs == 0:
            lines.append(f"  [mcp-audit] warning: no MCP configs discovered "
                         f"{sym('—')} this is not a clean bill of health.")
        else:
            lines.append("  no MCP servers found in audited configs.")
        lines.append(rule * 50)
        return redact.sanitize_report("\n".join(lines))
    for r in sorted(results, key=lambda x: x["score"]):
        lines.append("")
        lines.append(f"  [{r['grade']}] {s(r['name'])}  ({r['score']}/100)  "
                     f"<{s(r['client'])}>")
        lines.append(f"        {s(r['path'])}" + (
            f"  (project: {s(r['project'])})" if "project" in r else ""))
        for f in sorted(r["findings"],
                        key=lambda x: _SEV_ORDER.get(x["severity"], 9)):
            lines.append(f"        [{f['severity'].upper():8}] "
                         f"{s(f['message'])}")
        deep = _deep_line(r)
        if deep:
            lines.append(f"        {deep}")
        elif not r["findings"]:
            lines.append(f"        {sym('✓')} no findings")
    s = summarize(results)
    lines += ["",
              f"  {s['servers']} servers {sym('·')} {s['findings']} findings "
              f"(crit={s['by_severity']['critical']} high={s['by_severity']['high']} "
              f"med={s['by_severity']['medium']} low={s['by_severity']['low']})"]
    if warnings:
        lines.append(f"  [mcp-audit] warning: {len(warnings)} config file(s) "
                     f"existed but were not audited {sym('—')} results are "
                     "not a clean bill of health.")
    lines.append(rule * 50)
    return redact.sanitize_report("\n".join(lines))


_SARIF_LEVEL = {"critical": "error", "high": "error",
                "medium": "warning", "low": "note"}


def render_sarif(results: list[dict], version: str) -> dict:
    """SARIF 2.1.0 log (GitHub code scanning, IDE viewers). One rule per
    check id; each finding points at the config file that holds the server."""
    import pathlib
    rules: dict[str, dict] = {}
    out = []
    for r in results:
        try:
            uri = pathlib.Path(r["path"]).resolve().as_uri()
        except ValueError:
            uri = str(r["path"]).replace("\\", "/")
        for f in r["findings"]:
            rules.setdefault(f["check"], {
                "id": f["check"],
                "shortDescription": {"text": f["check"]}})
            out.append({
                "ruleId": f["check"],
                "level": _SARIF_LEVEL.get(f["severity"], "note"),
                "message": {"text": f"{r['name']}: {f['message']}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri}}}],
                "properties": {"severity": f["severity"],
                               "server": r["name"], "client": r["client"],
                               **({"project": r["project"]}
                                  if "project" in r else {})},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcp-audit", "version": version,
                "informationUri":
                    "https://github.com/calasdan-sketch/mcp-audit",
                "rules": list(rules.values())}},
            "results": out,
        }],
    }
