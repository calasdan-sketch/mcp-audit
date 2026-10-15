"""Score servers from findings and render reports."""

from __future__ import annotations

DEDUCTIONS = {"critical": 40, "high": 20, "medium": 10, "low": 5}


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


def render_human(results: list[dict], warnings: list[dict] | None = None,
                 n_configs: int = 0) -> str:
    """Render the human report.

    warnings: discovery warnings for config files that existed but were
    skipped (unparseable, unreadable, unknown/unsupported shape).
    n_configs: how many configs were actually discovered and parsed.
    When zero configs were discovered the report says so plainly — a
    confident "no findings" is never emitted for unscanned configs.
    """
    warnings = warnings or []
    lines = ["", "── mcp-audit ───────────────────────────────────────"]
    for w in warnings:
        lines.append(f"  [!] skipped {w['path']} <{w['client']}>: {w['reason']}")
    if not results:
        if n_configs == 0:
            lines.append("  [mcp-audit] warning: no MCP configs discovered — "
                         "this is not a clean bill of health.")
        else:
            lines.append("  no MCP servers found in audited configs.")
        lines.append("──────────────────────────────────────────────────")
        return "\n".join(lines)
    for r in sorted(results, key=lambda x: x["score"]):
        lines.append("")
        lines.append(f"  [{r['grade']}] {r['name']}  ({r['score']}/100)  <{r['client']}>")
        lines.append(f"        {r['path']}")
        if not r["findings"]:
            lines.append("        ✓ no findings")
            continue
        for f in sorted(r["findings"],
                        key=lambda x: _SEV_ORDER.get(x["severity"], 9)):
            lines.append(f"        [{f['severity'].upper():8}] {f['message']}")
    s = summarize(results)
    lines += ["",
              f"  {s['servers']} servers · {s['findings']} findings "
              f"(crit={s['by_severity']['critical']} high={s['by_severity']['high']} "
              f"med={s['by_severity']['medium']} low={s['by_severity']['low']})"]
    if warnings:
        lines.append(f"  [mcp-audit] warning: {len(warnings)} config file(s) "
                     "existed but were not audited — results are not a "
                     "clean bill of health.")
    lines.append("──────────────────────────────────────────────────")
    return "\n".join(lines)
