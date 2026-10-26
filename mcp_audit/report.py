"""Markdown and HTML reports: the audit findings, and the lockfile changes
someone has to approve (the text to paste into a pull request).

Every name, path and message comes from the configs and servers being
audited, so each one is cleaned (redact.clean: no credential), has its
control characters spelled out (redact.sanitize) and is escaped for the
format before it is placed. HTML is one self-contained page with no script,
no external file and a content-security-policy that forbids both."""

from __future__ import annotations

import html as _html
import re

from . import lockfile as lf
from . import redact

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|~<>&])")


def _plain(text) -> str:
    return redact.sanitize(redact.clean(str(text)))


def md(text) -> str:
    """`text` as inert Markdown: no emphasis, link, HTML, table break or
    @mention can come out of it."""
    out = _MD_SPECIAL.sub(r"\\\1", _plain(text))
    return out.replace("@", "@​")


def _fmt_check(fmt: str) -> None:
    if fmt not in ("markdown", "html"):
        raise ValueError(f"unknown report format {fmt!r}")


# -- the audit ----------------------------------------------------------------


def findings_report(results: list, warnings: "list | None", fmt: str,
                    version: str = "") -> str:
    _fmt_check(fmt)
    warnings = warnings or []
    order = sorted(results, key=lambda r: r["score"])
    counts = {k: 0 for k in _SEV_ORDER}
    for r in results:
        for f in r["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = (f"{len(results)} server(s), "
               f"{sum(counts.values())} finding(s): "
               + ", ".join(f"{counts[k]} {k}" for k in _SEV_ORDER))
    if fmt == "markdown":
        lines = ["## mcp-audit report", "", summary, ""]
        for w in warnings:
            lines.append(f"- **Not audited:** {md(w['path'])} "
                         f"({md(w['client'])}): {md(w['reason'])}")
        if warnings:
            lines.append("")
        for r in order:
            lines += [f"### {md(r['name'])} - {r['grade']} ({r['score']}/100)",
                      "", f"{md(r['client'])}, {md(r['path'])}", ""]
            fs = sorted(r["findings"],
                        key=lambda f: _SEV_ORDER.get(f["severity"], 9))
            if not fs:
                lines += ["No findings.", ""]
                continue
            lines += ["| Severity | Check | Finding |", "| --- | --- | --- |"]
            lines += [f"| {md(f['severity'])} | {md(f['check'])} | "
                      f"{md(f['message'])} |" for f in fs]
            lines.append("")
        if not results:
            lines += ["No MCP servers were audited. This is not a clean bill "
                      "of health.", ""]
        return "\n".join(lines).rstrip("\n") + "\n"
    e = _esc
    body = [f"<h1>mcp-audit report</h1><p>{e(summary)}</p>"]
    for w in warnings:
        body.append(f"<p class=warn>Not audited: {e(w['path'])} "
                    f"({e(w['client'])}): {e(w['reason'])}</p>")
    for r in order:
        body.append(f"<h2>{e(r['name'])} <small>{e(r['grade'])} "
                    f"({r['score']}/100)</small></h2>"
                    f"<p class=meta>{e(r['client'])}, {e(r['path'])}</p>")
        fs = sorted(r["findings"],
                    key=lambda f: _SEV_ORDER.get(f["severity"], 9))
        if not fs:
            body.append("<p>No findings.</p>")
            continue
        body.append("<table><tr><th>Severity</th><th>Check</th>"
                    "<th>Finding</th></tr>" + "".join(
                        f"<tr class=\"sev-{e(f['severity'])}\">"
                        f"<td>{e(f['severity'])}</td><td>{e(f['check'])}</td>"
                        f"<td>{e(f['message'])}</td></tr>" for f in fs)
                    + "</table>")
    if not results:
        body.append("<p>No MCP servers were audited. This is not a clean bill"
                    " of health.</p>")
    return _page("mcp-audit report", "".join(body))


# -- the lockfile -------------------------------------------------------------


def changes_report(changes: list, fmt: str, lockfile: str, title: str,
                   verdict: str, hints: "list | None" = None) -> str:
    """The differences between a lockfile and what is configured, as the text
    of a pull-request comment (markdown) or a page (html). `changes`:
    [(server key, lockfile.Drift)]; `hints`: more that is not drift;
    `verdict`: one sentence on what happens next."""
    _fmt_check(fmt)
    rows = [(k, d, False) for k, d in changes] + [
        (k, d, True) for k, d in (hints or [])]
    by_server: dict = {}
    for k, d, hint in rows:
        by_server.setdefault(k, []).append((d, hint))

    def what(d: "lf.Drift") -> str:
        return lf.KIND_TEXT[d.kind]

    if fmt == "markdown":
        lines = [f"## {md(title)}", "", md(verdict), ""]
        if not rows:
            lines += ["Nothing differs from "
                      f"`{_plain(lockfile).replace('`', '')}`.", ""]
        for key, items in by_server.items():
            lines += [f"### {md(key)}", "",
                      "| Change | Tool | Detail |", "| --- | --- | --- |"]
            for d, hint in items:
                lines.append(
                    f"| {md(what(d))}{' (hint)' if hint else ''} | "
                    f"{md(d.tool) if d.tool else ''} | "
                    f"{md(d.detail) if d.detail else ''} |")
            lines.append("")
        if rows:
            lines += ["To approve, review each line, then run "
                      "`mcp-audit lock --accept-changes` and commit the "
                      "lockfile.", ""]
        return "\n".join(lines).rstrip("\n") + "\n"
    e = _esc
    body = [f"<h1>{e(title)}</h1><p>{e(verdict)}</p>"]
    if not rows:
        body.append(f"<p>Nothing differs from {e(lockfile)}.</p>")
    for key, items in by_server.items():
        body.append(f"<h2>{e(key)}</h2><table><tr><th>Change</th><th>Tool"
                    "</th><th>Detail</th></tr>" + "".join(
                        f"<tr><td>{e(what(d))}{' (hint)' if hint else ''}"
                        f"</td><td>{e(d.tool) if d.tool else ''}</td>"
                        f"<td>{e(d.detail) if d.detail else ''}</td></tr>"
                        for d, hint in items) + "</table>")
    if rows:
        body.append("<p>To approve, review each line, then run <code>"
                    "mcp-audit lock --accept-changes</code> and commit the "
                    "lockfile.</p>")
    return _page(title, "".join(body))


# -- html ---------------------------------------------------------------------


def _esc(text) -> str:
    return _html.escape(_plain(text), quote=True)


_CSS = (":root{color-scheme:light dark}"
        "body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;"
        "margin:2rem auto;padding:0 1rem}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #8886;padding:.3rem .5rem;text-align:left;"
        "vertical-align:top}"
        ".meta{opacity:.7}.warn{font-weight:600}"
        ".sev-critical td:first-child,.sev-high td:first-child{font-weight:700}")


def _page(title: str, body: str) -> str:
    return ("<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta http-equiv=\"Content-Security-Policy\" content=\""
            "default-src 'none'; style-src 'unsafe-inline'\">"
            "<meta name=viewport content=\"width=device-width,"
            "initial-scale=1\">"
            f"<title>{_esc(title)}</title><style>{_CSS}</style></head>"
            f"<body>{body}</body></html>\n")
