"""mcp-gradecard: `npm audit` for your agent's MCP tool supply chain."""

import argparse
import codecs
import contextlib
import errno
import json
import os
import re
import shutil
import signal
import stat
import sys
import tempfile
import time
import traceback

from . import __version__
from . import deep as deep_mod
from . import detectors
from . import discovery
from . import launch
from . import redact
from . import scoring


def _audit_one(name: str, cfg: dict, group: dict, advisories: list[dict],
               online: bool = False, allow_hosts=()) -> dict:
    """Statically audit one server entry of a discovered group (see
    discovery). Nothing is launched here: that is the --deep step.
    `allow_hosts`: --allow-host, as detectors.host_pattern() writes them."""
    client, path = group["client"], group["path"]
    findings = detectors.audit_server(name, cfg, advisories, allow_hosts)
    if online:
        findings.extend(detectors.detect_osv(name, cfg))
    tools: list[dict] = []
    for f in findings:  # whatever produced it, nothing secret goes out
        f["message"] = redact.clean(f["message"])
    score, grade = scoring.score(findings)
    result = {"name": name, "client": client, "path": path,
              "config": cfg, "findings": findings,
              "score": score, "grade": grade, "tools": tools,
              "key_path": group.get("key_path")}
    if group.get("project") is not None:
        result["project"] = group["project"]
    return result


def _audit_all(discovered: list[dict], advisories: list[dict],
               online: bool, allow_hosts=()) -> list[dict]:
    return [_audit_one(name, cfg, d, advisories, online, allow_hosts)
            for d in discovered for name, cfg in d["servers"].items()]


def _note(text: str) -> None:
    """A line for the operator on stderr (stdout carries the report)."""
    sys.stderr.write(f"[mcp-gradecard] {redact.clean(text)}\n")


def _has_critical(result: dict) -> bool:
    return any(f["severity"] == "critical" for f in result["findings"])


def _add_findings(result: dict, new: list[dict]) -> None:
    """Fold findings found after the static audit into a result: cleaned
    like the rest, and the score and grade follow."""
    for f in new:
        f["message"] = redact.clean(f["message"])
    result["findings"].extend(new)
    result["score"], result["grade"] = scoring.score(result["findings"])


_HELD_BECAUSE = {
    "critical": ("it has critical findings, and launching it would run the "
                 "command that was flagged", "--probe-critical"),
    "unreadable": ("the static audit could not analyze it (a check failed "
                   "on it), so what launching it would run is not known",
                   "--probe-critical"),
    "url": ("it has a URL that could not be taken apart, so where it would "
            "connect is not known", "--probe-critical"),
    "http": ("it installs its packages from a registry over plain http, "
             "where anyone on the way can swap what it serves",
             "--probe-critical"),
    "project": ("it comes from a project file in the current directory, so "
                "whoever wrote that project, say a repository you have just "
                "cloned, chose what it would run", "--probe-project"),
}

#: The findings below critical that hold a server back too, as (check,
#: severity or None for any, reason): each says the audit could not settle
#: what launching the server would do. A medium finding does not: a git
#: source, a registry over https and a bridge are how MCP servers are
#: installed and reached.
_HELD_FINDINGS = (
    ("detector-error", None, "unreadable"),
    ("unparseable-url", None, "url"),
    ("package-registry", "high", "http"),
)


def _hold_reasons(result: dict, probe_critical: bool,
                  probe_project: bool) -> list[str]:
    """Why --deep must leave this server alone, from _HELD_BECAUSE; empty
    when it may be launched.

    "critical": the static audit rated it critical. "unreadable", "url",
    "http": a finding below critical that says the audit could not tell what
    launching it would do (see _HELD_FINDINGS); a server that is critical
    already is told only that. All of these take --probe-critical.
    "project": it comes from a file found in the current directory
    (discovery.PROJECT_CLIENTS), which is not yours: a cloned repository
    names its own commands. A server that would not be launched anyway (a
    remote one) is not held back for that: it keeps its own `deep-probe`
    finding."""
    reasons = []
    if not probe_critical:
        if _has_critical(result):
            reasons.append("critical")
        else:
            reasons += [reason for check, severity, reason in _HELD_FINDINGS
                        if any(f["check"] == check
                               and severity in (None, f["severity"])
                               for f in result["findings"])]
    if (not probe_project and discovery.is_project_client(result["client"])
            and deep_mod.not_launchable(result["config"]) is None):
        reasons.append("project")
    return reasons


def _starts_in_the_project(result: dict) -> bool:
    """A server from a project file (which --probe-project let through)
    starts in the project, the current directory: the paths in a project's
    config are written for it. Every other server starts in an empty
    directory of its own, because the current directory may be a repository
    you are auditing (see deep.probe_server)."""
    return discovery.is_project_client(result["client"])


#: What a launch fetches that nothing in the config pins, as the launch list
#: says it - by the finding that shows it: (check, severity or None for any,
#: words). A package that is not pinned to one release, a git source that is
#: not pinned to a commit or a tag, and a registry other than the default
#: are whatever the registry or the forge serves when the server starts. A
#: bridge connects to a remote server by design.
_FETCHES = (
    ("floating-version", None, "downloads code"),
    ("git-source", "medium", "downloads code"),
    ("package-registry", None, "downloads code"),
    ("remote-server", None, "connects to a remote server"),
)


def _launch_line(result: dict) -> str:
    """One line of the list of what --deep is about to launch: where the
    server comes from, what it runs (launch.summary: no argument is printed)
    and, in fixed words, where it starts and what it fetches."""
    notes = []
    for check, severity, words in _FETCHES:
        if words not in notes and any(
                f["check"] == check and severity in (None, f["severity"])
                for f in result["findings"]):
            notes.append(words)
    if _starts_in_the_project(result):
        notes.append("starts in the current directory")
    return (f"  '{result['name']}' <{result['client']}> from "
            f"{result['path']}, runs: {launch.summary(result['config'])}"
            + "".join("; " + words for words in notes))


def _off_text(result: dict, how: str) -> str:
    """Why a switched-off server (deep.switched_off) is not launched."""
    return f"disabled in the {result['client']} config ({how})"


def _held_text(reasons: list[str]) -> str:
    """The reasons, and what it takes to launch the server anyway."""
    why = "; and ".join(_HELD_BECAUSE[r][0] for r in reasons)
    flags = []
    for r in reasons:
        if _HELD_BECAUSE[r][1] not in flags:
            flags.append(_HELD_BECAUSE[r][1])
    if len(flags) == 1:
        return f"{why} ({flags[0]} launches it anyway)"
    return f"{why} (it takes {' and '.join(flags)} to launch it)"


def _deep_pass(results: list[dict], probe_critical: bool,
               probe_project: bool) -> None:
    """The --deep step: launch the servers that may be launched, read their
    tool descriptions, fold what they say into `results`.

    Launching runs the commands in the configs, with the user's rights, so
    this says what it is about to launch BEFORE it launches anything. It
    leaves alone the servers the static audit rated critical or could not
    settle (see _HELD_FINDINGS) unless `probe_critical` is set, and the
    servers that come from a project file in the current directory (whoever
    wrote the project chose their commands: think of a repository you have
    just cloned) unless `probe_project` is set. It skips the entries that
    switch themselves off (`"disabled": true`, `"enabled": false`), which no
    flag launches. A server that is left alone, skipped, or cannot be
    probed, gets a low `deep-probe` finding: --deep never reports a server as
    read when it was not.

    A signal that ends mcp-gradecard while a server runs (Ctrl-C, SIGTERM,
    SIGHUP) stops the server first and ends the run: deep_mod.Interrupted
    comes out of here and main() answers it. There is no report then."""
    off = {}    # the entries that switch themselves off, and how
    for r in results:
        how = deep_mod.switched_off(r["config"])
        if how and deep_mod.not_launchable(r["config"]) is None:
            off[id(r)] = how
    holds = {id(r): [] if id(r) in off
             else _hold_reasons(r, probe_critical, probe_project)
             for r in results}
    held_back = {i for i, reasons in holds.items() if reasons}
    launching = {id(r) for r in results
                 if id(r) not in held_back and id(r) not in off
                 and deep_mod.not_launchable(r["config"]) is None}
    if launching:
        _note(f"--deep will now LAUNCH {len(launching)} MCP server(s) on this "
              "machine, with your user rights, and talk to them over stdio. "
              "A server can do anything you can: only go on if you would "
              "run these yourself. Each one starts in an empty temporary "
              "directory (removed afterwards) unless its line says it starts "
              "in the current directory, and its program is looked up on "
              "PATH only. Arguments are counted, not printed (any of them "
              "can be a credential): read them in the config file named on "
              "each line.")
        for r in results:
            if id(r) in launching:
                _note(_launch_line(r))
    for r in results:
        if id(r) in held_back:
            _note(f"--deep leaves '{r['name']}' <{r['client']}> from "
                  f"{r['path']} alone: {_held_text(holds[id(r)])}")
        if id(r) in off:
            _note(f"--deep skips '{r['name']}' <{r['client']}> from "
                  f"{r['path']}: {_off_text(r, off[id(r)])}")
    sys.stderr.flush()
    with deep_mod.stop_on_signals():
        for r in results:
            if id(r) in off:
                _add_findings(r, [{
                    "severity": "low", "check": "deep-probe",
                    "message": "--deep did not launch this server: "
                               + _off_text(r, off[id(r)])}])
                continue
            if id(r) in held_back:
                _add_findings(r, [{
                    "severity": "low", "check": "deep-probe",
                    "message": "--deep did not launch this server: "
                               + _held_text(holds[id(r)])}])
                continue
            if id(r) in launching:
                _note(f"probing '{r['name']}'...")
            probe = deep_mod.probe_server(
                r["config"],
                cwd=os.getcwd() if _starts_in_the_project(r) else None)
            new: list[dict] = []
            if probe["ok"]:
                r["tools"] = probe["tools"]
                r["deep_read"] = len(probe["tools"])
                new += deep_mod.audit_descriptions(probe["tools"],
                                                   probe.get("server"))
            if probe.get("error"):
                new.append({"severity": "low", "check": "deep-probe",
                            "message": f"--deep probe: {probe['error']}"})
            _add_findings(r, new)


# Only unambiguous launch-time attacks are fixable. URL/description/advisory
# findings are report-only: they are too often legitimate config.
FIXABLE_CHECKS = ("suspicious-command", "pipe-to-shell")


def _fixable_shape(result: dict) -> bool:
    """True when the server sits in a layout --fix owns: a flat
    mcpServers/servers object, or Claude Code's local scope."""
    key_path = result.get("key_path") or []
    return (key_path in (["mcpServers"], ["servers"])
            or (len(key_path) == 3 and key_path[0] == "projects"
                and key_path[2] == "mcpServers"))


def _servers_at(data, result: dict):
    """The servers object a result came from, or None if it moved."""
    node = data
    for key in result["key_path"]:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node if isinstance(node, dict) else None


def _where(result: dict) -> str:
    """Where in its file a server sits, for the --fix plan."""
    key_path = result.get("key_path") or []
    return " > ".join(str(k) for k in key_path) or "?"


def _plan_fix(results: list[dict]) -> "tuple[list[dict], list[str]]":
    """What --fix would remove, and the notes about what it will leave.

    One item per server with a critical suspicious-command / pipe-to-shell
    finding in a layout --fix owns."""
    items: list[dict] = []
    notes: list[str] = []
    skipped: set[str] = set()
    for r in results:
        crit = [f for f in r["findings"]
                if f["severity"] == "critical"
                and f["check"] in FIXABLE_CHECKS]
        if not crit:
            continue
        if discovery.is_managed_client(r["client"]):
            # the organization's file, not this person's: not ours to edit
            if r["path"] not in skipped:
                skipped.add(r["path"])
                notes.append(f"skipped {r['path']}: it is your organization's "
                             "managed configuration, which --fix never "
                             "rewrites; ask whoever manages it")
            continue
        if not _fixable_shape(r):
            # e.g. VS Code's nested {"mcp": {"servers": ...}} shape: we don't
            # rewrite layouts we don't fully own. Report-only, never silent.
            if r["path"] not in skipped:
                skipped.add(r["path"])
                notes.append(f"skipped {r['path']}: --fix only rewrites flat "
                             "mcpServers/servers shapes")
            continue
        items.append({
            "path": r["path"], "name": r["name"], "client": r["client"],
            "key_path": r["key_path"], "config": r["config"],
            "where": _where(r),
            "reasons": "; ".join(dict.fromkeys(f["check"] for f in crit)),
            "runs": launch.summary(r["config"]),
        })
    return items, notes


class _Skip(Exception):
    """A file --fix will not rewrite; the message says why."""


def _load_for_rewrite(path: str) -> "tuple[object, bytes, dict]":
    """(data, raw bytes, style) of a config --fix may rewrite, or _Skip.

    Only plain UTF-8 JSON is rewritten: a file with comments or trailing
    commas (JSONC) cannot be written back without losing them."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise _Skip(f"cannot read it ({e.strerror or type(e).__name__})")
    bom = raw.startswith(codecs.BOM_UTF8)
    try:
        text = raw[len(codecs.BOM_UTF8):].decode("utf-8") if bom \
            else raw.decode("utf-8")
        data = json.loads(text)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _Skip("it is not plain UTF-8 JSON (comments, trailing commas "
                    "or another encoding?); remove the server by hand")
    m = re.search(r"\n([ \t]+)\S", text)
    style = {"bom": bom, "indent": m.group(1) if m else None,
             "crlf": "\r\n" in text, "final_newline": text.endswith("\n")}
    return data, raw, style


def _dump(data, style: dict) -> bytes:
    """`data` as JSON bytes in the style of the file it came from."""
    def dumps(ensure_ascii: bool) -> bytes:
        text = json.dumps(data, indent=style["indent"],
                          ensure_ascii=ensure_ascii)
        if style["crlf"]:
            text = text.replace("\n", "\r\n")
        if style["final_newline"]:
            text += "\r\n" if style["crlf"] else "\n"
        out = text.encode("utf-8")
        return codecs.BOM_UTF8 + out if style["bom"] else out
    try:
        return dumps(False)
    except UnicodeEncodeError:  # a lone surrogate: keep it as an escape
        return dumps(True)


def _write_backup(path: str, raw: bytes) -> str:
    """Save `raw` next to `path` under a name that is not taken yet."""
    base = f"{path}.mcp-gradecard.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_BINARY", 0))
    for n in range(1000):
        bak = base if n == 0 else f"{base}-{n}"
        try:
            fd = os.open(bak, flags, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        try:
            shutil.copystat(path, bak)
        except OSError:
            pass
        return bak
    raise OSError("no free backup name")


def _write_atomic(path: str, data: bytes) -> None:
    """Replace `path` with `data` in one step: a crash or a full disk leaves
    the old file, never half a new one."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                               prefix=os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            shutil.copymode(path, tmp)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _apply_fix(items: list[dict]) -> "tuple[list[str], bool]":
    """Remove the planned servers, one config file at a time.

    Each touched file is backed up first and replaced atomically in the style
    it had (indent, line endings, BOM). A server whose entry is no longer the
    one that was audited is left alone. Returns (lines to show, all ok)."""
    lines: list[str] = []
    ok = True
    by_path: dict[str, list[dict]] = {}
    for it in items:
        by_path.setdefault(it["path"], []).append(it)
    for shown, group in by_path.items():
        path = os.path.realpath(shown)  # a symlinked config stays a symlink
        try:
            data, raw, style = _load_for_rewrite(path)
        except _Skip as e:
            lines.append(f"skipped {shown}: {e}")
            continue
        removed = []
        for it in group:
            servers = _servers_at(data, it)
            if servers is None or it["name"] not in servers:
                lines.append(f"skipped '{it['name']}' in {shown}: it is no "
                             "longer there")
            elif servers[it["name"]] != it["config"]:
                lines.append(f"skipped '{it['name']}' in {shown}: the entry "
                             "changed since it was audited")
            else:
                del servers[it["name"]]
                removed.append(it)
        if not removed:
            continue
        try:
            bak = _write_backup(path, raw)
            lines.append(f"backed up {shown} -> {bak}")
            _write_atomic(path, _dump(data, style))
            check = _load_for_rewrite(path)[0]
            if check != data:
                raise OSError("the rewritten file does not read back as "
                              "intended")
        except OSError as e:
            ok = False
            lines.append(f"FAILED to rewrite {shown}: "
                         f"{e.strerror or e}; its backup is untouched")
            continue
        for it in removed:
            lines.append(f"removed '{it['name']}' ({it['reasons']}) from "
                         f"{shown}")
    return lines, ok


def _confirm_removal(count: int, files: int, yes: bool) -> str:
    """"yes", "no", or "refuse" when there is nobody to ask and no --yes."""
    if yes:
        return "yes"
    stdin = sys.stdin
    try:
        interactive = stdin is not None and stdin.isatty()
    except (OSError, ValueError, AttributeError):
        interactive = False
    if not interactive:
        return "refuse"
    sys.stderr.write(
        f"[mcp-gradecard] Remove {count} server(s) from {files} file(s)? Each "
        "file is backed up first. [y/N] ")
    sys.stderr.flush()
    try:
        answer = stdin.readline()
    except (OSError, ValueError):
        answer = ""
    return "yes" if answer.strip().lower() in ("y", "yes") else "no"


def _run_fix(results: list[dict], remove: bool,
             yes: bool) -> "tuple[int | None, bool]":
    """The --fix step. Shows exactly what would be removed, asks, then
    removes. Returns (exit code to stop with or None, whether a rewrite
    failed)."""
    items, notes = _plan_fix(results)
    for n in notes:
        _note(n)
    if not items:
        _note("--fix: nothing to remove")
        return None, False
    for it in items:
        _note(f"would remove '{it['name']}' ({it['reasons']}) from "
              f"{it['path']} [{it['client']}: {it['where']}]")
        _note(f"    it runs: {it['runs']}")
    if not remove:
        _note("dry run - nothing was changed. Re-run with --fix --remove to "
              "remove these (it asks first; --yes skips the question)")
        return None, False
    files = len({it["path"] for it in items})
    answer = _confirm_removal(len(items), files, yes)
    if answer == "refuse":
        _note(f"error: --fix --remove would remove {len(items)} server(s) "
              "but there is no terminal to ask on; re-run with --yes to "
              "confirm. Nothing was changed.")
        return 2, False
    if answer == "no":
        _note("nothing was removed")
        return None, False
    lines, ok = _apply_fix(items)
    for line in lines:
        _note(line)
    return None, not ok


def _harden_streams() -> None:
    """Never crash on a console that cannot encode a path or server name.

    Python's stderr already replaces unencodable characters; make stdout
    do the same instead of raising UnicodeEncodeError mid-report.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        # Both handlers raise UnicodeEncodeError on a character the code
        # page lacks: "strict" (the default) and "surrogateescape" (what a
        # piped stdout reports on Windows 11 / Python 3.11, with cp1252).
        if reconfigure is None or getattr(stream, "errors", None) not in (
                "strict", "surrogateescape"):
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


def _host_arg(text: str) -> str:
    """An --allow-host value. The error does not repeat it: it may be a URL
    with a credential in it."""
    try:
        return detectors.host_pattern(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-gradecard",
        description="Audit installed MCP servers: prompt-injection, "
                    "exfiltration endpoints, known-vulnerable versions, "
                    "floating pins, secret env vars.")
    p.add_argument("--config", action="append", default=None,
                   help="Explicit config file to audit (repeatable). "
                        "Default: auto-discover Claude Code (+project "
                        ".mcp.json, and the organization's "
                        "managed-mcp.json), Claude Desktop, Cursor, VS Code, "
                        "Windsurf, Zed.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    p.add_argument("--deep", action="store_true",
                   help="Also launch each stdio server and scan what it says "
                        "about itself and its tools (instructions, "
                        "descriptions, titles, schema texts) for prompt "
                        "injection - a heuristic: a "
                        "clean scan is not proof of safety. This EXECUTES the "
                        "servers: it lists them first. It skips the ones "
                        "with critical findings or others the audit could "
                        "not settle (--probe-critical launches them), the "
                        "ones from project config files in the current "
                        "directory (--probe-project launches them) and the "
                        'ones disabled in their config ("disabled": true, '
                        '"enabled": false; nothing launches them). Each one '
                        "it launches starts in an empty temporary directory, "
                        "not the one you are in, and its program is looked "
                        "up on PATH only. A signal "
                        "that ends mcp-gradecard meanwhile (Ctrl-C, SIGTERM, "
                        "SIGHUP) stops the servers first and exits 128 plus "
                        "its number, with no report.")
    p.add_argument("--probe-critical", action="store_true",
                   help="With --deep: also launch the servers the static "
                        "audit makes it skip: those with critical findings "
                        "(launching one runs the very command that was "
                        "flagged), a server it could not analyze, a URL it "
                        "could not take apart and a package registry over "
                        "plain http.")
    p.add_argument("--probe-project", action="store_true",
                   help="With --deep: also launch servers that come from "
                        "project config files found in the current directory "
                        "(.mcp.json, .cursor/mcp.json, .vscode/, .devin/, "
                        ".zed/settings.json). Skipped by default: whoever "
                        "wrote the project, say a repository you have just "
                        "cloned, chose the commands. Servers from your home "
                        "directory and from a --config you name are launched. "
                        "Servers from project files start in the current "
                        "directory; all others in an empty temporary one.")
    p.add_argument("--allow-host", action="append", default=[],
                   type=_host_arg, metavar="HOST",
                   help="Trust HOST (repeatable): a remote MCP server, a "
                        "package registry or an endpoint at HOST is not "
                        "reported when it is reached over https or wss, and "
                        "a package from a git repository there is judged by "
                        "its pin (git-source) instead of as an unknown "
                        "endpoint. HOST is a name (mcp.example.com), "
                        "*.example.com for every host below a name, or an "
                        "IPv4 address - not a URL, a port or a wildcard over "
                        "a whole top-level domain. Plain http is still "
                        "reported. There is no config file: give it on every "
                        "run. Without it only the hosts built in are "
                        "trusted (the README lists them).")
    p.add_argument("--format", choices=("human", "json", "sarif"),
                   default="human")
    p.add_argument("--fix", action="store_true",
                   help="List the servers launched via a downloader/shell or "
                        "curl|sh (critical suspicious-command / pipe-to-shell)"
                        " that --remove would delete, with what each one "
                        "runs. Dry run on its own.")
    p.add_argument("--remove", action="store_true",
                   help="With --fix: remove those servers. Shows what it will "
                        "remove and asks first (with no terminal to ask on it "
                        "refuses unless --yes is given); backs up each "
                        "config before rewriting it.")
    p.add_argument("--yes", action="store_true",
                   help="With --fix --remove: do not ask for confirmation.")
    p.add_argument("--online", action="store_true",
                   help="Also query OSV (api.osv.dev) for pinned npx/uvx "
                        "packages. Sends package names and versions.")
    p.add_argument("--fail-on", choices=("critical", "high", "medium", "low"),
                   default=None,
                   help="Exit 1 if any finding is at/above this severity; exit "
                        "2 instead of passing if a config file could not be "
                        "audited (unparseable, too large...).")
    return p


_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _explicit_config_error(path: str) -> str | None:
    """Return an error string if an explicit --config path can't be read.

    Missing/unreadable explicit configs fail closed: a scanner that can't
    read the file it was told to audit must not report "clean" (exit 0).
    Returns None when the file is fine.
    """
    try:
        st = os.stat(path)
    except OSError as e:
        return f"{e.strerror or 'cannot stat'}"
    if not stat.S_ISREG(st.st_mode):
        return "not a regular file"
    # Bit check (not os.access): works even when running as root, where
    # chmod 000 would still be readable via access() but is clearly meant
    # to be unreadable.
    if st.st_mode & 0o444 == 0:
        return "no read permission bits set"
    try:
        with open(path, "rb"):
            pass
    except OSError as e:
        return f"{e.strerror or 'cannot open'}"
    return None


# Windows does not report a pipe nobody reads as BrokenPipeError: print() of
# a small output works there (it only fills the buffer) and the flush then
# fails with a plain OSError(EINVAL) - at interpreter exit, as "Exception
# ignored", with exit status 120 - or, under `python -u`, out of print().
# A module-level flag, so tests can switch the rule on (and off) anywhere.
_IS_WINDOWS = os.name == "nt"


def _is_closed_pipe(e: BaseException) -> bool:
    """True when `e` means nobody is reading this pipe any more: a
    BrokenPipeError or any OSError with errno EPIPE, and, on Windows only,
    plain EINVAL. Anywhere else EINVAL is a real error and is not
    swallowed."""
    if not isinstance(e, OSError):
        return False
    return (isinstance(e, BrokenPipeError) or e.errno == errno.EPIPE
            or (_IS_WINDOWS and e.errno == errno.EINVAL))


def _discard_output(stream) -> None:
    """Point `stream`'s file descriptor at the null device, so what is
    still buffered (and the interpreter's own flush at exit) goes nowhere
    instead of failing again. A stream with no descriptor needs nothing."""
    try:
        with open(os.devnull, "wb") as null:
            os.dup2(null.fileno(), stream.fileno())
    except (OSError, ValueError, AttributeError):
        pass


class _PipeSafe:
    """Stand-in for sys.stdout / sys.stderr while main() runs.

    The reader of a pipe can quit at any moment (`mcp-gradecard
    | head -1`). Left alone, Python raises BrokenPipeError out of print()
    or, when the output was still buffered, prints "Exception ignored" at
    exit and replaces the exit code with 120 (see _IS_WINDOWS for how
    Windows words that failure). Here the first failed write or flush
    points the stream at the null device and the command carries on into
    it: a closed pipe acts like `> /dev/null`, the output stops and the
    exit code is whatever the command computed.

    That is the choice against the usual `except BrokenPipeError:
    sys.exit(1)` recipe: for `run` the exit code IS the verdict (0 pass,
    1 a case failed, 2 an error), and a shortened pipe must never turn a
    regression into a pass, or into some other number.
    """

    def __init__(self, stream):
        self._stream = stream
        self._dead = False

    def _call(self, name, *args):
        if self._dead:
            return
        try:
            getattr(self._stream, name)(*args)
        except OSError as e:
            if not _is_closed_pipe(e):
                raise
            self._dead = True
            _discard_output(self._stream)

    def write(self, text):
        self._call("write", text)
        return len(text)

    def flush(self):
        self._call("flush")

    def __getattr__(self, name):  # encoding, isatty(), reconfigure() ...
        return getattr(self._stream, name)


@contextlib.contextmanager
def _closed_pipe_tolerant():
    """Run the body with stdout and stderr wrapped in _PipeSafe."""
    real = (sys.stdout, sys.stderr)  # either is None under pythonw
    safe = tuple(_PipeSafe(s) if s is not None else None for s in real)
    sys.stdout, sys.stderr = safe
    try:
        yield
    finally:
        try:
            # Flush now, with the command done, while a closed pipe is
            # still handled. A small output only ever sits in the buffer,
            # so nothing has failed yet; left to the interpreter's flush
            # at exit, the error would be "Exception ignored" and the exit
            # code 120 instead of the command's own.
            for s in safe:
                if s is not None:
                    s.flush()
        finally:
            sys.stdout, sys.stderr = real


def _origin(exc: BaseException) -> str:
    """Where an exception came from, as "file.py:123": the innermost frame
    inside mcp_gradecard, else the innermost frame there is. Never its message,
    which can quote the config that was being audited."""
    package = os.path.dirname(os.path.abspath(__file__)) + os.sep
    frames = []
    tb = exc.__traceback__
    while tb is not None:
        frames.append((tb.tb_frame.f_code.co_filename, tb.tb_lineno))
        tb = tb.tb_next
    ours = [f for f in frames if os.path.abspath(f[0]).startswith(package)]
    path, line = (ours or frames or [("?", 0)])[-1]
    return f"{os.path.basename(path)}:{line}"


def _crash(exc: Exception) -> int:
    """An internal error is exit status 2 - the audit did not happen; 1
    means "findings" - named by its class and the line it came from, and
    never by its message or traceback (both can quote the config).
    MCP_AUDIT_DEBUG=1 prints the traceback as well, for whoever debugs
    mcp-gradecard; the exit status is 2 either way."""
    debug = bool(os.environ.get("MCP_AUDIT_DEBUG"))
    if debug:
        sys.stderr.write("".join(traceback.format_exception(exc)))
    _note(f"error: internal error ({type(exc).__name__} at {_origin(exc)}). "
          "This is a bug in mcp-gradecard, not a finding in your configs; no "
          "audit result was produced, so this run is not a clean bill of "
          "health."
          + ("" if debug else
             " Set MCP_AUDIT_DEBUG=1 to see the traceback (it can quote "
             "your config: read it before you share it)."))
    return 2


def _interrupted(signum: int, servers: bool = False) -> int:
    """The run was cut short by a signal. There is no verdict, so there is no
    report: a note on stderr says so, and the exit code is the one a shell
    reports for a process that the signal ended, 128 plus its number (Ctrl-C
    is 130). `servers`: --deep had servers running, and they were stopped."""
    try:
        name = signal.Signals(signum).name
    except ValueError:
        name = f"signal {signum}"
    text = f"interrupted by {name}; no report was produced"
    if servers:
        text += "; the servers --deep had started were stopped"
    try:
        _note(text)
    except (OSError, ValueError):
        # The terminal is gone (that is what SIGHUP says): nobody is left to
        # tell, and what is still buffered must not fail again at exit and
        # change the code.
        _discard_output(sys.stderr)
    return 128 + signum


def main(argv: list[str] | None = None) -> int:
    _harden_streams()
    # `mcp-gradecard | head -1` must neither traceback nor change the exit code
    # (the exit code is the verdict).
    with _closed_pipe_tolerant():
        try:
            return _main(argv)
        except deep_mod.Interrupted as e:   # --deep, from its handlers
            return _interrupted(e.signum, servers=True)
        except KeyboardInterrupt:           # Ctrl-C anywhere else
            return _interrupted(signal.SIGINT)
        except Exception as e:  # SystemExit is not an Exception
            return _crash(e)


def _main(argv: list[str] | None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.remove and not args.fix:
        parser.error("--remove only works together with --fix")
    if args.yes and not (args.fix and args.remove):
        parser.error("--yes only works together with --fix --remove")
    if args.probe_critical and not args.deep:
        parser.error("--probe-critical only works together with --deep")
    if args.probe_project and not args.deep:
        parser.error("--probe-project only works together with --deep")
    try:
        advisories = detectors.load_advisories()
    except detectors.AdvisoryFeedError as e:
        # A scanner without its feed would call vulnerable packages clean.
        _note(f"error: {e}; refusing to report results without it")
        return 2
    if args.config:
        for path in args.config:
            err = _explicit_config_error(path)
            if err is not None:
                _note(f"error: cannot read --config file '{path}': {err}")
                return 2
    discovered, warnings = discovery.discover(args.config)
    if args.config and warnings:
        # Fail closed: an explicit --config that exists but can't be parsed
        # or understood must never report "clean" (exit 0).
        for w in warnings:
            _note(f"error: cannot audit --config '{w['path']}': "
                  f"{w['reason']}")
        return 2

    allow_hosts = tuple(dict.fromkeys(args.allow_host))
    results = _audit_all(discovered, advisories, args.online, allow_hosts)

    fix_failed = False
    if args.fix:
        stop, fix_failed = _run_fix(results, args.remove, args.yes)
        if stop is not None:
            return stop
        # re-audit so the report reflects reality
        discovered, warnings = discovery.discover(args.config)
        results = _audit_all(discovered, advisories, args.online, allow_hosts)

    if args.deep:  # after --fix: once, and never a server --fix just removed
        _deep_pass(results, args.probe_critical, args.probe_project)

    # Names, paths and project directories come from the config files: what
    # is printed has its control and bidi characters spelled out (sanitize),
    # whatever the format.
    if args.format == "sarif":
        print(json.dumps(redact.sanitize_tree(
            scoring.render_sarif(results, __version__)), indent=2))
    elif args.format == "json":
        out = {"results": [{k: r[k] for k in
                            ("name", "client", "path", "project", "findings",
                             "score", "grade") if k in r} for r in results],
               "summary": scoring.summarize(results),
               "warnings": warnings}
        print(json.dumps(redact.sanitize_tree(out), indent=2))
    if args.format != "human":
        if args.format == "sarif":
            for w in warnings:  # JSON carries these inline; SARIF can't
                _note(f"warning: skipped {w['path']} <{w['client']}>: "
                      f"{w['reason']}")
        if not discovered:
            _note("warning: no MCP configs discovered — this is not a "
                  "clean bill of health")
    else:
        print(scoring.render_human(results, warnings=warnings,
                                   n_configs=len(discovered),
                                   configs=discovered))

    if fix_failed:
        return 2
    if args.fail_on:
        threshold = _SEV_RANK[args.fail_on]
        for r in results:
            for f in r["findings"]:
                if _SEV_RANK.get(f["severity"], 0) >= threshold:
                    return 1
        if warnings:
            # A config that could not be audited might have held anything, so
            # a gate that passes here would be lying.
            _note(f"error: --fail-on: {len(warnings)} config file(s) could "
                  "not be audited (see the warnings), so a pass cannot be "
                  "promised")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
