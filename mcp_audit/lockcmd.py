"""`mcp-audit lock`, `mcp-audit verify` and `mcp-audit who-added`.

lock writes mcp.lock (see docs/LOCKFILE.md): a SHA-256 of every tool each
configured server lists. verify compares the servers as they are now against
it and exits 1 on drift. who-added says which git commit and author put each
server into a config file.

Where the tool lists come from: a file you give (--from-tools-json: nothing
is launched, so it is safe and works offline) or, only when you ask for it
with --launch, the servers themselves (that RUNS them, with your rights).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import subprocess
import sys
import tempfile

from . import __version__
from . import detectors
from . import discovery
from . import lockfile as lf
from . import redact

EXIT_OK, EXIT_DRIFT, EXIT_ERROR = 0, 1, 2
DEFAULT_LOCK = "mcp.lock"
MAX_TOOLS_JSON = 64 * 1024 * 1024


class _Stop(Exception):
    """A problem to tell the user; the command ends with `code`."""

    def __init__(self, text: str, code: int = EXIT_ERROR):
        super().__init__(text)
        self.text, self.code = text, code


def _say(text: str) -> None:
    sys.stderr.write(f"[mcp-audit] {redact.clean(text)}\n")


def _show(text) -> str:
    """A name from a config or a server, safe to print."""
    return redact.sanitize(redact.redact_text(str(text)))


# -- the servers a run is about ----------------------------------------------


def jail_inner(command: str, args: list) -> "tuple[str, list]":
    """The command a server really runs when its config starts it through
    `mcp-jail ... -- <command> <args>`: the part after `--`. The lock is of
    the server, not of the wrapper."""
    prog = os.path.basename(command.replace("\\", "/")).lower()
    for ext in (".exe", ".cmd", ".bat"):
        if prog.endswith(ext):
            prog = prog[:-len(ext)]
    if prog == "mcp-jail" and "--" in args:
        rest = args[args.index("--") + 1:]
        if rest and all(isinstance(a, str) for a in rest):
            return rest[0], rest[1:]
    return command, args


def entry_fingerprint(cfg) -> "str | None":
    """The command fingerprint of a server entry, or None when the entry has
    no shape a fingerprint can be made of."""
    if not isinstance(cfg, dict):
        return None
    try:
        urls = detectors.remote_urls(cfg)
        if urls and not cfg.get("command"):
            return lf.command_fingerprint(url=urls[0][1])
        command, args = cfg.get("command"), cfg.get("args")
        if isinstance(command, str) and command and (
                args is None or isinstance(args, list)):
            command, args = jail_inner(command, list(args or []))
            return lf.command_fingerprint(command, args)
    except lf.LockError:
        return None
    return None


class Srv:
    """One server entry of one config, and the key it has in the lock."""

    def __init__(self, result: dict):
        self.result = result
        self.name = result["name"]
        self.client = result["client"]
        self.path = result["path"]
        self.cfg = result["config"]
        self.project = result.get("project")
        self.fingerprint = entry_fingerprint(self.cfg)
        self.key = self.name


def servers_of(results: "list[dict]") -> "list[Srv]":
    """The servers of a run with their lock keys: the name, or `name@client`
    (then `name@client:where`) when one name is used for different commands.
    The same name with the same command in two configs is one server."""
    servers = [Srv(r) for r in results]
    by_name: "dict[str, list[Srv]]" = {}
    for s in servers:
        by_name.setdefault(s.name, []).append(s)
    for name, group in by_name.items():
        if len({s.fingerprint for s in group}) <= 1:
            continue
        for s in group:
            s.key = f"{name}@{s.client}"
        if len({s.key for s in group}) < len(group):
            for s in group:
                s.key = f"{name}@{s.client}:{s.project or s.path}"
    return servers


def _unique(servers: "list[Srv]") -> "list[Srv]":
    """One Srv per key (the same server found in two configs)."""
    seen: "dict[str, Srv]" = {}
    for s in servers:
        seen.setdefault(s.key, s)
    return list(seen.values())


# -- tool lists from a file ---------------------------------------------------


def read_tools_json(path: str):
    """The --from-tools-json file: {"<server>": [tool, ...]} (a list may be
    {"tools": [...]}, a tools/list result), or a single list for a single
    server. Returns ({key: list}, single list or None)."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_TOOLS_JSON + 1)
    except OSError as e:
        raise _Stop(f"cannot read --from-tools-json {path}: "
                    f"{e.strerror or type(e).__name__}") from None
    if len(raw) > MAX_TOOLS_JSON:
        raise _Stop(f"--from-tools-json {path} is too large")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        raise _Stop(f"--from-tools-json {path} is not valid JSON") from None

    def as_list(value, label):
        if isinstance(value, dict) and isinstance(value.get("tools"), list):
            value = value["tools"]
        if not isinstance(value, list):
            raise _Stop(f"--from-tools-json {path}: {label} is not a list of "
                        "tools (or a tools/list result)")
        return value

    if isinstance(data, list) or (isinstance(data, dict)
                                  and isinstance(data.get("tools"), list)):
        return {}, as_list(data, "the file")
    if not isinstance(data, dict):
        raise _Stop(f"--from-tools-json {path} is not an object or a list")
    return {k: as_list(v, f"'{_show(k)}'") for k, v in data.items()}, None


def tools_from_json(servers: "list[Srv]", mapping: dict, single) -> "tuple[dict, list]":
    """({key: tools}, notes) for the servers the file speaks about."""
    out: dict = {}
    notes = []
    if single is not None:
        if len(servers) != 1:
            raise _Stop("the tools file is one bare list, so it needs exactly "
                        f"one server (here: {len(servers)}); name the server "
                        "with --server, or use a file of the form "
                        '{"<server>": [...]}')
        out[servers[0].key] = single
        return out, notes
    names: "dict[str, list[Srv]]" = {}
    for s in servers:
        names.setdefault(s.name, []).append(s)
    used = set()
    for key, tools in mapping.items():
        hit = [s for s in servers if s.key == key]
        if not hit and len(names.get(key, [])) >= 1:
            hit = names[key]
        if not hit:
            continue
        used.add(key)
        for s in hit:
            out[s.key] = tools
    for key in mapping:
        if key not in used:
            notes.append(f"the tools file has '{_show(key)}', which is not a "
                         "server in the configs; ignored")
    return out, notes


# -- the shared command line --------------------------------------------------


def _common(p: argparse.ArgumentParser, lock_option: str) -> None:
    p.add_argument("--config", action="append", default=None, metavar="FILE",
                   help="config file to read (repeatable). Default: "
                        "auto-discover every MCP client's config.")
    p.add_argument("--server", action="append", default=None, metavar="NAME",
                   help="only this server (repeatable)")
    p.add_argument("--from-tools-json", metavar="FILE",
                   help='tool lists from a file instead of from the servers: '
                        '{"<server>": [tool, ...]}, or one bare list for a '
                        'single server. Nothing is launched.')
    p.add_argument("--launch", action="store_true",
                   help="start each stdio server and ask it for its tools "
                        "(tools/list). THIS RUNS THE SERVERS' COMMANDS with "
                        "your rights: only use it on a config you wrote. "
                        "Servers with critical findings, from a project file "
                        "or disabled are left alone unless the flags below "
                        "say otherwise.")
    p.add_argument("--probe-critical", action="store_true",
                   help="with --launch: also start servers the audit rated "
                        "critical or could not read")
    p.add_argument("--probe-project", action="store_true",
                   help="with --launch: also start servers that come from "
                        "project files in the current directory")
    p.add_argument("--allow-host", action="append", default=[], metavar="HOST",
                   help="trust HOST (as in the main command; used to decide "
                        "which servers --launch leaves alone)")
    if lock_option:
        p.add_argument("--lockfile", default=DEFAULT_LOCK, metavar="FILE",
                       help=f"the lockfile (default: {DEFAULT_LOCK})")


def _check_launch_flags(args, parser) -> None:
    if args.probe_critical and not args.launch:
        parser.error("--probe-critical only works together with --launch")
    if args.probe_project and not args.launch:
        parser.error("--probe-project only works together with --launch")


def _gather(args, parser) -> "tuple[list[Srv], dict, list[str], bool]":
    """(servers, tools by key, notes, tools_requested) for lock and verify."""
    from . import cli       # the audit and launch machinery live there
    if args.config:
        for path in args.config:
            err = cli._explicit_config_error(path)
            if err is not None:
                raise _Stop(f"cannot read --config file '{path}': {err}")
    discovered, warnings = discovery.discover(args.config)
    notes = []
    for w in warnings:
        if args.config:
            raise _Stop(f"cannot read --config '{w['path']}': {w['reason']}")
        notes.append(f"skipped {w['path']} <{w['client']}>: {w['reason']}")
    if not discovered:
        raise _Stop("no MCP configs found; name one with --config")
    allow = []
    for h in args.allow_host:
        try:
            allow.append(detectors.host_pattern(h))
        except ValueError as e:
            parser.error(str(e))
    results = cli._audit_all(discovered, detectors.load_advisories(), False,
                             tuple(dict.fromkeys(allow)))
    servers = servers_of(results)
    if args.server:
        want = set(args.server)
        servers = [s for s in servers if s.name in want or s.key in want]
        missing = want - {s.name for s in servers} - {s.key for s in servers}
        if missing:
            raise _Stop("no such server in the configs: "
                        + ", ".join(sorted(_show(m) for m in missing)))
    tools: dict = {}
    if args.from_tools_json:
        mapping, single = read_tools_json(args.from_tools_json)
        tools, more = tools_from_json(_unique(servers), mapping, single)
        notes += more
    if args.launch:
        chosen = [s for s in _unique(servers) if s.key not in tools]
        wanted = {id(s.result) for s in chosen}
        cli._deep_pass([s.result for s in servers if id(s.result) in wanted],
                       args.probe_critical, args.probe_project,
                       flag="--launch")
        for s in chosen:
            raw = s.result.get("raw_tools")
            if raw is not None and s.result.get("probe_complete"):
                tools[s.key] = raw
            elif raw is not None:
                notes.append(f"'{_show(s.key)}': the server's tool list was "
                             "cut short (too many tools or pages), so it "
                             "cannot be locked or verified")
    return servers, tools, notes, bool(args.from_tools_json or args.launch)


def _why_unread(s: Srv) -> str:
    from . import deep as deep_mod
    reason = deep_mod.not_launchable(s.cfg)
    if reason:
        return reason + "; give its tools with --from-tools-json"
    if s.fingerprint is None:
        return "the entry has no command or URL to fingerprint"
    return ("it was not started (see the notes above) or did not answer; "
            "give its tools with --from-tools-json")


# -- lock ---------------------------------------------------------------------


def _atomic_write(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".mcp.lock-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _load_lock(path: str) -> dict:
    try:
        with open(path, "rb") as f:
            raw = f.read(lf.MAX_LOCK_BYTES + 1)
    except FileNotFoundError:
        raise _Stop(f"no lockfile at {path}; create one with: mcp-audit lock "
                    "--from-tools-json tools.json   (or --launch)") from None
    except OSError as e:
        raise _Stop(f"cannot read the lockfile {path}: "
                    f"{e.strerror or type(e).__name__}") from None
    try:
        return lf.parse_lock(raw)
    except lf.LockError as e:
        raise _Stop(f"{path} is not a valid lockfile: {e}") from None


def _changes(old: dict, new: dict) -> "list[tuple[str, lf.Drift]]":
    """What differs between two locks: [(server key, Drift)]."""
    out = []
    for key, entry in new["servers"].items():
        before = old["servers"].get(key)
        if before is None:
            out.append((key, lf.Drift(lf.NEW_SERVER, "", "not in the old "
                                      "lockfile")))
            continue
        if before["command_fingerprint"] != entry["command_fingerprint"]:
            out.append((key, lf.Drift(lf.COMMAND_CHANGED, "", "started "
                                      "differently")))
        for name, hashes in entry["tools"].items():
            if name not in before["tools"]:
                out.append((key, lf.Drift(lf.NEW_TOOL, name, "")))
            else:
                out += [(key, d) for d in lf.diff_entry(
                    name, before["tools"][name], hashes)]
        for name in before["tools"]:
            if name not in entry["tools"]:
                out.append((key, lf.Drift(lf.REMOVED_TOOL, name, "")))
    for key in old["servers"]:
        if key not in new["servers"]:
            out.append((key, lf.Drift(lf.REMOVED_SERVER, "", "")))
    return out


def _line(key: str, d: "lf.Drift") -> str:
    what = lf.KIND_TEXT[d.kind]
    tool = f" '{_show(d.tool)}'" if d.tool else ""
    more = f" ({d.detail})" if d.detail else ""
    return f"  [{_show(key)}]{tool}: {what}{more}"


def cmd_lock(argv: "list[str]") -> int:
    p = argparse.ArgumentParser(
        prog="mcp-audit lock",
        description="Write mcp.lock: a SHA-256 of every tool each configured "
                    "server lists, so a later change to a description or a "
                    "schema (a 'rug pull') can be caught. Give the tool "
                    "lists with --from-tools-json (nothing is launched) or "
                    "ask the servers with --launch (that runs them).")
    _common(p, True)
    p.add_argument("--out", metavar="FILE",
                   help="where to write (default: the --lockfile name)")
    p.add_argument("--accept-changes", action="store_true",
                   help="overwrite an existing lockfile whose approvals "
                        "differ (the differences are listed first). Without "
                        "it, an existing lockfile is never changed.")
    p.add_argument("--save-tools", metavar="FILE",
                   help="also write the tool lists that were read to FILE "
                        "(a --from-tools-json file for later offline checks)")
    args = p.parse_args(argv)
    _check_launch_flags(args, p)
    try:
        return _lock(args, p)
    except _Stop as e:
        _say(f"error: {e.text}")
        return e.code
    except discovery.ConfigError as e:
        _say(f"error: {e}")
        return EXIT_ERROR


def _lock(args, parser) -> int:
    if not args.from_tools_json and not args.launch:
        raise _Stop("lock needs the servers' tool lists, otherwise the "
                    "lockfile would approve no tools. Give them with "
                    "--from-tools-json FILE (nothing is launched) or ask the "
                    "servers with --launch (that RUNS them).")
    out_path = args.out or args.lockfile
    servers, tools, notes, _ = _gather(args, parser)
    lock = lf.new_lock(f"mcp-audit {__version__}")
    locked = unread = 0
    for s in _unique(servers):
        if s.fingerprint is None:
            notes.append(f"'{_show(s.key)}' not locked: " + _why_unread(s))
            unread += 1
            continue
        if s.key not in tools:
            notes.append(f"'{_show(s.key)}' not locked: " + _why_unread(s))
            unread += 1
            continue
        entries, problems = lf.tools_entries(tools[s.key])
        if problems:
            raise _Stop(f"'{_show(s.key)}' lists a tool that cannot be "
                        f"locked ({_show(problems[0].tool)}: "
                        f"{problems[0].detail}); fix it and run again")
        lock["servers"][s.key] = lf.server_entry(s.fingerprint, entries)
        locked += 1
    if not locked:
        for n in notes:
            _say(n)
        raise _Stop("no server could be locked (see the notes above)")

    if os.path.exists(out_path):
        existing = _load_lock(out_path)
        configured = {s.key for s in servers}
        for key, entry in existing["servers"].items():
            # a server that was not read this time (or not asked for) keeps
            # its old approval; one that is no longer configured is dropped
            if key not in lock["servers"] and (args.server
                                               or key in configured):
                lock["servers"][key] = entry
        changes = _changes(existing, lock)
        if changes and not args.accept_changes:
            for n in notes:
                _say(n)
            _say(f"{out_path} already exists and these approvals would "
                 "change:")
            for key, d in changes:
                sys.stderr.write(_line(key, d) + "\n")
            _say("nothing was written. If you have read the changes and "
                 "approve them, run again with --accept-changes.")
            return EXIT_DRIFT
    for n in notes:
        _say(n)
    try:
        _atomic_write(out_path, lf.dump_lock(lock))
    except OSError as e:
        raise _Stop(f"cannot write {out_path}: "
                    f"{e.strerror or type(e).__name__}") from None
    if args.save_tools:
        snap = {s.key: tools[s.key] for s in _unique(servers)
                if s.key in tools}
        try:
            _atomic_write(args.save_tools, json.dumps(
                snap, sort_keys=True, indent=2, ensure_ascii=False) + "\n")
        except OSError as e:
            raise _Stop(f"cannot write {args.save_tools}: "
                        f"{e.strerror or type(e).__name__}") from None
    n_tools = sum(len(e["tools"]) for e in lock["servers"].values())
    print(f"wrote {out_path}: {len(lock['servers'])} server(s), "
          f"{n_tools} tool(s)"
          + (f"; {unread} server(s) not locked" if unread else ""))
    return EXIT_OK


# -- verify -------------------------------------------------------------------


def cmd_verify(argv: "list[str]") -> int:
    p = argparse.ArgumentParser(
        prog="mcp-audit verify",
        description="Check the configured servers against mcp.lock. Exit 0 "
                    "when nothing differs, 1 on drift (a new tool, a "
                    "changed description or schema, a changed command, a "
                    "new server), 2 when it could not check.")
    _common(p, True)
    p.add_argument("--format", choices=("human", "json"), default="human")
    p.add_argument("--require-tools", action="store_true",
                   help="exit 2 if tool definitions were not checked (no "
                        "--from-tools-json and no --launch)")
    p.add_argument("--strict", action="store_true",
                   help="count hints (a removed tool or server, changed "
                        "annotations) as drift too")
    args = p.parse_args(argv)
    _check_launch_flags(args, p)
    try:
        return _verify(args, p)
    except _Stop as e:
        _say(f"error: {e.text}")
        return e.code
    except discovery.ConfigError as e:
        _say(f"error: {e}")
        return EXIT_ERROR


def verify_servers(lock: dict, servers: "list[Srv]", tools: dict,
                   tools_requested: bool, partial: bool = False) -> dict:
    """The comparison, as data: {"drift": [(key, Drift)], "unverified":
    [key], "checked": [key]}."""
    drift: "list[tuple[str, lf.Drift]]" = []
    unverified: "list[str]" = []
    checked: "list[str]" = []
    seen = set()
    for s in _unique(servers):
        seen.add(s.key)
        entry = lock["servers"].get(s.key)
        if entry is None:
            drift.append((s.key, lf.Drift(lf.NEW_SERVER, "",
                                          "configured but not in the "
                                          "lockfile")))
            continue
        if s.fingerprint is None:
            drift.append((s.key, lf.Drift(lf.COMMAND_CHANGED, "",
                                          "the entry no longer has a "
                                          "command or URL")))
        elif s.fingerprint != entry["command_fingerprint"]:
            drift.append((s.key, lf.Drift(lf.COMMAND_CHANGED, "",
                                          "it is started differently from "
                                          "when it was locked")))
        if s.key in tools:
            checked.append(s.key)
            drift += [(s.key, d) for d in lf.diff_tools(entry["tools"],
                                                       tools[s.key])]
        elif tools_requested:
            unverified.append(s.key)
    if not partial:
        for key in lock["servers"]:
            if key not in seen:
                drift.append((key, lf.Drift(lf.REMOVED_SERVER, "",
                                            "in the lockfile, not configured")))
    return {"drift": drift, "unverified": unverified, "checked": checked}


def _verify(args, parser) -> int:
    lock = _load_lock(args.lockfile)
    servers, tools, notes, requested = _gather(args, parser)
    res = verify_servers(lock, servers, tools, requested,
                         partial=bool(args.server))
    hard = [(k, d) for k, d in res["drift"]
            if args.strict or d.kind not in lf.HINT_KINDS]
    hints = [(k, d) for k, d in res["drift"] if (k, d) not in hard]
    tools_checked = bool(res["checked"])
    code = EXIT_OK
    if hard:
        code = EXIT_DRIFT
    elif res["unverified"] or (args.require_tools and not tools_checked):
        code = EXIT_ERROR
    if args.format == "json":
        doc = {
            "ok": code == EXIT_OK, "exit": code,
            "tools_checked": tools_checked,
            "checked": [_show(k) for k in res["checked"]],
            "unverified": [_show(k) for k in res["unverified"]],
            "drift": [{"server": _show(k), "tool": _show(d.tool),
                       "kind": d.kind, "text": lf.KIND_TEXT[d.kind],
                       "detail": _show(d.detail), "hint": (k, d) in hints}
                      for k, d in res["drift"]],
            "notes": [redact.clean(n) for n in notes],
        }
        print(json.dumps(doc, indent=2, sort_keys=True))
        return code
    for n in notes:
        _say(n)
    if not requested:
        _say("tool definitions were NOT checked: only the servers and how "
             "they are started were. Add --from-tools-json FILE or --launch "
             "to check the tools themselves.")
    for key in res["unverified"]:
        _say(f"'{_show(key)}' could not be checked: " + _why_unread(
            next(s for s in servers if s.key == key)))
    if hard:
        print(f"DRIFT: {len(hard)} difference(s) from {args.lockfile}")
        for key, d in hard:
            print(_line(key, d))
    if hints:
        print(("also (counted as drift because of --strict):" if args.strict
               else "also (hints, not drift):"))
        for key, d in hints:
            print(_line(key, d))
    if code == EXIT_OK:
        n = sum(len(lock["servers"][k]["tools"]) for k in res["checked"]
                if k in lock["servers"])
        print(f"ok: {len(res['checked'])} server(s) match {args.lockfile} "
              f"({n} tool(s) checked)" if tools_checked else
              f"ok: the servers and their commands match {args.lockfile} "
              "(tools not checked)")
    return code


# -- who-added ----------------------------------------------------------------

#: git settings that keep it from running anything the repository names
#: (a diff driver, a pager, a file-system monitor): the repository may be one
#: you have just cloned.
_GIT_SAFE = ("-c", "core.fsmonitor=false", "-c", "core.pager=cat",
             "-c", "diff.external=", "-c", "core.hooksPath=")
_SEP = "\x1f"


def _git(args: "list[str]", cwd: str) -> "tuple[int, str]":
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0",
               LC_ALL="C")
    for var in ("GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_DIR",
                "GIT_WORK_TREE"):
        env.pop(var, None)
    try:
        r = subprocess.run(["git", *_GIT_SAFE, *args], cwd=cwd, env=env,
                           capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    return r.returncode, r.stdout.decode("utf-8", "replace")


def _history(path: str, key: str) -> "tuple[str, list[dict]]":
    """("", commits) for the commits that changed how often `"key"` occurs in
    the file, newest first; or (why not, [])."""
    directory = os.path.dirname(os.path.abspath(path))
    code, top = _git(["rev-parse", "--show-toplevel"], directory)
    if code == 127:
        return "git is not installed", []
    if code != 0:
        return "not in a git repository", []
    code, tracked = _git(["ls-files", "--error-unmatch", "--",
                          os.path.basename(path)], directory)
    if code != 0:
        return "the file is not tracked by git", []
    needle = json.dumps(key, ensure_ascii=False)
    code, out = _git(
        ["log", "--no-textconv", "--no-ext-diff", "--no-color",
         "-S" + needle, "--format=%H" + _SEP + "%an" + _SEP + "%ae" + _SEP
         + "%aI" + _SEP + "%s", "--", os.path.basename(path)], directory)
    if code != 0:
        return "git could not read the history", []
    commits = []
    for line in out.splitlines():
        parts = line.split(_SEP)
        if len(parts) == 5:
            commits.append(dict(zip(("hash", "author", "email", "date",
                                     "subject"), parts)))
    code, status = _git(["status", "--porcelain", "--",
                         os.path.basename(path)], directory)
    if code == 0 and status.strip():
        return "uncommitted", commits
    return "", commits


def _commit_text(c: dict) -> str:
    return _show(f"{c['hash'][:10]} {c['date'][:10]} {c['author']} "
                 f"<{c['email']}> {c['subject']}")


def cmd_who_added(argv: "list[str]") -> int:
    p = argparse.ArgumentParser(
        prog="mcp-audit who-added",
        description="For each server in the configs, show the git commit "
                    "and author that first put it there (and the latest "
                    "that changed it). Reads the local git history only: "
                    "nothing is fetched. Works for config files that are "
                    "tracked by git, such as a project's .mcp.json.")
    p.add_argument("--config", action="append", default=None, metavar="FILE")
    p.add_argument("--server", action="append", default=None, metavar="NAME")
    p.add_argument("--format", choices=("human", "json"), default="human")
    args = p.parse_args(argv)
    try:
        if args.config:
            from . import cli
            for path in args.config:
                err = cli._explicit_config_error(path)
                if err is not None:
                    raise _Stop(f"cannot read --config file '{path}': {err}")
        discovered, _warn = discovery.discover(args.config)
        rows = []
        done = set()
        for g in discovered:
            for name in g["servers"]:
                if args.server and name not in args.server:
                    continue
                if (g["path"], name) in done:
                    continue
                done.add((g["path"], name))
                why, commits = _history(g["path"], name)
                rows.append({"server": name, "client": g["client"],
                             "path": g["path"], "why": why,
                             "commits": commits})
    except _Stop as e:
        _say(f"error: {e.text}")
        return e.code
    except discovery.ConfigError as e:
        _say(f"error: {e}")
        return EXIT_ERROR
    if args.format == "json":
        print(json.dumps(redact.sanitize_tree(rows), indent=2,
                         sort_keys=True))
        return EXIT_OK
    if not rows:
        print("no servers found")
    for r in rows:
        print(f"{_show(r['server'])} <{_show(r['client'])}> in "
              f"{_show(r['path'])}")
        c = r["commits"]
        if r["why"] and r["why"] != "uncommitted":
            print(f"  history: {r['why']}")
        elif not c:
            print("  history: no commit mentions it"
                  + (" (it is not committed yet)" if r["why"] else ""))
        else:
            print("  added by:   " + _commit_text(c[-1]))
            if len(c) > 1:
                print("  last touch: " + _commit_text(c[0]))
            if r["why"] == "uncommitted":
                print("  note: the file has uncommitted changes")
    return EXIT_OK
