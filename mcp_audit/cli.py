"""mcp-audit: `npm audit` for your agent's MCP tool supply chain."""

import argparse
import json
import os
import shutil
import stat
import sys
import time

from . import __version__
from . import deep as deep_mod
from . import detectors
from . import discovery
from . import scoring


def _audit_one(name: str, cfg: dict, client: str, path: str,
               deep: bool, advisories: list[dict],
               online: bool = False) -> dict:
    findings = detectors.audit_server(name, cfg, advisories)
    if online:
        findings.extend(detectors.detect_osv(name, cfg))
    tools: list[dict] = []
    if deep:
        probe = deep_mod.probe_server(cfg)
        if probe["ok"]:
            tools = probe["tools"]
            findings.extend(deep_mod.audit_descriptions(tools))
        elif probe["error"]:
            findings.append({"severity": "low", "check": "deep-probe",
                             "message": f"--deep probe: {probe['error']}"})
    score, grade = scoring.score(findings)
    return {"name": name, "client": client, "path": path,
            "config": cfg, "findings": findings,
            "score": score, "grade": grade, "tools": tools}


def _backup(path: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    bak = f"{path}.mcp-audit.bak-{stamp}"
    shutil.copy2(path, bak)
    return bak


# Only unambiguous launch-time attacks are fixable. URL/description/advisory
# findings are report-only: they are too often legitimate config.
FIXABLE_CHECKS = ("suspicious-command", "pipe-to-shell")


def _apply_fix(results: list[dict], remove: bool = False) -> list[str]:
    """Remove servers with critical suspicious-command/pipe-to-shell findings.

    Without remove=True (--remove) this is a dry run that only reports.
    Backs up each touched config first. Returns human-readable actions."""
    actions: list[str] = []
    # group results by config path
    by_path: dict[str, list[dict]] = {}
    for r in results:
        by_path.setdefault(r["path"], []).append(r)

    for path, group in by_path.items():
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
        if "mcpServers" not in data and "servers" not in data:
            # e.g. VS Code's nested {"mcp": {"servers": ...}} shape: we don't
            # rewrite layouts we don't fully own. Report-only, never silent.
            actions.append(f"skipped {path}: --fix only rewrites flat "
                           "mcpServers/servers shapes")
            continue
        key = "mcpServers" if "mcpServers" in data else "servers"
        servers = data.get(key, {})
        changed = False
        for r in group:
            crit = [f for f in r["findings"]
                    if f["severity"] == "critical"
                    and f["check"] in FIXABLE_CHECKS]
            if crit and r["name"] in servers and not remove:
                reasons = "; ".join(c["check"] for c in crit)
                actions.append(f"would remove '{r['name']}' ({reasons}) — "
                               "re-run with --fix --remove to apply")
                continue
            if crit and r["name"] in servers:
                if not changed:
                    bak = _backup(path)
                    actions.append(f"backed up {path} -> {bak}")
                    changed = True
                del servers[r["name"]]
                reasons = "; ".join(c["check"] for c in crit)
                actions.append(f"removed '{r['name']}' ({reasons})")
        if changed:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
    return actions


def _harden_streams() -> None:
    """Never crash on a console that cannot encode a path or server name.

    Python's stderr already replaces unencodable characters; make stdout
    do the same instead of raising UnicodeEncodeError mid-report.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None or getattr(stream, "errors", None) != "strict":
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Audit installed MCP servers: prompt-injection, "
                    "exfiltration endpoints, known-vulnerable versions, "
                    "floating pins, secret env vars.")
    p.add_argument("--config", action="append", default=None,
                   help="Explicit config file to audit (repeatable). "
                        "Default: auto-discover Claude Code (+project "
                        ".mcp.json), Claude Desktop, Cursor, VS Code, "
                        "Windsurf, Zed.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    p.add_argument("--deep", action="store_true",
                   help="Also spawn each server and scan live tool "
                        "descriptions (executes server binaries).")
    p.add_argument("--format", choices=("human", "json", "sarif"),
                   default="human")
    p.add_argument("--fix", action="store_true",
                   help="List servers launched via a downloader/shell or "
                        "curl|sh (critical suspicious-command / pipe-to-shell)"
                        " that --remove would delete. Dry run on its own.")
    p.add_argument("--remove", action="store_true",
                   help="With --fix: actually remove those servers, after "
                        "backing up each config.")
    p.add_argument("--online", action="store_true",
                   help="Also query OSV (api.osv.dev) for pinned npx/uvx "
                        "packages. Sends package names and versions.")
    p.add_argument("--fail-on", choices=("critical", "high", "medium", "low"),
                   default=None,
                   help="Exit non-zero if any finding at/above this severity.")
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


def main(argv: list[str] | None = None) -> int:
    _harden_streams()
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.remove and not args.fix:
        parser.error("--remove only works together with --fix")
    if args.config:
        for path in args.config:
            err = _explicit_config_error(path)
            if err is not None:
                sys.stderr.write(
                    f"[mcp-audit] error: cannot read --config file "
                    f"'{path}': {err}\n")
                return 2
    discovered, warnings = discovery.discover(args.config)
    if args.config and warnings:
        # Fail closed: an explicit --config that exists but can't be parsed
        # or understood must never report "clean" (exit 0).
        for w in warnings:
            sys.stderr.write(
                f"[mcp-audit] error: cannot audit --config "
                f"'{w['path']}': {w['reason']}\n")
        return 2
    advisories = detectors.load_advisories()

    results = []
    for d in discovered:
        for name, cfg in d["servers"].items():
            results.append(_audit_one(name, cfg, d["client"], d["path"],
                                      args.deep, advisories, args.online))

    if args.fix:
        for a in _apply_fix(results, remove=args.remove):
            sys.stderr.write(f"[mcp-audit] {a}\n")
        # re-audit so the report reflects reality
        discovered, warnings = discovery.discover(args.config)
        results = []
        for d in discovered:
            for name, cfg in d["servers"].items():
                results.append(_audit_one(name, cfg, d["client"], d["path"],
                                          args.deep, advisories, args.online))

    if args.format == "sarif":
        print(json.dumps(scoring.render_sarif(results, __version__), indent=2))
    elif args.format == "json":
        out = {"results": [{k: r[k] for k in
                            ("name", "client", "path", "findings",
                             "score", "grade")} for r in results],
               "summary": scoring.summarize(results),
               "warnings": warnings}
        print(json.dumps(out, indent=2))
    if args.format != "human":
        if args.format == "sarif":
            for w in warnings:  # JSON carries these inline; SARIF can't
                sys.stderr.write(f"[mcp-audit] warning: skipped {w['path']} "
                                 f"<{w['client']}>: {w['reason']}\n")
        if not discovered:
            sys.stderr.write(
                "[mcp-audit] warning: no MCP configs discovered — this is "
                "not a clean bill of health\n")
    else:
        print(scoring.render_human(results, warnings=warnings,
                                   n_configs=len(discovered),
                                   configs=discovered))
        if args.deep:
            sys.stderr.write(
                "[mcp-audit] --deep executes server binaries; only probe "
                "servers you already trust enough to launch.\n")

    if args.fail_on:
        threshold = _SEV_RANK[args.fail_on]
        for r in results:
            for f in r["findings"]:
                if _SEV_RANK.get(f["severity"], 0) >= threshold:
                    return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
