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
               deep: bool, advisories: list[dict]) -> dict:
    findings = detectors.audit_server(name, cfg, advisories)
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


def _apply_fix(results: list[dict]) -> list[str]:
    """Remove servers with critical exfiltration/command findings.

    Backs up each touched config first. Returns human-readable actions."""
    actions: list[str] = []
    # group results by config path
    by_path: dict[str, list[dict]] = {}
    for r in results:
        by_path.setdefault(r["path"], []).append(r)

    for path, group in by_path.items():
        with open(path) as f:
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
                    and f["check"] in ("suspicious-command", "pipe-to-shell",
                                       "exfiltration-endpoint",
                                       "tool-description-injection")]
            if crit and r["name"] in servers:
                if not changed:
                    bak = _backup(path)
                    actions.append(f"backed up {path} -> {bak}")
                    changed = True
                del servers[r["name"]]
                reasons = "; ".join(c["check"] for c in crit)
                actions.append(f"removed '{r['name']}' ({reasons})")
        if changed:
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
    return actions


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
    p.add_argument("--format", choices=("human", "json"), default="human")
    p.add_argument("--fix", action="store_true",
                   help="Back up configs and remove servers with critical "
                        "findings. Regex-only heuristic findings (e.g. "
                        "base64-looking blobs) are capped at high with a "
                        "manual-review note and are never auto-removed.")
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
    args = _build_parser().parse_args(argv)
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
                                      args.deep, advisories))

    if args.fix:
        for a in _apply_fix(results):
            sys.stderr.write(f"[mcp-audit] {a}\n")
        # re-audit so the report reflects reality
        discovered, warnings = discovery.discover(args.config)
        results = []
        for d in discovered:
            for name, cfg in d["servers"].items():
                results.append(_audit_one(name, cfg, d["client"], d["path"],
                                          args.deep, advisories))

    if args.format == "json":
        out = {"results": [{k: r[k] for k in
                            ("name", "client", "path", "findings",
                             "score", "grade")} for r in results],
               "summary": scoring.summarize(results),
               "warnings": warnings}
        print(json.dumps(out, indent=2))
        if not discovered:
            sys.stderr.write(
                "[mcp-audit] warning: no MCP configs discovered — this is "
                "not a clean bill of health\n")
    else:
        print(scoring.render_human(results, warnings=warnings,
                                   n_configs=len(discovered)))
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
