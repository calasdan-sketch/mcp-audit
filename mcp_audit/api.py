"""Use mcp-audit from Python.

    from mcp_audit.api import audit
    report = audit(["~/.cursor/mcp.json"])     # or audit() to discover
    worst = report["summary"]["by_severity"]

`audit` is the static audit (the command without --deep): it launches
nothing, prints nothing, never exits the process and never calls
`sys.exit`. It returns the dict that `--format json` prints:
{"results": [...], "summary": {...}, "warnings": [...]}. A config that
cannot be audited, or a feed that cannot be read, raises `AuditError`
instead of coming back as "clean"."""

from __future__ import annotations

import os

from . import cli, detectors, discovery, iocs, osv

__all__ = ["audit", "AuditError"]


class AuditError(RuntimeError):
    """The audit could not be done (the message is safe to print)."""


def audit(config=None, *, online: bool = False, allow_hosts=(),
          ioc_feeds=(), advisory_feeds=(), osv_cache: bool = True) -> dict:
    """Audit MCP server configs and return the report as a dict.

    config: a path, a list of paths, or None to discover every client's
        config (as the command does). An explicit path that cannot be read
        or understood raises AuditError.
    online: also ask OSV about pinned packages (sends names and versions);
        osv_cache=False skips its 24-hour cache.
    allow_hosts: hosts to trust, as --allow-host.
    ioc_feeds, advisory_feeds: more feeds, each a path or an https URL."""
    paths = None
    if config is not None:
        paths = [config] if isinstance(config, (str, os.PathLike)) \
            else list(config)
        paths = [os.fspath(p) for p in paths]
        for path in paths:
            err = cli._explicit_config_error(path)
            if err is not None:
                raise AuditError(f"cannot read config file '{path}': {err}")
    try:
        advisories = detectors.load_advisories(list(advisory_feeds))
        campaigns = iocs.load_feed(list(ioc_feeds)) if ioc_feeds else None
    except (detectors.AdvisoryFeedError, iocs.IocFeedError) as e:
        raise AuditError(str(e)) from None
    discovered, warnings = discovery.discover(paths)
    if paths and warnings:
        raise AuditError("; ".join(
            f"cannot audit '{w['path']}': {w['reason']}" for w in warnings))
    try:
        hosts = tuple(dict.fromkeys(
            detectors.host_pattern(h) for h in allow_hosts))
    except ValueError as e:
        raise AuditError(f"allow_hosts: {e}") from None
    results = cli._audit_all(discovered, advisories, online, hosts, campaigns,
                             osv.cache_path() if osv_cache else None)
    return cli.json_document(results, warnings)
