# Changelog

## 0.3.0

- Renamed the PyPI distribution to **mcp-gradecard** (PyPI rejected `mcp-audit` as too similar to existing projects). The import package is now `mcp_gradecard` and the primary command is `mcp-gradecard`; `python -m mcp_gradecard` replaces `python -m mcp_audit`.
- The old `mcp-audit` command stays as an alias for the same entry point. A thin `mcp_audit` module re-exports the top-level names and warns with `DeprecationWarning`; `python -m mcp_audit` still runs. Submodule imports such as `mcp_audit.cli` are not forwarded.
- User-visible labels (`[mcp-gradecard]` prefixes, SARIF tool name, `.mcp-gradecard.bak-` backup suffix) follow the new name. The `MCP_AUDIT_HOME` and `MCP_AUDIT_DEBUG` environment variables are unchanged.
- The GitHub repository is still named mcp-audit.

## 0.2.4

- Last release under the name mcp-audit.
