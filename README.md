# mcp-audit

`npm audit` for your agent's MCP tool supply chain. Scans every MCP server
installed across your clients (Claude Code incl. project `.mcp.json`, Claude
Desktop, Cursor, VS Code incl. workspace settings, Windsurf) and flags what
can hurt you: prompt-injection in tool descriptions, exfiltration endpoints
baked into configs, known-vulnerable packages, floating version pins, and
secrets handed to servers via env.

Thousands of one-line-install MCP servers, ~zero vetting. This is the vetting.

## Install

Zero dependencies — Python 3.10+ stdlib only.

```bash
pip install git+https://github.com/calasdan-sketch/mcp-audit
mcp-audit                         # auto-discovers installed clients
```

Or from a clone without installing: `python3 -m mcp_audit` (same flags).

## Usage

```bash
# Static audit (safe: reads configs only, never executes servers)
python3 -m mcp_audit

# Deep audit: also spawn each server over stdio and scan live tool
# descriptions for prompt-injection. Executes server binaries — only
# probe servers you already trust enough to launch.
python3 -m mcp_audit --deep

# Audit a specific file, JSON output for CI, fail the build on highs
python3 -m mcp_audit --config ~/.claude.json --format json --fail-on high

# SARIF 2.1.0 for GitHub code scanning / IDE viewers
python3 -m mcp_audit --format sarif > mcp-audit.sarif

# Also look up pinned npx/uvx packages in OSV (network; sends name+version)
python3 -m mcp_audit --online

# Preview which servers --fix would remove, then remove them (with backup)
python3 -m mcp_audit --fix
python3 -m mcp_audit --fix --remove
```

Exit codes: `0` = ran clean, `1` = `--fail-on` threshold met, `2` = CLI
error (including an explicit `--config` path that is missing, unreadable,
unparseable, or an unrecognized shape — mcp-audit fails closed rather than
reporting "no MCP servers found").

## Discovery coverage

| Client | Location | Shape |
|---|---|---|
| Claude Code | `~/.claude.json` | `mcpServers` |
| Claude Code (project) | `./.mcp.json` (current directory) | `mcpServers` |
| Cursor | `~/.cursor/mcp.json` | `mcpServers` |
| Claude Desktop | `~/Library/Application Support/Claude/` (macOS), `~/.config/Claude/` (Linux), `%APPDATA%\Claude\` (Windows) `claude_desktop_config.json` | `mcpServers` |
| VS Code | global `Code/User/settings.json` under the same three roots + `./.vscode/settings.json` | nested `{"mcp": {"servers": …}}` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |
| Zed | `~/.config/zed/settings.json` | **not audited** — see below |

`~` is `$HOME` (`%USERPROFILE%` on Windows) and the `%APPDATA%` locations are
probed whenever `APPDATA` is set. Set `MCP_AUDIT_HOME=<dir>` to point every
default location at `<dir>` (and `<dir>/AppData/Roaming`) instead of the real
machine — e.g. to audit a copied profile; the test-suite uses it.

Discovery never reports a confident clean bill on files it couldn't audit.
A config file that exists but is unparseable, unreadable, or has a
servers-like key (`mcpServers`, `servers`, `mcp`, `context_servers`) in an
unknown shape produces a **warning** (a `[!]` line in human output, a
`"warnings"` entry in `--format json`) instead of a silent skip. A known
client's config with none of those keys — a fresh Claude Desktop config, VS
Code settings without an `mcp` block — is **0 servers configured** (an `[i]`
line), not a warning. When zero configs are discovered at all, mcp-audit
prints `[mcp-audit] warning: no MCP configs discovered — this is not a clean
bill of health` rather than "no findings". On a console that cannot show
`✓`/`─` (Windows cp1252 pipes) the report falls back to `[ok]`/`-`.

**Zed:** the path is discovered, but the `context_servers` shape is
deliberately not parsed — the per-server field mapping can't be verified from
documented sources, and guessing would risk clean bills on unscanned servers.
It surfaces as an "unsupported shape" warning instead. A Zed settings file
with no `context_servers` key is a known negative (no Zed servers
configured), not a warning.

**Not yet covered:** Goose (`~/.config/goose/config.yaml`) — YAML, and this
tool is stdlib-only (no PyYAML); the exact config format is also unverified.
Documented here rather than guessed.

Weekly cron example (uses the installed console script):

```bash
0 9 * * 1 mcp-audit --format json --fail-on high > /var/log/mcp-audit.json
```

## What it checks

| Check | Severity | What |
|---|---|---|
| `suspicious-command` | critical | Server launches via curl/wget/bash/sh/powershell/pwsh/cmd — a downloader or shell, not a server (Windows paths and `.exe`/`.cmd`/`.bat` handled) |
| `pipe-to-shell` | critical | Args pipe content into a shell (`curl … \| sh`, incl. `bash -c "curl … \| sh"`) |
| `inline-code` | critical/high | `powershell -EncodedCommand` (critical); `powershell -Command`, `python -c`, `node -e` (high) — code passed inline instead of a server file |
| `tool-description-injection` | critical | Live tool description tells the agent to ignore instructions, hide behavior, or send data out (`--deep` only) |
| `tool-description-injection` (base64 heuristic) | high | Long base64-looking blob in a description — could be a legit example key; capped at high with a manual-review note, never auto-removed |
| `exfiltration-endpoint` | critical (args) / medium (env) | Remote `http(s)://`/`ws(s)://` URL or bare `IP:port` baked into the launch config. Loopback (`localhost`, `127.x`, `::1`, `0.0.0.0`) and the well-known API hosts below are not reported |
| `known-vulnerable` | high/crit | Package matches the built-in advisory feed (`advisories.json`; unverified entries capped at medium) or, with `--online`, an OSV record (high) |
| `floating-version` | medium | `npx -y pkg` with no pin — every launch can pull a different release |
| `secret-env` | medium | Server receives `*_TOKEN`/`*_KEY`/`*_SECRET` via env |
| `remote-server` | medium | Non-local MCP URL — traffic leaves the machine by design |

Allowlisted API hosts (HTTPS/WSS only, exact host match; `.googleapis.com`
covers subdomains): `api.github.com`, `api.openai.com`, `api.anthropic.com`,
`*.googleapis.com`, `api.slack.com`, `api.notion.com`, `api.linear.app`,
`api.stripe.com` — see `ALLOWED_API_HOSTS` in `mcp_audit/detectors.py`. These
are vendor endpoints official servers are configured with
(e.g. `GITHUB_API_URL=https://api.github.com`), not places an attacker can
receive data.

Scores: 100 − deductions (critical 40, high 20, medium 10, low 5),
graded A–F. Severity floor: any single critical finding caps the grade at D,
no matter how few findings there are. Servers sort worst-first so the fires
are on top.

## `--fix`

`--fix` on its own is a dry run: it lists the servers it would remove.
`--fix --remove` removes them, after backing up each touched config
(`<path>.mcp-audit.bak-<timestamp>`).

Only unambiguous launch-time attacks are fixable: critical
`suspicious-command` (launched via a downloader/shell) and `pipe-to-shell`.
Everything else — URLs, tool-description matches, advisories, inline code —
is report-only, because it is too often legitimate config. You decide.

## Advisory feed

`mcp_audit/advisories.json` carries three October 2026 community reports
(mcp-server-fetch SSRF, Python SDK OAuth theft, HashiCorp session-isolation).
None matched a public OSV record when checked (2026-10-16), so each is marked
`"verified": false`: findings say **UNVERIFIED**, are capped at medium, and
should be checked before acting on or quoting them. Entries with no known
`fixed_in` are flagged "review manually" rather than silently passed. PRs
welcome — the feed is just JSON; set `"verified": true` only with a public
record.

`--online` queries [OSV](https://osv.dev) (`api.osv.dev`, stdlib `urllib`)
for each pinned npx/uvx package (npm / PyPI). Unpinned packages are skipped —
`floating-version` already flags them. A failed lookup is a low finding,
never a silent pass. (OSV does list real, verified advisories for the `mcp`
Python SDK — `--online` reports those by version.)

## Testing

```bash
python3 -m unittest discover -s tests -v   # 95 tests, all green
python -m pytest -q                        # same suite
```

Fixtures include a clean config, a nasty config (curl|sh, exfil URLs,
floating known-vuln package, secret env), per-client discovery fixtures
(project `.mcp.json`, VS Code global + workspace `settings.json`, Windsurf
`mcp_config.json`, Zed `settings.json`), and a fake MCP server speaking
real stdio protocol (plus a noisy one that logs and sends notifications
before answering) so the `--deep` probe path is tested without trusting
anything real.

## Scope / limits (v0.2.0)

- Static checks read configs only and are always safe. `--deep` executes
  server binaries — opt-in, with a warning, by design.
- Description scanning covers known injection phrasings; it's a tripwire,
  not a proof of safety.
- Advisory feed is curated manually — verify before quoting CVEs externally.
- A remote URL in launch args is critical even when legitimate (e.g.
  `npx mcp-remote https://vendor.example/sse`); add the host to
  `ALLOWED_API_HOSTS` only if it is a vendor endpoint you trust.
- `--deep` resolves the command via `PATH` (so Windows `npx.cmd` shims
  launch) and matches JSON-RPC responses by id, skipping log lines and
  notifications.
- Zed's `context_servers` shape and Goose's YAML config are not audited
  (see Discovery coverage) — they warn instead of reporting clean.

## License

MIT — see [LICENSE](LICENSE).
