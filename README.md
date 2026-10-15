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
git clone <repo> && cd mcp-audit
python3 -m mcp_audit              # auto-discovers installed clients
```

Once installed (`pip install .`), the `mcp-audit` console script is available
and takes the same flags.

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

# Back up configs and remove servers with critical findings
python3 -m mcp_audit --fix
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
| Claude Desktop | platform-specific `claude_desktop_config.json` | `mcpServers` |
| VS Code | global `Code/User/settings.json` + `./.vscode/settings.json` | nested `{"mcp": {"servers": …}}` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |
| Zed | `~/.config/zed/settings.json` | **not audited** — see below |

Discovery never reports a confident clean bill on files it couldn't audit.
A config file that exists but is unparseable, unreadable, or has an unknown
top-level shape produces a **warning** (a `[!]` line in human output, a
`"warnings"` entry in `--format json`) instead of a silent skip. When zero
configs are discovered at all, mcp-audit prints
`[mcp-audit] warning: no MCP configs discovered — this is not a clean bill of
health` rather than "no findings".

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
| `suspicious-command` | critical | Server launches via curl/wget/bash — a downloader, not a server |
| `pipe-to-shell` | critical | Args pipe content into a shell (`curl … \| sh`) |
| `tool-description-injection` | critical | Live tool description tells the agent to ignore instructions, hide behavior, or send data out (`--deep` only) |
| `tool-description-injection` (base64 heuristic) | high | Long base64-looking blob in a description — could be a legit example key; capped at high with a manual-review note, never auto-removed |
| `exfiltration-endpoint` | critical | Remote URL baked into args/env (localhost excluded) — data exfiltration is critical |
| `known-vulnerable` | high/crit | Package matches the built-in advisory feed (`advisories.json`) |
| `floating-version` | medium | `npx -y pkg` with no pin — every launch can pull a different release |
| `secret-env` | medium | Server receives `*_TOKEN`/`*_KEY`/`*_SECRET` via env |
| `remote-server` | medium | Non-local MCP URL — traffic leaves the machine by design |

Scores: 100 − deductions (critical 40, high 20, medium 10, low 5),
graded A–F. Severity floor: any single critical finding caps the grade at D,
no matter how few findings there are. Servers sort worst-first so the fires
are on top.

## `--fix`

Backs up each touched config (`<path>.mcp-audit.bak-<timestamp>`), then
removes servers with critical exfiltration/command/description findings.
High/medium findings are report-only — you decide.

Conservative by design: `--fix` never auto-removes a server on a regex-only
heuristic. The base64-blob pattern in tool descriptions (which could be a
legit example key or PEM block) is capped at high severity with an explicit
manual-review note, so it cannot trigger removal.

## Advisory feed

`mcp_audit/advisories.json` ships with the October 2026 MCP CVEs
(mcp-server-fetch SSRF, Python SDK OAuth theft, HashiCorp session-isolation).
Entries with no known `fixed_in` are flagged "review manually" rather than
silently passed. PRs welcome — the feed is just JSON.

## Testing

```bash
python3 -m unittest discover -s tests -v   # 57 tests, all green
```

Fixtures include a clean config, a nasty config (curl|sh, exfil URLs,
floating known-vuln package, secret env), per-client discovery fixtures
(project `.mcp.json`, VS Code global + workspace `settings.json`, Windsurf
`mcp_config.json`, Zed `settings.json`), and a fake MCP server speaking
real stdio protocol so the `--deep` probe path is tested without trusting
anything real.

## Scope / limits (v0.2.0)

- Static checks read configs only and are always safe. `--deep` executes
  server binaries — opt-in, with a warning, by design.
- Description scanning covers known injection phrasings; it's a tripwire,
  not a proof of safety.
- Advisory feed is curated manually — verify before quoting CVEs externally.
- Zed's `context_servers` shape and Goose's YAML config are not audited
  (see Discovery coverage) — they warn instead of reporting clean.
