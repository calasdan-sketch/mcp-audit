# mcp-audit

`npm audit` for your agent's MCP tool supply chain. Scans every MCP server
installed across your clients (Claude Code incl. its per-project "local" scope
and project `.mcp.json`, Claude Desktop, Cursor, VS Code, Copilot CLI,
Windsurf/Devin, Zed) and flags what can hurt you: prompt-injection in tool
descriptions, exfiltration endpoints baked into configs, known-vulnerable
packages, floating version pins, and secrets handed to servers via env.

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

# Deep audit: also launch each stdio server and scan its live tool
# descriptions for prompt-injection. This EXECUTES the servers: it lists
# them first, and leaves out the ones the static audit rated critical and
# the ones that come from project files in the current directory.
python3 -m mcp_audit --deep
python3 -m mcp_audit --deep --probe-critical   # launch the critical ones too
python3 -m mcp_audit --deep --probe-project    # launch the project's too

# Audit a specific file, JSON output for CI, fail the build on highs
python3 -m mcp_audit --config ~/.claude.json --format json --fail-on high

# SARIF 2.1.0 for GitHub code scanning / IDE viewers
python3 -m mcp_audit --format sarif > mcp-audit.sarif

# Also look up pinned npx/uvx packages in OSV (network; sends name+version)
python3 -m mcp_audit --online

# Preview which servers --fix would remove, then remove them (it asks first
# and backs the file up; --yes when there is no terminal to ask on)
python3 -m mcp_audit --fix
python3 -m mcp_audit --fix --remove
python3 -m mcp_audit --fix --remove --yes
```

Exit codes: `0` = ran clean, `1` = `--fail-on` threshold met, `2` = no
verdict: a CLI error (including an explicit `--config` path that is
missing, unreadable, unparseable, or an unrecognized shape — mcp-audit fails
closed rather than reporting "no MCP servers found"), the built-in
advisory feed cannot be loaded (a broken install must not grade vulnerable
packages as clean), `--fix --remove` has no terminal to ask on and no
`--yes` or could not rewrite a file, `--fail-on` is given and a discovered
config file could not be audited (see below), or mcp-audit hit an internal
error. An internal error prints the exception class and `file.py:line`
(never the message, which can quote your config) and exits `2`, because `1`
means findings; `MCP_AUDIT_DEBUG=1` gives the traceback to whoever debugs
mcp-audit. When both apply, findings win: `1`.

## Discovery coverage

Locations and key names come from each client's own documentation (read on
2026-10-17); a location marked **unverified** could not be confirmed there and
is probed on a best-effort basis. Run `mcp-audit` from the project root to
include the project-level files (only the current directory is looked at):
the locations below that start with `./`. They are audited like any other,
but under `--deep` their servers are listed and **not launched** unless you
pass `--probe-project` (see `--deep`).

| Client (`<label>` in the report) | Location | Servers under | Source |
|---|---|---|---|
| `claude-code` | `~/.claude.json` (user scope) | `mcpServers` | [Claude Code](https://code.claude.com/docs/en/mcp) |
| `claude-code-local` | `~/.claude.json` > `projects."<dir>"` - the local scope that `claude mcp add` writes by default; **every** project is audited, not just the current one | `mcpServers` | same page |
| `claude-code-project` | `./.mcp.json` (VS Code reads the same workspace-root file) | `mcpServers` | same page, [VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers) |
| `cursor` | `~/.cursor/mcp.json` | `mcpServers` | [Cursor](https://cursor.com/docs/mcp) |
| `cursor-project` | `./.cursor/mcp.json` | `mcpServers` | same page |
| `vscode-workspace-mcp` | `./.vscode/mcp.json` | `servers` | [VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers) |
| `vscode-mcp` | `mcp.json` in the VS Code user folder (below) | `servers` | documented as "mcp.json in your user profile"; the folder is **unverified** (inferred from where `settings.json` lives) |
| `vscode-profile` | `profiles/<id>/mcp.json` in the VS Code user folder | `servers` | **unverified** (same reason) |
| `vscode`, `vscode-workspace` | VS Code user folder `settings.json`, `./.vscode/settings.json` (JSON with comments is read) | `mcp.servers` (the older location) | folder: [VS Code settings](https://code.visualstudio.com/docs/configure/settings); the `mcp.servers` key is **unverified** against the current docs, kept for existing setups |
| `copilot` | `$COPILOT_HOME/mcp-config.json`, else `~/.copilot/mcp-config.json` | `mcpServers` | [VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers) |
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` | listed in [VS Code's MCP reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration); Windsurf's own page now describes the Devin location instead |
| `devin` | `$XDG_CONFIG_HOME/devin/` or `~/.config/devin/` (macOS, Linux), `%APPDATA%\devin\` (Windows): `mcp_config.json`, and `config.json` for Devin before v3000.3 | `mcpServers` | [Cascade](https://docs.devin.ai/desktop/cascade/mcp), [Devin CLI](https://docs.devin.ai/cli/extensibility/mcp/configuration) |
| `devin-project` | `./.devin/mcp_config.json`, `./.devin/mcp_config.local.json` (and `config.json`, `config.local.json` before v3000.3) | `mcpServers` | [Devin CLI](https://docs.devin.ai/cli/extensibility/mcp/configuration) |
| `zed` | `~/.config/zed/settings.json` (macOS, Linux); `%APPDATA%\Zed\settings.json` (Windows, **unverified**) | `context_servers` | [Zed MCP](https://zed.dev/docs/ai/mcp), [settings reference](https://zed.dev/docs/reference/all-settings) |
| `zed-project` | `./.zed/settings.json` | `context_servers` | **unverified** (path inferred from the settings reference's default `private_files` globs) |
| `claude-desktop` | `~/Library/Application Support/Claude/` (macOS), `%APPDATA%\Claude\` (Windows), `$XDG_CONFIG_HOME/Claude/` or `~/.config/Claude/` (Linux): `claude_desktop_config.json` | `mcpServers` | macOS and Windows: [MCP docs](https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-local-servers); Linux: [VS Code's MCP reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) |

The "VS Code user folder" is `~/Library/Application Support/Code/User`
(macOS), `$XDG_CONFIG_HOME/Code/User` or `~/.config/Code/User` (Linux) and
`%APPDATA%\Code\User` (Windows), as documented for `settings.json`.

`~` is `$HOME` (`%USERPROFILE%` on Windows) and the `%APPDATA%` locations are
probed whenever `APPDATA` is set. Set `MCP_AUDIT_HOME=<dir>` to point every
default location at `<dir>` (and `<dir>/AppData/Roaming`, `<dir>/.config`)
instead of the real machine - `XDG_CONFIG_HOME` and `COPILOT_HOME` are then
ignored; e.g. to audit a copied profile. The test-suite uses it.

Zed's servers come in three forms (flat `command`/`args`/`env`, the older
nested `command.path`, and remote `url`/`headers`); all are audited. An entry
that carries neither a command nor a URL (a server provided by a Zed
extension, whose launch command is not in `settings.json`) is reported as a
low `unauditable` finding rather than passing as clean.

Discovery never reports a confident clean bill on files it couldn't audit.
A config file that exists but is unparseable, unreadable, or has a
servers-like key (`mcpServers`, `servers`, `mcp`, `context_servers`) in an
unknown shape produces a **warning** (a `[!]` line in human output, a
`"warnings"` entry in `--format json`) instead of a silent skip. A known
client's config with none of those keys - a fresh Claude Desktop config, VS
Code settings without an `mcp` block - is **0 servers configured** (an `[i]`
line), not a warning. When zero configs are discovered at all, mcp-audit
prints `[mcp-audit] warning: no MCP configs discovered - this is not a clean
bill of health` rather than "no findings". On a console that cannot show
`✓`/`─` (Windows cp1252 pipes) the report falls back to `[ok]`/`-`.

### Odd and hostile config files

Config files are untrusted input, so none of these crashes the audit:

- JSON **with comments and trailing commas** (JSONC: what VS Code and Zed
  write in `settings.json`, and what people write elsewhere) is read in every
  location. A `//` or `/*` inside a string - a URL, a Windows path - is text.
- UTF-8 (with or without a BOM) is expected. UTF-16 and UTF-32 files with a
  byte order mark (what Windows PowerShell 5 writes for `>`) are read too.
  Other bytes are a warning: "not UTF-8 text".
- A file over 64 MiB, one nested so deeply that the parser gives up (100,000
  levels of `[`) and one that runs the parser out of memory are warnings
  ("too large", "nested too deeply"), not a traceback.
- A skipped file is a warning, and under `--fail-on` it is an error: the run
  exits `2` ("could not be audited") instead of passing the gate, unless a
  finding already made it exit `1`. Without `--fail-on` the exit code stays
  `0`, and the report says the files were not audited.
- Server names, paths, project directories and the arguments a finding
  quotes come from files someone else may have written. Control characters
  (the ESC that starts a terminal escape sequence), bidirectional overrides,
  zero-width and other invisible characters, and line breaks in them are
  printed as escapes (`\x1b`, `\u202e`, `\n`) in the human report, `--format
  json` and SARIF alike, so a name can neither clear the screen, nor reorder
  the text around it, nor fake a line of the report. In JSON and SARIF such a
  name is therefore not byte for byte the name in the config.

**Not covered:** Claude Code's organization-managed `managed-mcp.json` (the
page we could read does not give its location), servers that Claude Code
plugins and claude.ai connectors provide, servers passed with
`--mcp-config`, VS Code Insiders/VSCodium user folders, MCP servers that
extensions register through an editor API, and Goose
(`~/.config/goose/config.yaml`; YAML, and this tool is stdlib-only). They are
listed here instead of guessed.

Weekly cron example (uses the installed console script):

```bash
0 9 * * 1 mcp-audit --format json --fail-on high > /var/log/mcp-audit.json
```

## What it checks

| Check | Severity | What |
|---|---|---|
| `suspicious-command` | critical | Server runs a downloader or a shell instead of a server: `curl`, `wget`, `iwr`, `certutil`, `start`, a `bash`/`sh`/`zsh`/`cmd`/`powershell` that is given no command string (`bash run.sh`, `-EncodedCommand`), or any of those inside a wrapper. A shell that is given a command string is judged by what it runs - see below (Windows paths and `.exe`/`.cmd`/`.bat` handled) |
| `pipe-to-shell` | critical | Content is piped into a shell (`curl ... \| sh`, `\| sudo -E bash`, `\| /bin/zsh`, `\| iex`), also inside `bash -c "..."`, `$(...)` and backticks, or `eval` is given generated text (`eval "$(curl ...)"`, `eval $VAR`). The word `eval` in a package name or a path is not a finding |
| `inline-code` | critical/high | `powershell -EncodedCommand` (critical); `powershell -Command`, `python -c`, `node -e` (high) — code passed inline instead of a server file |
| `tool-description-injection` | critical | Live tool description tells the agent to ignore instructions, hide behavior, or send data out (`--deep` only) |
| `tool-description-injection` (base64 heuristic) | high | Long base64-looking blob in a description — could be a legit example key; capped at high with a manual-review note, never auto-removed |
| `exfiltration-endpoint` | critical (args) / medium (env) | Remote `http(s)://`/`ws(s)://` URL or bare `IP:port` baked into the launch config. Loopback (`localhost`, `127.x`, `::1`, `0.0.0.0`) and the well-known API hosts below are not reported |
| `known-vulnerable` | high/crit | Package matches the built-in advisory feed (`advisories.json`; unverified entries capped at medium) or, with `--online`, an OSV record (high) |
| `floating-version` | medium | A package that is not pinned to one release, so every launch can pull a different one: no version (`npx -y pkg`, `uvx pkg`), a tag (`pkg@latest`, `@next`) or a range (`^1.2.0`, `~1`, `>=1`, `1.x`, `*`, `pkg>=1`, `pkg==1.*`). An exact version (`pkg@1.2.3`, `uvx pkg==1.2.3`) or a `sha256:` digest is pinned. Read through `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`, `uv tool run`, `pipx run` and through `cmd /c`, `bash -lc`, `env` and `sudo`. Git, URL, tarball and path specs are not judged |
| `secret-env` | medium | Server receives credentials via env: any variable whose name has a `TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `PASSPHRASE`, `CREDENTIAL`, `BEARER`, `COOKIE`, `DSN` or `PAT` word (`API_KEY`, `OPENAI_KEY`, `accessToken`, `DB_PASSWORD`). `PUBLIC_KEY` and `KEYBOARD_LAYOUT` are not flagged. Only the names are printed |
| `remote-server` | medium | Non-local MCP URL — traffic leaves the machine by design |
| `unparseable-url` | high | A URL in the config that cannot be taken apart (`http://[x`): where it points is unknown, so it is treated as unsafe. One bad URL never hides another |
| `detector-error` | high | A check crashed on this entry. mcp-audit fails closed: this is a visible HIGH finding (so `--fail-on high` trips), never a quiet pass. Only the exception class is shown |
| `invalid-config` | high | The entry is not an object, or `command`/`args`/`env`/`url` has the wrong type |
| `deep-probe` | low | `--deep` only: the server was not launched (it has critical findings, it comes from a project file in the current directory, or it is remote), could not be probed (did not start, silent, exited early, sent too much output), or only part of its tools were read |
| `unauditable` | low | The entry has neither `command` nor `url` (for instance a Zed server provided by an extension): what it runs is not in the config |

### Shell wrappers are judged by what they run

`cmd /c npx -y pkg@1.2.3` is how npx is started on Windows and
`bash -lc "npx ..."` is how it is started from a login shell, so a shell that
is given a command string (`-c`, `/c`, `-Command`) is judged by the commands
inside that string. A downloader, another shell, `start` or a pipe into a shell
is critical; `npx`, `node`, `cd`, `exec` and the like are not. `sudo`, `env`,
`exec`, `nohup`, `timeout` and `NAME=value` in front of a command are looked
through, and `$(...)`, backticks, `;`, `&&` and newlines split a script into
its commands. `--fix --remove` therefore no longer deletes a `cmd /c npx`
server.

The reader is a small tokenizer, not a shell. What it cannot follow is
listed under Limitations. A command line it cannot read at all - over
1,000,000 characters, or nested more than 8 levels deep (`$(...)` in
`$(...)`, a shell started by a shell) - is reported as a `detector-error`
HIGH finding, never as clean.

### Secrets are never printed

Configs hold credentials, and SARIF gets uploaded to GitHub, so nothing a
config contains is repeated in any output (human, `--format json`, SARIF,
stderr):

- a URL is shown as `scheme://host[:port]`, followed by `/...` when a path,
  query or fragment came after it - never the userinfo, path, query or
  fragment (a webhook's secret is often its path);
- env values, `headers` and OAuth `auth` blocks are never shown, only the
  env variable names;
- a command line that has to be shown (`--fix`, `--deep`) has the value of
  every credential-looking flag (`--api-key=...`, `--password ...`) masked
  and its URLs shortened as above;
- a check that crashes is reported by exception class only;
- as a last line of defense every finding message is run through the same
  URL shortener and a scrubber for well-known credential shapes (GitHub,
  OpenAI/Anthropic, Slack, AWS, Google, JWT, `Bearer ...`).

The test-suite plants fake secrets in every one of those places and greps all
three formats.

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

`--fix` on its own is a dry run. For each server it would remove it prints
the name, the config file and where in it the entry sits, the findings that
condemn it and what the server runs (credentials masked, URLs shortened),
and changes nothing.

`--fix --remove` shows the same list and asks `[y/N]` before it removes
anything. With no terminal to ask on (CI, a pipe) it refuses and exits `2`,
unless `--yes` is given; with nothing to remove it needs no answer. Before a
file is touched it is copied to `<path>.mcp-audit.bak-<timestamp>` (`-1`,
`-2`... when that name is taken: a backup is never overwritten, and it is
the original byte for byte). The new file is written beside the old one and
moved into place in one step, so a crash or a full disk leaves the old file;
it keeps its indent, line endings, BOM and permissions, and a symlinked
config stays a link.

Only plain JSON is rewritten. A config with comments or trailing commas
(VS Code's `settings.json`, Zed's) is reported as skipped - remove the server
by hand - and so is an entry that changed after it was audited. Close the
client first: Claude Code rewrites `~/.claude.json` while it runs.

Only unambiguous launch-time attacks are fixable: critical
`suspicious-command` (launched via a downloader/shell) and `pipe-to-shell`.
Everything else — URLs, tool-description matches, advisories, inline code —
is report-only, because it is too often legitimate config. You decide.

## `--deep`

`--deep` launches each stdio server in your configs, as your MCP client
would and with your user rights, speaks MCP to it (`initialize`, then
`tools/list` and every further page) and scans the tool descriptions for
prompt-injection phrasing. Configs are not trustworthy input - a cloned
repository's `.mcp.json` runs whatever its author wrote - so:

- **It says what it will run before it runs anything.** On stderr, in every
  output format: one line per server with its name, client, config file
  and command (credentials masked, URLs shortened).
- **Servers with critical findings are not launched** (a downloader,
  `curl | sh`, a remote endpoint in the arguments): launching one would run
  the very command that was flagged. They get a low `deep-probe` finding
  saying so; `--probe-critical` launches them anyway. Static analysis cannot
  tell what `node ./server.js` does, so `--deep` is still only for configs
  you would run anyway.
- **Servers from project files are not launched** (`./.mcp.json`,
  `./.cursor/mcp.json`, `./.vscode/mcp.json` and `settings.json`,
  `./.devin/`, `./.zed/settings.json`: everything found by looking in the
  current directory). Whoever wrote the project chose their commands - think
  of a repository you have just cloned and want to audit before you trust it -
  so they are listed (on stderr, and as a low `deep-probe` finding in every
  format) and left alone; `--probe-project` launches them anyway, which is
  also what to pass when the project is your own. A server that is both
  critical and a project's needs both flags. Your own files (the home
  directory, including Claude Code's local scope) and a file you name with
  `--config` are launched after the list, as before; if the current directory
  is your home directory, the files in it are yours.
- **One deadline for the whole probe** (15 s), enforced from outside the
  server: a server that never answers, answers slowly, or has a child that
  keeps its output pipe open cannot hold mcp-audit (or CI) past it. The
  server starts in its own session (POSIX) or process group (Windows) and
  its whole process tree is killed when the probe ends, however it ends - on
  Windows with `taskkill /T /F`, a code path that this repository tests only
  with a mock, not on a real Windows machine (**unverified**). A process
  that deliberately leaves the session (`setsid`) is not reached, but it
  cannot hold the probe either.
- **Output is capped.** A line over 4 MiB, or more than 16 MiB in total,
  ends the probe and kills the server (a runaway server wrote 4 GB in nine
  seconds into the old probe).
- **A minimal environment.** A server gets `PATH`, `HOME`, `USER`,
  `LOGNAME`, `SHELL`, `TERM`, `LANG`, `LC_ALL` and `TMPDIR` (on Windows
  `APPDATA`, `COMSPEC`, `HOMEDRIVE`, `HOMEPATH`, `LOCALAPPDATA`, `PATH`,
  `PATHEXT`, `PROCESSOR_ARCHITECTURE`, `SYSTEMDRIVE`, `SYSTEMROOT`, `TEMP`,
  `TMP`, `USERNAME`, `USERPROFILE`, `WINDIR`) plus the `env` of its own
  config entry - not the API keys, tokens and proxy passwords of the shell
  that ran mcp-audit. A server that needs one gets it from its `env`; one
  that must download through a proxy may fail to start, and says so.
- **A probe that falls short is visible.** A server that does not start,
  stays silent, exits before it lists its tools or floods is a low
  `deep-probe` finding, not a pass; so is a tool list cut at 2,000 tools or
  100 pages.
- Each server is probed once, after `--fix`, and never one that `--fix`
  just removed.

## Advisory feed

The feed ships inside the package as package data (wheel and sdist both
contain `mcp_audit/advisories.json`) and is read with `importlib.resources`.
If it is missing or malformed mcp-audit exits 2 and says so, instead of
quietly reporting every known-vulnerable package as clean. The test-suite
builds the wheel, unpacks it elsewhere and runs the installed copy.

`mcp_audit/advisories.json` carries three October 2026 community reports
(mcp-server-fetch SSRF, Python SDK OAuth theft, HashiCorp session-isolation).
None matched a public OSV record when checked (2026-10-16), so each is marked
`"verified": false`: findings say **UNVERIFIED**, are capped at medium, and
should be checked before acting on or quoting them. Entries with no known
`fixed_in` are flagged "review manually" rather than silently passed. PRs
welcome — the feed is just JSON; set `"verified": true` only with a public
record.

`--online` queries [OSV](https://osv.dev) (`api.osv.dev`, stdlib `urllib`)
for each package pinned to an exact version (npm / PyPI). Tags and ranges are
skipped — `floating-version` already flags them — and so is a digest. A failed lookup is a low finding,
never a silent pass. (OSV does list real, verified advisories for the `mcp`
Python SDK — `--online` reports those by version.)

## Testing

```bash
python3 -m unittest discover -s tests -v
python -m pytest -q                        # same suite
```

The suite is hermetic: it works in temporary directories (a fake home via
`MCP_AUDIT_HOME`), reaches no network except `127.0.0.1` stand-ins, and never
reads the real machine's configs. Fixtures include a clean config, a nasty
config (curl|sh, exfil URLs, floating known-vuln package, secret env),
per-client discovery fixtures, and fake MCP servers that speak the real stdio
protocol - a noisy one, a silent one, one that floods its output, one whose
child leaves the process group and keeps the pipe, one that pages its tools
- so the `--deep` probe is tested without trusting anything real. Tests
that plant fake secrets grep all three output formats, and the packaging
test builds the wheel and runs the installed copy (it is skipped, with the
reason, when the interpreter cannot build a wheel at all).

## Limitations

What mcp-audit does not do, so that you do not find out the hard way:

**Reading configs**

- The shell reader is a tokenizer, not a shell. Aliases, functions,
  here-documents, sourced files, command names held in variables and process
  substitution are not followed; a script is judged by the commands it
  spells out. Piping into an interpreter (`| python -`, `| node`) is not
  flagged as pipe-to-shell.
- Pinning is judged for npm and PyPI launchers only (`npx`, `bunx`,
  `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx`, `uv tool run`, `pipx run`).
  Git, URL, tarball and path package specs, and container images
  (`docker run image`), are not judged. The tables that tell an option's
  value from the package name are heuristics.
- Only the locations in the Discovery table are read, and project-level
  files only in the current directory. The VS Code user-folder `mcp.json`,
  Zed's Windows path and `./.zed/settings.json` are **unverified**, and the
  Windsurf location rests on a third-party page (Windsurf's own page now
  describes Devin's; see the table). Organization-managed Claude Code
  config, plugin and connector servers, `--mcp-config`, VS Code
  Insiders/VSCodium and Goose are not covered.
- A config over 64 MiB is not read (it is reported as a file that could not
  be audited).
- Description scanning (`--deep`) covers known injection phrasings; it is a
  tripwire, not a proof of safety. The advisory feed is curated by hand:
  verify before quoting a CVE externally. `--online` looks up exact npm and
  PyPI versions only.
- A remote URL in launch args is critical even when legitimate (e.g.
  `npx mcp-remote https://vendor.example/sse`); add the host to
  `ALLOWED_API_HOSTS` only if it is a vendor endpoint you trust.

**`--fix`**

- It rewrites plain JSON only: a config with comments is reported as
  skipped, and so is a layout it does not own (VS Code's nested
  `mcp.servers`). Claude Code rewrites `~/.claude.json` while it runs, so
  close it first.

**`--deep`**

- It launches stdio servers only, once each, with a 15 s limit and a minimal
  environment. A server that needs a login, a proxy, or a credential that is
  not in its `env` fails to start or to answer, and is reported as a failed
  probe rather than skipped silently. Remote (`url`) servers are not probed.
- Project files are not launched without `--probe-project`, whoever wrote
  them: mcp-audit cannot tell your own project from a stranger's. A file you
  name with `--config` counts as yours even when it sits in a repository you
  have cloned, so point `--config` only at files you would run.
- It resolves the command via `PATH` (so Windows `npx.cmd` shims launch).
- A process that deliberately leaves the server's session (`setsid`) is not
  killed when the probe ends, though it cannot hold the probe. On Windows the
  tree is killed with `taskkill /T /F`, which is **unverified** on a real
  Windows machine.

**Platforms**

- Python 3.10 to 3.13 are tested. The Windows-specific paths (the
  `%APPDATA%` locations, the cp1252 console fallback, closed-pipe handling,
  `taskkill`) are exercised by tests that simulate Windows, not by a run on
  Windows.

## License

MIT — see [LICENSE](LICENSE).
