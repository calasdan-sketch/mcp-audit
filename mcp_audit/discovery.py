"""Find MCP server configs in known client locations.

Where each client keeps its servers is taken from the clients' own
documentation (see the README for the page behind every location). Anything
that could not be checked there is marked "unverified" in the README.
"""

from __future__ import annotations

import codecs
import os
import platform

from . import jsonc

# Set this to a directory to make default discovery look there instead of
# the real machine: it replaces the home directory and, for the clients that
# live under %APPDATA%/%LOCALAPPDATA%, <dir>/AppData/Roaming and
# <dir>/AppData/Local. One variable isolates every default path (the
# test-suite relies on it; it also lets you audit a copied user profile).
# While it is set XDG_CONFIG_HOME and COPILOT_HOME are ignored.
HOME_ENV = "MCP_AUDIT_HOME"


def roots() -> dict[str, str]:
    """The directories every default-discovery path hangs off.

    "home" is what os.path.expanduser("~") gives (HOME on POSIX, USERPROFILE
    on Windows); "appdata"/"local_appdata" are %APPDATA%/%LOCALAPPDATA%,
    empty when unset off Windows and defaulting to the conventional folders
    on Windows; "config" is $XDG_CONFIG_HOME (when absolute) or ~/.config.
    MCP_AUDIT_HOME overrides all of them at once. Nothing else in the tool
    reads HOME, USERPROFILE, APPDATA or XDG_CONFIG_HOME, so overriding this
    one function (or setting the variable) is enough to isolate discovery.
    """
    override = os.environ.get(HOME_ENV)
    if override:
        return {"home": override,
                "appdata": os.path.join(override, "AppData", "Roaming"),
                "local_appdata": os.path.join(override, "AppData", "Local"),
                "config": os.path.join(override, ".config")}
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    if platform.system() == "Windows":
        appdata = appdata or os.path.join(home, "AppData", "Roaming")
        local_appdata = local_appdata or os.path.join(home, "AppData", "Local")
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    config = xdg if xdg and os.path.isabs(xdg) else os.path.join(home, ".config")
    return {"home": home, "appdata": appdata, "local_appdata": local_appdata,
            "config": config}


def _copilot_home(home: str) -> str:
    """$COPILOT_HOME, or ~/.copilot when it is not set (never both)."""
    chosen = "" if os.environ.get(HOME_ENV) else os.environ.get(
        "COPILOT_HOME", "")
    return chosen or os.path.join(home, ".copilot")


def _profile_files(user_dir: str, name: str) -> list[str]:
    """<user_dir>/profiles/<id>/<name> for every VS Code profile folder."""
    folder = os.path.join(user_dir, "profiles")
    try:
        ids = sorted(os.listdir(folder))
    except OSError:
        return []
    return [os.path.join(folder, i, name) for i in ids]


def candidate_paths() -> list[tuple[str, str]]:
    """(client, path) pairs to check, in a stable order.

    Claude Code, Cursor, Windsurf and Copilot live under the home directory
    on every OS. VS Code, Claude Desktop, Devin and Zed live under
    ~/Library/Application Support (macOS), ~/.config (Linux) or %APPDATA%
    (Windows); the %APPDATA% locations are probed whenever APPDATA is set,
    which is always on Windows and lets the other OSes exercise them.
    Project-level files are looked up in the current directory only.
    """
    r = roots()
    home, appdata, config = r["home"], r["appdata"], r["config"]
    cwd = os.getcwd()
    system = platform.system()
    vscode_dirs: list[str] = []
    desktop_dirs: list[str] = []
    devin_dirs: list[str] = []
    zed_files: list[str] = []
    if system == "Darwin":
        support = os.path.join(home, "Library", "Application Support")
        vscode_dirs.append(os.path.join(support, "Code", "User"))
        desktop_dirs.append(os.path.join(support, "Claude"))
        devin_dirs.append(os.path.join(config, "devin"))
        zed_files.append(os.path.join(config, "zed", "settings.json"))
    elif system != "Windows":
        vscode_dirs.append(os.path.join(config, "Code", "User"))
        desktop_dirs.append(os.path.join(config, "Claude"))
        devin_dirs.append(os.path.join(config, "devin"))
        zed_files.append(os.path.join(config, "zed", "settings.json"))
    if appdata:
        vscode_dirs.append(os.path.join(appdata, "Code", "User"))
        desktop_dirs.append(os.path.join(appdata, "Claude"))
        devin_dirs.append(os.path.join(appdata, "devin"))
        zed_files.append(os.path.join(appdata, "Zed", "settings.json"))
    paths = [
        ("claude-code", os.path.join(home, ".claude.json")),
        ("claude-code-project", os.path.join(cwd, ".mcp.json")),
        ("cursor", os.path.join(home, ".cursor", "mcp.json")),
        ("cursor-project", os.path.join(cwd, ".cursor", "mcp.json")),
    ]
    paths += [("vscode", os.path.join(d, "settings.json"))
              for d in vscode_dirs]
    paths += [("vscode-mcp", os.path.join(d, "mcp.json"))
              for d in vscode_dirs]
    for d in vscode_dirs:
        paths += [("vscode-profile", p) for p in _profile_files(d, "mcp.json")]
    paths += [
        ("vscode-workspace", os.path.join(cwd, ".vscode", "settings.json")),
        ("vscode-workspace-mcp", os.path.join(cwd, ".vscode", "mcp.json")),
        ("copilot", os.path.join(_copilot_home(home), "mcp-config.json")),
        ("windsurf", os.path.join(home, ".codeium", "windsurf",
                                  "mcp_config.json")),
    ]
    for d in devin_dirs:
        paths.append(("devin", os.path.join(d, "mcp_config.json")))
        paths.append(("devin", os.path.join(d, "config.json")))  # < v3000.3
    paths += [
        ("devin-project", os.path.join(cwd, ".devin", "mcp_config.json")),
        ("devin-project", os.path.join(cwd, ".devin", "mcp_config.local.json")),
        ("devin-project", os.path.join(cwd, ".devin", "config.json")),
        ("devin-project", os.path.join(cwd, ".devin", "config.local.json")),
    ]
    paths += [("zed", p) for p in zed_files]
    paths.append(("zed-project", os.path.join(cwd, ".zed", "settings.json")))
    paths += [("claude-desktop", os.path.join(d, "claude_desktop_config.json"))
              for d in desktop_dirs]
    return paths


# Every top-level key some client stores servers under. A known client's
# config object that has NONE of them simply has no MCP servers configured
# (Claude Desktop before any server is added - just coworkUserFilesPath and
# preferences; VS Code settings without an "mcp" block; Claude Code's
# .claude.json without global servers; Zed without context_servers). That
# is "0 servers configured", not an unknown shape. The unknown-shape warning
# is kept for files where one of these keys IS present but has an unexpected
# shape (e.g. "mcpServers": []): servers may be hiding in there.
#
#   mcpServers       Claude Code, Claude Desktop, Cursor, Windsurf, Devin,
#                    Copilot CLI, workspace-root .mcp.json
#   servers          VS Code mcp.json (workspace and user profile)
#   mcp.servers      VS Code settings.json (the older location)
#   context_servers  Zed settings.json
_SERVER_KEYS = ("mcpServers", "servers", "mcp", "context_servers")

#: The clients whose files are looked up in the current directory (every
#: other location hangs off the home directory). They belong to the project,
#: not to the person running mcp-audit: whoever wrote the project wrote them,
#: so --deep leaves their servers alone unless --probe-project is given.
PROJECT_CLIENTS = ("claude-code-project", "cursor-project", "vscode-workspace",
                   "vscode-workspace-mcp", "devin-project", "zed-project")


def is_project_client(client: str) -> bool:
    """True for a config that was found by looking in the current directory.
    Your own files (the home directory, Claude Code's local scope in it) and a
    file you name with --config ("explicit") are not the project's."""
    return client in PROJECT_CLIENTS


#: Where Claude Code keeps "local scope" servers (the default of
#: `claude mcp add`): ~/.claude.json -> projects.<project dir>.mcpServers.
LOCAL_SCOPE_CLIENTS = ("claude-code", "explicit")


def normalize_server(cfg):
    """One server entry in the {command, args, env | url} shape the detectors
    read. Zed's older form nests the launch fields under "command"
    ({"command": {"path": ..., "args": [...], "env": {...}}}); that is
    flattened. Everything else is returned untouched."""
    if not isinstance(cfg, dict) or not isinstance(cfg.get("command"), dict):
        return cfg
    nested = cfg["command"]
    out = {k: v for k, v in cfg.items() if k != "command"}
    out["command"] = nested.get("path") or ""
    if "args" in nested and "args" not in out:
        out["args"] = nested["args"]
    if isinstance(nested.get("env"), dict):
        env = out.get("env")
        out["env"] = {**nested["env"], **(env if isinstance(env, dict) else {})}
    return out


def extract_groups(client: str, data) -> tuple[list[dict], list[str]]:
    """The server objects in one parsed config -> (groups, problems).

    A group is {"servers", "key_path", "client", "project"?}: key_path is
    where the object sits in the document (so --fix can edit it), project is
    the project directory of a Claude Code local-scope group. problems lists
    server-ish keys that are present but have an unexpected shape - servers
    may be hiding behind them, so the caller must warn rather than pass.
    """
    if not isinstance(data, dict):
        return [], ["the top level is not a JSON object"]
    groups: list[dict] = []
    problems: list[str] = []

    def add(label, key_path, servers, project=None):
        group = {"client": label, "key_path": list(key_path),
                 "servers": {n: normalize_server(c)
                             for n, c in servers.items()}}
        if project is not None:
            group["project"] = project
        groups.append(group)

    for key in _SERVER_KEYS:
        if key not in data:
            continue
        value = data[key]
        if key == "mcp":
            inner = value.get("servers") if isinstance(value, dict) else None
            if isinstance(inner, dict):
                add(client, ("mcp", "servers"), inner)
            else:
                problems.append("'mcp' has no 'servers' object")
        elif isinstance(value, dict):
            add(client, (key,), value)
        else:
            problems.append(f"'{key}' is not an object")
    if client in LOCAL_SCOPE_CLIENTS and "projects" in data:
        projects = data["projects"]
        label = "claude-code-local" if client == "claude-code" else client
        if not isinstance(projects, dict):
            problems.append("'projects' is not an object")
        else:
            for project, entry in projects.items():
                if not isinstance(entry, dict) or "mcpServers" not in entry:
                    if not isinstance(entry, dict):
                        problems.append("a 'projects' entry is not an object")
                    continue
                servers = entry["mcpServers"]
                if not isinstance(servers, dict):
                    problems.append("a project's 'mcpServers' is not an "
                                    "object")
                elif servers:  # Claude Code writes {} for most projects
                    add(label, ("projects", project, "mcpServers"), servers,
                        project=str(project))
    return groups, problems


#: A config file bigger than this is not read: it is reported as a file that
#: could not be audited. (A real client config is a few KB; Claude Code's
#: ~/.claude.json grows with its history but stays far below this.)
MAX_CONFIG_BYTES = 64 * 1024 * 1024

# Byte order marks, longest first: the UTF-32 LE mark begins with the UTF-16 LE
# one. Windows PowerShell 5 writes UTF-16 with a mark for `>` and `Out-File`.
_BOMS = ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
         (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"),
         (codecs.BOM_UTF8, "utf-8-sig"))


class ConfigError(ValueError):
    """A config file that exists but cannot be turned into a document. The
    message says why and is safe to print: it never quotes the file."""


def _decode(raw: bytes) -> str:
    """Client configs are UTF-8 (never the console code page, which is what
    a bare open() uses on Windows); a byte order mark also selects UTF-16/32
    and is consumed."""
    for bom, codec in _BOMS:
        if raw.startswith(bom):
            return raw.decode(codec)
    return raw.decode("utf-8")


def _read_json(path: str):
    """The JSON (or JSONC: comments and trailing commas) document in `path`.

    Raises OSError when the file cannot be read and ConfigError when it can
    but not be understood: not text, too large, nested too deeply, malformed.
    Hostile input is an expected case here, so nothing else escapes."""
    with open(path, "rb") as f:
        raw = f.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"too large to audit (over {MAX_CONFIG_BYTES} bytes)")
    try:
        text = _decode(raw)
    except UnicodeError:
        raise ConfigError("not UTF-8 text (and no UTF-16/32 byte order mark)"
                          ) from None
    try:
        return jsonc.loads(text)
    except RecursionError:
        raise ConfigError("nested too deeply to parse") from None
    except MemoryError:
        raise ConfigError("too large to parse") from None
    except ValueError as e:
        raise ConfigError(f"unparseable JSON ({e})") from None


def load_config(path: str) -> dict:
    """Return {server_name: server_config} from a client config file.

    Unsupported or unrecognized shapes yield {} - use discover() when you
    need to distinguish "no servers configured" from "couldn't parse".
    """
    groups, _problems = extract_groups("explicit", _read_json(path))
    servers: dict = {}
    for g in groups:
        servers.update(g["servers"])
    return servers


_SHAPE_HELP = "expected mcpServers, servers, mcp.servers or context_servers"


def discover(explicit: list[str] | None = None
             ) -> tuple[list[dict], list[dict]]:
    """Return (found, warnings).

    found: [{"client", "path", "servers", ...}] for each servers object in
    each config that parsed (a Claude Code .claude.json yields one for the
    user scope and one per project with local-scope servers, each of those
    with a "project"). A known client's config object with none of the server
    keys is found with servers == {} ("0 servers configured").
    warnings: [{"client", "path", "reason"}] for files that EXISTED but
    were skipped - unparseable JSON, not text, too large or too deeply
    nested, unreadable, or a top-level shape we don't understand. A skipped
    file is never a clean bill of health (under --fail-on it is an error). An
    explicit path with no server keys stays a warning: the caller asked for
    that file to be audited.
    """
    found: list[dict] = []
    warnings: list[dict] = []
    if explicit:
        targets = [("explicit", p) for p in explicit]
    else:
        targets = candidate_paths()
    seen: set[str] = set()
    for client, path in targets:
        if not os.path.isfile(path):
            continue
        identity = os.path.normcase(os.path.realpath(path))
        if identity in seen:  # e.g. cwd == home: one file, two names
            continue
        seen.add(identity)
        try:
            data = _read_json(path)
        except ConfigError as e:
            warnings.append({"client": client, "path": path,
                             "reason": str(e)})
            continue
        except OSError as e:
            warnings.append({"client": client, "path": path,
                             "reason": f"unreadable ({e.strerror or e})"})
            continue
        try:
            groups, problems = extract_groups(client, data)
        except Exception as e:  # a shape nobody planned for: say so, go on
            warnings.append({"client": client, "path": path,
                             "reason": f"could not be analyzed "
                                       f"({type(e).__name__})"})
            continue
        if not groups and not problems:
            if client != "explicit" and isinstance(data, dict):
                found.append({"client": client, "path": path, "servers": {}})
                continue
            problems = [_SHAPE_HELP]
        for g in groups:
            found.append({"path": path, **g})
        if problems:
            detail = "; ".join(problems)
            reason = (f"partially audited ({detail})" if groups else
                      f"unknown top-level shape ({detail}) \u2014 not audited")
            warnings.append({"client": client, "path": path,
                             "reason": reason})
    return found, warnings
