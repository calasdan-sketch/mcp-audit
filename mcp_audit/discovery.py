"""Find MCP server configs in known client locations."""

from __future__ import annotations

import json
import os
import platform

# Set this to a directory to make default discovery look there instead of
# the real machine: it replaces the home directory and, for the clients that
# live under %APPDATA%/%LOCALAPPDATA%, <dir>/AppData/Roaming and
# <dir>/AppData/Local. One variable isolates every default path (the
# test-suite relies on it; it also lets you audit a copied user profile).
HOME_ENV = "MCP_AUDIT_HOME"


def roots() -> dict[str, str]:
    """The directories every default-discovery path hangs off.

    "home" is what os.path.expanduser("~") gives (HOME on POSIX, USERPROFILE
    on Windows); "appdata"/"local_appdata" are %APPDATA%/%LOCALAPPDATA%,
    empty when unset off Windows and defaulting to the conventional folders
    on Windows. MCP_AUDIT_HOME overrides all three at once. Nothing else in
    the tool reads HOME, USERPROFILE or APPDATA, so overriding this one
    function (or setting the variable) is enough to isolate discovery.
    """
    override = os.environ.get(HOME_ENV)
    if override:
        return {"home": override,
                "appdata": os.path.join(override, "AppData", "Roaming"),
                "local_appdata": os.path.join(override, "AppData", "Local")}
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    if platform.system() == "Windows":
        appdata = appdata or os.path.join(home, "AppData", "Roaming")
        local_appdata = local_appdata or os.path.join(home, "AppData", "Local")
    return {"home": home, "appdata": appdata, "local_appdata": local_appdata}


def _zed_path(home: str) -> str | None:
    # ~/.config/zed/settings.json is the documented location on macOS and
    # Linux. The Windows location isn't pinned down from documented sources,
    # so Zed discovery is omitted there rather than guessed.
    if platform.system() == "Windows":
        return None
    return os.path.join(home, ".config", "zed", "settings.json")


def candidate_paths() -> list[tuple[str, str]]:
    """(client, path) pairs to check, in a stable order.

    Claude Code, Cursor and Windsurf live under the home directory on every
    OS. VS Code's global settings and Claude Desktop's config live under
    ~/Library/Application Support (macOS), ~/.config (Linux) and %APPDATA%
    (Windows); the %APPDATA% locations are probed whenever APPDATA is set,
    which is always on Windows and lets the other OSes exercise them.
    """
    r = roots()
    home, appdata = r["home"], r["appdata"]
    cwd = os.getcwd()
    system = platform.system()
    vscode_dirs: list[str] = []
    desktop_dirs: list[str] = []
    if system == "Darwin":
        support = os.path.join(home, "Library", "Application Support")
        vscode_dirs.append(os.path.join(support, "Code", "User"))
        desktop_dirs.append(os.path.join(support, "Claude"))
    elif system != "Windows":
        vscode_dirs.append(os.path.join(home, ".config", "Code", "User"))
        desktop_dirs.append(os.path.join(home, ".config", "Claude"))
    if appdata:
        vscode_dirs.append(os.path.join(appdata, "Code", "User"))
        desktop_dirs.append(os.path.join(appdata, "Claude"))
    paths = [
        ("claude-code", os.path.join(home, ".claude.json")),
        ("claude-code-project", os.path.join(cwd, ".mcp.json")),
        ("cursor", os.path.join(home, ".cursor", "mcp.json")),
    ]
    paths += [("vscode", os.path.join(d, "settings.json"))
              for d in vscode_dirs]
    paths += [
        ("vscode-workspace", os.path.join(cwd, ".vscode", "settings.json")),
        ("windsurf", os.path.join(home, ".codeium", "windsurf",
                                  "mcp_config.json")),
    ]
    zed = _zed_path(home)
    if zed:
        paths.append(("zed", zed))
    paths += [("claude-desktop", os.path.join(d, "claude_desktop_config.json"))
              for d in desktop_dirs]
    return paths


# Top-level shapes we recognize but deliberately do NOT audit: the key is
# known but the per-server field mapping can't be verified from documented
# sources, so guessing would risk clean bills on unscanned servers.
_UNSUPPORTED_SHAPES = {
    # Zed nests servers under "context_servers", but the documented
    # per-server schema isn't pinned down well enough to map onto the
    # {command, args, env} shape the detectors expect.
    "context_servers",
}


def _extract_servers(data) -> tuple[dict, str]:
    """Return ({server_name: config}, shape).

    shape names the recognized top-level layout: "mcpServers", "servers",
    "vscode-mcp" ({"mcp": {"servers": ...}}), one of _UNSUPPORTED_SHAPES,
    or "unknown". Precedence is mcpServers > servers > mcp.servers.
    """
    if not isinstance(data, dict):
        return {}, "unknown"
    mcp_servers = data.get("mcpServers")
    if isinstance(mcp_servers, dict):
        return mcp_servers, "mcpServers"
    servers = data.get("servers")
    if isinstance(servers, dict):
        return servers, "servers"
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"], "vscode-mcp"
    for shape in _UNSUPPORTED_SHAPES:
        if isinstance(data.get(shape), dict):
            return {}, shape
    return {}, "unknown"


# Every top-level key some client stores servers under. A known client's
# config object that has NONE of them simply has no MCP servers configured
# (Claude Desktop before any server is added — just coworkUserFilesPath and
# preferences; VS Code settings without an "mcp" block; Claude Code's
# .claude.json without global servers; Zed without context_servers). That
# is "0 servers configured", not an unknown shape. The unknown-shape warning
# is kept for files where one of these keys IS present but has an unexpected
# shape (e.g. "mcpServers": []): servers may be hiding in there.
_SERVER_KEYS = ("mcpServers", "servers", "mcp", *_UNSUPPORTED_SHAPES)


def _read_json(path: str):
    # Client configs are UTF-8 (never the console code page, which is what
    # a bare open() uses on Windows); utf-8-sig also swallows a BOM.
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def load_config(path: str) -> dict:
    """Return {server_name: server_config} from a client config file.

    Unsupported or unrecognized shapes yield {} — use discover() when you
    need to distinguish "no servers configured" from "couldn't parse".
    """
    servers, _shape = _extract_servers(_read_json(path))
    return servers


def discover(explicit: list[str] | None = None
             ) -> tuple[list[dict], list[dict]]:
    """Return (found, warnings).

    found: [{"client", "path", "servers"}] for each config that parsed.
    A known client's config object with none of the server keys is found
    with servers == {} ("0 servers configured").
    warnings: [{"client", "path", "reason"}] for files that EXISTED but
    were skipped — unparseable JSON, unreadable, or a top-level shape we
    don't understand (or understand but can't safely audit). A skipped
    file is never a clean bill of health. An explicit path with no server
    keys stays a warning: the caller asked for that file to be audited.
    """
    found: list[dict] = []
    warnings: list[dict] = []
    targets: list[tuple[str, str]] = []
    if explicit:
        targets = [("explicit", p) for p in explicit]
    else:
        targets = candidate_paths()
    for client, path in targets:
        if not os.path.isfile(path):
            continue
        try:
            data = _read_json(path)
        except json.JSONDecodeError as e:
            warnings.append({"client": client, "path": path,
                             "reason": f"unparseable JSON ({e})"})
            continue
        except (OSError, UnicodeDecodeError) as e:
            warnings.append({"client": client, "path": path,
                             "reason": f"unreadable ({e})"})
            continue
        servers, shape = _extract_servers(data)
        if shape == "unknown":
            if (client != "explicit" and isinstance(data, dict)
                    and not any(k in data for k in _SERVER_KEYS)):
                found.append({"client": client, "path": path, "servers": {}})
                continue
            warnings.append({
                "client": client, "path": path,
                "reason": ("unknown top-level shape (expected mcpServers, "
                           "servers, or mcp.servers) — not audited")})
            continue
        if shape in _UNSUPPORTED_SHAPES:
            warnings.append({
                "client": client, "path": path,
                "reason": (f"unsupported shape '{shape}': per-server field "
                           "mappings unverified — not audited")})
            continue
        found.append({"client": client, "path": path, "servers": servers})
    return found, warnings
