"""Find MCP server configs in known client locations."""

from __future__ import annotations

import json
import os
import platform


def _vscode_global_path(home: str) -> str:
    system = platform.system()
    if system == "Darwin":
        return os.path.join(home, "Library", "Application Support",
                            "Code", "User", "settings.json")
    if system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        return os.path.join(appdata, "Code", "User", "settings.json")
    return os.path.join(home, ".config", "Code", "User", "settings.json")


def _zed_path(home: str) -> str | None:
    # ~/.config/zed/settings.json is the documented location on macOS and
    # Linux. The Windows location isn't pinned down from documented sources,
    # so Zed discovery is omitted there rather than guessed.
    if platform.system() == "Windows":
        return None
    return os.path.join(home, ".config", "zed", "settings.json")


def candidate_paths() -> list[tuple[str, str]]:
    """(client, path) pairs to check, in a stable order."""
    home = os.path.expanduser("~")
    cwd = os.getcwd()
    paths = [
        ("claude-code", os.path.join(home, ".claude.json")),
        ("claude-code-project", os.path.join(cwd, ".mcp.json")),
        ("cursor", os.path.join(home, ".cursor", "mcp.json")),
        ("vscode", _vscode_global_path(home)),
        ("vscode-workspace", os.path.join(cwd, ".vscode", "settings.json")),
        ("windsurf", os.path.join(home, ".codeium", "windsurf",
                                  "mcp_config.json")),
    ]
    zed = _zed_path(home)
    if zed:
        paths.append(("zed", zed))
    system = platform.system()
    if system == "Darwin":
        paths.append((
            "claude-desktop",
            os.path.join(home, "Library", "Application Support",
                         "Claude", "claude_desktop_config.json"),
        ))
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        paths.append((
            "claude-desktop",
            os.path.join(appdata, "Claude", "claude_desktop_config.json"),
        ))
    else:
        paths.append((
            "claude-desktop",
            os.path.join(home, ".config", "Claude",
                         "claude_desktop_config.json"),
        ))
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


def load_config(path: str) -> dict:
    """Return {server_name: server_config} from a client config file.

    Unsupported or unrecognized shapes yield {} — use discover() when you
    need to distinguish "no servers configured" from "couldn't parse".
    """
    with open(path) as f:
        data = json.load(f)
    servers, _shape = _extract_servers(data)
    return servers


def discover(explicit: list[str] | None = None
             ) -> tuple[list[dict], list[dict]]:
    """Return (found, warnings).

    found: [{"client", "path", "servers"}] for each config that parsed.
    warnings: [{"client", "path", "reason"}] for files that EXISTED but
    were skipped — unparseable JSON, unreadable, or a top-level shape we
    don't understand (or understand but can't safely audit). A skipped
    file is never a clean bill of health.
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
            with open(path) as f:
                data = json.load(f)
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
            # Zed's settings.json without a context_servers key means no Zed
            # MCP servers are configured — a known negative, not an unknown
            # shape.
            if client == "zed" and "context_servers" not in data:
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
