"""Static detectors: config-level checks needing no network and no execution."""

from __future__ import annotations

import ipaddress
import json
import ntpath
import os
import re
import urllib.parse
import urllib.request

ADVISORIES_PATH = os.path.join(os.path.dirname(__file__), "advisories.json")

# A finding: {"severity": "critical|high|medium|low",
#             "check": str, "message": str}
SEVERITIES = ("critical", "high", "medium", "low")

URL_RE = re.compile(r"(?:https?|wss?)://[^\s'\"<>]+", re.IGNORECASE)
# Bare IPv4:port callbacks ("203.0.113.9:4444") not already part of a URL.
IP_PORT_RE = re.compile(r"(?<![\w./:])(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b")
# Well-known vendor API hosts that official MCP servers are configured with
# (e.g. GITHUB_API_URL=https://api.github.com). HTTPS/WSS only. A leading
# "." means "any subdomain of". Keep this list short: every entry is a host
# an attacker cannot receive traffic on.
ALLOWED_API_HOSTS = (
    "api.github.com",
    "api.openai.com",
    "api.anthropic.com",
    ".googleapis.com",
    "api.slack.com",
    "api.notion.com",
    "api.linear.app",
    "api.stripe.com",
)
SECRET_KEY_RE = re.compile(r"(TOKEN|API_KEY|SECRET|PASSWORD|PRIVATE_KEY)",
                           re.IGNORECASE)
# npx -y @scope/pkg  (floating) vs  npx -y @scope/pkg@1.2.3 (pinned)
FLOATING_PKG_RE = re.compile(r"^(@[^/]+/[^@\s]+|[^@\s/]+)$")
PINNED_PKG_RE = re.compile(r"^(@[^/]+/[^@\s]+|[^@\s/]+)@[^@\s]+$")
SUSPICIOUS_CMDS = {"curl", "wget", "bash", "sh", "powershell", "pwsh", "cmd"}
INTERPRETERS = {"python", "python3", "py", "node", "deno", "bun", "ruby",
                "perl", "php"}
INLINE_FLAGS = {"-c", "-e", "--eval", "-p", "--print"}
PS_ENCODED_RE = re.compile(r"^[-/](e|ec|en\w*)$", re.IGNORECASE)
PS_COMMAND_RE = re.compile(r"^[-/](c|com\w*)$", re.IGNORECASE)
PIPE_TO_SHELL_RE = re.compile(r"\|\s*(ba)?sh\b|\beval\b", re.IGNORECASE)


def _finding(severity: str, check: str, message: str) -> dict:
    return {"severity": severity, "check": check, "message": message}


def _cmd_name(cfg: dict) -> str:
    """Bare, lower-case command name for POSIX or Windows paths:
    C:\\...\\PowerShell.exe -> "powershell", npx.cmd -> "npx"."""
    name = ntpath.basename(str(cfg.get("command") or "")).lower()
    for ext in (".exe", ".cmd", ".bat"):
        if name.endswith(ext):
            return name[:-len(ext)]
    return name


def _is_local(host: str) -> bool:
    host = (host or "").strip("[]").lower()
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _is_allowed_api(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme.lower() not in ("https", "wss") or not host:
        return False
    return any(host.endswith(h) if h.startswith(".") else host == h
               for h in ALLOWED_API_HOSTS)


def _endpoints(text: str) -> list[str]:
    """Remote, non-allowlisted endpoints (URLs and bare IP:port) in text."""
    out = []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;)")
        host = urllib.parse.urlsplit(url).hostname or ""
        if not _is_local(host) and not _is_allowed_api(url):
            out.append(url)
    for m in IP_PORT_RE.finditer(text):
        try:
            ipaddress.ip_address(m.group(1))
        except ValueError:
            continue  # not an IP (e.g. a version string)
        if not _is_local(m.group(1)):
            out.append(m.group(0))
    return out


def _text_blobs(cfg: dict) -> list[tuple[str, str]]:
    """(where, text) pairs worth scanning: args joined + env values."""
    blobs = []
    args = cfg.get("args") or []
    if args:
        blobs.append(("args", " ".join(str(a) for a in args)))
    for k, v in (cfg.get("env") or {}).items():
        blobs.append((f"env:{k}", str(v)))
    if cfg.get("command"):
        blobs.append(("command", str(cfg.get("command"))))
    return blobs


def detect_exfiltration(name: str, cfg: dict) -> list[dict]:
    """Remote URLs baked into a server's launch config."""
    findings = []
    # Remote (non-stdio) servers are inherently networked — note it.
    if cfg.get("url"):
        url = str(cfg["url"])
        if not _is_local(urllib.parse.urlsplit(url).hostname or ""):
            findings.append(_finding(
                "medium", "remote-server",
                f"remote MCP server URL (traffic leaves the machine): {url}"))
        return findings
    for where, text in _text_blobs(cfg):
        for url in _endpoints(text):
            # A remote endpoint baked into launch args is critical. In env it
            # is usually service config (API base URLs), so medium: worth a
            # look, not a verdict. Well-known API hosts are not reported.
            sev = "medium" if where.startswith("env:") else "critical"
            findings.append(_finding(
                sev, "exfiltration-endpoint",
                f"remote endpoint in {where}: {url}"))
    return findings


def detect_suspicious_command(name: str, cfg: dict) -> list[dict]:
    findings = []
    cmd_raw = str(cfg.get("command") or "")
    cmd = _cmd_name(cfg)
    args = [str(a) for a in (cfg.get("args") or [])]
    argtext = " ".join(args)
    if cmd in SUSPICIOUS_CMDS:
        findings.append(_finding(
            "critical", "suspicious-command",
            f"server launches via '{cmd}' — a downloader/shell, not a server binary"))
    # Piping a remote download into a shell (curl … | sh, wget … | bash) is
    # CRITICAL — check the command string too (e.g. sh -c "curl … | sh").
    if PIPE_TO_SHELL_RE.search(argtext + " " + cmd_raw):
        findings.append(_finding(
            "critical", "pipe-to-shell",
            "command pipes content into a shell (classic curl|sh pattern)"))
    findings.extend(_inline_code(cmd, args))
    return findings


def _inline_code(cmd: str, args: list[str]) -> list[dict]:
    """Code passed inline instead of a server file: python -c, node -e,
    powershell -EncodedCommand / -Command."""
    if cmd in ("powershell", "pwsh"):
        if any(PS_ENCODED_RE.match(a) for a in args):
            return [_finding("critical", "inline-code",
                             f"'{cmd}' runs a base64-encoded command "
                             "(-EncodedCommand) — hidden payload")]
        if any(PS_COMMAND_RE.match(a) for a in args):
            return [_finding("high", "inline-code",
                             f"'{cmd}' runs an inline -Command script")]
        return []
    if cmd in INTERPRETERS or re.fullmatch(r"python3(\.\d+)?", cmd):
        # Interpreter options come before the script; "-c" after
        # "server.py" belongs to the server.
        for a in args:
            if not a.startswith("-"):
                break
            if a in INLINE_FLAGS:
                return [_finding("high", "inline-code",
                                 f"'{cmd} {a}' runs inline code instead of "
                                 "a server file")]
    return []


def _iter_packages(cfg: dict) -> list[tuple[str, str | None]]:
    """(package, version|None) for npx/uvx-launched servers."""
    cmd = _cmd_name(cfg)
    if cmd not in ("npx", "uvx", "pnpm", "bunx"):
        return []
    args = [str(a) for a in (cfg.get("args") or [])]
    # find token after -y / --yes, else first non-flag token
    pkg = None
    for i, a in enumerate(args):
        if a in ("-y", "--yes") and i + 1 < len(args):
            pkg = args[i + 1]
            break
    if pkg is None:
        for a in args:
            if not a.startswith("-"):
                pkg = a
                break
    if not pkg:
        return []
    m = PINNED_PKG_RE.match(pkg)
    if m:
        if pkg.startswith("@"):
            base, _, ver = pkg[1:].partition("@")
            base = "@" + base
        else:
            base, _, ver = pkg.partition("@")
        return [(base, ver or None)]
    if FLOATING_PKG_RE.match(pkg):
        return [(pkg, None)]
    return []


def detect_floating_version(name: str, cfg: dict) -> list[dict]:
    findings = []
    for pkg, ver in _iter_packages(cfg):
        if ver is None:
            findings.append(_finding(
                "medium", "floating-version",
                f"unpinned package '{pkg}' — every launch can pull a "
                f"different (possibly compromised) release; pin with pkg@x.y.z"))
    return findings


def load_advisories() -> list[dict]:
    try:
        # The feed is UTF-8 (it has em dashes); decoding it with a Windows
        # code page would garble titles or, on some pages, drop the feed.
        with open(ADVISORIES_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _ver_tuple(v: str) -> tuple:
    parts = []
    for p in str(v).split("."):
        try:
            parts.append(int("".join(c for c in p if c.isdigit()) or 0))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def detect_known_bad(name: str, cfg: dict,
                     advisories: list[dict] | None = None) -> list[dict]:
    findings = []
    advisories = load_advisories() if advisories is None else advisories
    if not advisories:
        return findings
    pkgs = {p.lower(): v for p, v in _iter_packages(cfg)}
    # also match plain command names (uvx mcp-server-git -> "mcp-server-git")
    cmd = _cmd_name(cfg)
    haystack = set(pkgs) | {cmd}
    for adv in advisories:
        target = str(adv.get("package", "")).lower()
        if not target or target not in haystack:
            continue
        fixed = adv.get("fixed_in")
        installed = pkgs.get(target)
        cve = adv.get("cve") or "advisory"
        if fixed and installed and _ver_tuple(installed) >= _ver_tuple(fixed):
            continue  # patched
        sev = adv.get("severity", "high")
        if fixed:
            remedy = f"Fixed in {fixed}; installed {installed or 'unknown'}."
        else:
            remedy = "No fixed version on record — review manually."
        msg = f"matches {cve}: {adv.get('title', '')}. {remedy}"
        if adv.get("verified") is False:
            # Unconfirmed reports never outrank medium or pose as fact.
            sev = "medium" if sev in ("critical", "high") else sev
            msg = (f"UNVERIFIED report ({cve}, no matching OSV record): "
                   f"{adv.get('title', '')}. Check before acting.")
        findings.append(_finding(sev, "known-vulnerable", msg))
    return findings


OSV_URL = "https://api.osv.dev/v1/query"


def detect_osv(name: str, cfg: dict, timeout: float = 10) -> list[dict]:
    """--online: look up pinned npx/uvx packages in OSV (api.osv.dev).

    Sends only the package name + version. Unpinned packages are skipped
    (floating-version already flags them; "all versions" results mislead).
    """
    eco = "PyPI" if _cmd_name(cfg) == "uvx" else "npm"
    findings = []
    for pkg, ver in _iter_packages(cfg):
        if not ver:
            continue
        body = json.dumps({"package": {"name": pkg, "ecosystem": eco},
                           "version": ver}).encode()
        req = urllib.request.Request(
            OSV_URL, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                vulns = json.load(resp).get("vulns") or []
        except (OSError, ValueError) as e:
            findings.append(_finding("low", "osv-lookup",
                                     f"OSV lookup for {pkg}@{ver} failed: {e}"))
            continue
        for v in vulns:
            findings.append(_finding(
                "high", "known-vulnerable",
                f"{pkg}@{ver} is affected by {v.get('id')} (OSV): "
                f"{v.get('summary') or 'see https://osv.dev/' + str(v.get('id'))}"))
    return findings


def detect_secret_env(name: str, cfg: dict) -> list[dict]:
    findings = []
    secrets = [k for k in (cfg.get("env") or {}) if SECRET_KEY_RE.search(k)]
    if secrets:
        shown = ", ".join(sorted(secrets)[:5])
        more = f" (+{len(secrets) - 5} more)" if len(secrets) > 5 else ""
        findings.append(_finding(
            "medium", "secret-env",
            f"server receives secrets via env: {shown}{more} — "
            f"a compromised server leaks these"))
    return findings


STATIC_DETECTORS = (
    detect_suspicious_command,
    detect_exfiltration,
    detect_known_bad,
    detect_floating_version,
    detect_secret_env,
)


def audit_server(name: str, cfg: dict,
                 advisories: list[dict] | None = None) -> list[dict]:
    """Run all static detectors against one server entry."""
    findings: list[dict] = []
    for det in STATIC_DETECTORS:
        try:
            if det is detect_known_bad:
                findings.extend(det(name, cfg, advisories))
            else:
                findings.extend(det(name, cfg))
        except Exception as e:  # a detector must never kill the audit
            findings.append(_finding(
                "low", "detector-error",
                f"detector {det.__name__} failed: {e}"))
    return findings
