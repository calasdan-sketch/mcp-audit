"""Static detectors: config-level checks needing no network and no execution."""

from __future__ import annotations

import json
import os
import re

ADVISORIES_PATH = os.path.join(os.path.dirname(__file__), "advisories.json")

# A finding: {"severity": "critical|high|medium|low",
#             "check": str, "message": str}
SEVERITIES = ("critical", "high", "medium", "low")

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
LOCAL_RE = re.compile(r"https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(/|$)",
                      re.IGNORECASE)
SECRET_KEY_RE = re.compile(r"(TOKEN|API_KEY|SECRET|PASSWORD|PRIVATE_KEY)",
                           re.IGNORECASE)
# npx -y @scope/pkg  (floating) vs  npx -y @scope/pkg@1.2.3 (pinned)
FLOATING_PKG_RE = re.compile(r"^(@[^/]+/[^@\s]+|[^@\s/]+)$")
PINNED_PKG_RE = re.compile(r"^(@[^/]+/[^@\s]+|[^@\s/]+)@[^@\s]+$")
SUSPICIOUS_CMDS = {"curl", "wget", "bash", "sh", "powershell", "cmd"}
PIPE_TO_SHELL_RE = re.compile(r"\|\s*(ba)?sh\b|\beval\b", re.IGNORECASE)


def _finding(severity: str, check: str, message: str) -> dict:
    return {"severity": severity, "check": check, "message": message}


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
        if not LOCAL_RE.match(url):
            findings.append(_finding(
                "medium", "remote-server",
                f"remote MCP server URL (traffic leaves the machine): {url}"))
        return findings
    for where, text in _text_blobs(cfg):
        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(".,;)")
            if LOCAL_RE.match(url):
                continue
            # Data exfiltration IS critical: a baked-in remote URL means
            # server traffic can leave the machine. Critical so --fix can
            # remove the server (with backup).
            findings.append(_finding(
                "critical",
                "exfiltration-endpoint",
                f"remote URL in {where}: {url}"))
    return findings


def detect_suspicious_command(name: str, cfg: dict) -> list[dict]:
    findings = []
    cmd_raw = str(cfg.get("command") or "")
    cmd = cmd_raw.split("/")[-1].lower()
    argtext = " ".join(str(a) for a in (cfg.get("args") or []))
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
    return findings


def _iter_packages(cfg: dict) -> list[tuple[str, str | None]]:
    """(package, version|None) for npx/uvx-launched servers."""
    cmd = str(cfg.get("command") or "").split("/")[-1].lower()
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
        with open(ADVISORIES_PATH) as f:
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
    cmd = str(cfg.get("command") or "").split("/")[-1].lower()
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
        findings.append(_finding(sev, "known-vulnerable", msg))
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
