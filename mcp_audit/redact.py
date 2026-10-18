"""Keep secrets out of everything mcp-audit prints.

mcp-audit reads configs that hold credentials (URLs with a password, tokens
in a query string, API keys in env, Authorization headers). Whatever it
prints - the human report, --format json, SARIF (which people upload to
GitHub), the --fix plan, the --deep notice - must never repeat one. The
rules are blunt on purpose:

* a URL is shown as scheme://host[:port] and, when anything followed it, a
  "/..." (no userinfo, no path, no query, no fragment: a webhook's secret is
  often the path);
* env values and headers are never shown at all;
* the value of an argument that looks like a credential is masked.

Nothing it prints may drive the terminal either: control characters (ESC
sequences, NUL), bidirectional overrides and other invisible characters in a
server name, path or quoted argument are spelled out as \\x1b / \\u202e
(see sanitize), so a config cannot clear the screen or fake a line of the
report.
"""

from __future__ import annotations

import re
import unicodedata

_URL_PARTS_RE = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://(?P<authority>[^/?#]*)"
    r"(?P<rest>.*)$", re.DOTALL)
#: Any scheme://... run inside free text.
_URL_IN_TEXT_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s'\"<>]+")
_TRAILING_PUNCT_RE = re.compile(r"[.,;:!?)\]}]+$")
_MAX_HOST = 120

REDACTED = "[redacted]"

#: Shapes of well-known credentials, redacted wherever they appear.
_TOKEN_SHAPES_RE = re.compile("|".join((
    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}",
    r"\bgithub_pat_[A-Za-z0-9_]{20,}",
    r"\bsk-[A-Za-z0-9_\-]{16,}",
    r"\bxox[abeprs]-[A-Za-z0-9\-]{10,}",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bAIza[0-9A-Za-z_\-]{30,}",
    r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*",
)))
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=\-]{8,}")


def safe_url(url: str) -> str:
    """`url` as scheme://host[:port] (+ "/..." if a path, query or fragment
    followed). Never raises; text that is not a URL comes back as "<url>"."""
    m = _URL_PARTS_RE.match(str(url).strip())
    if not m:
        return "<url>"
    host = m.group("authority").rsplit("@", 1)[-1]  # drop the userinfo
    if len(host) > _MAX_HOST:
        host = host[:_MAX_HOST] + "..."
    rest = m.group("rest")
    suffix = rest if rest in ("", "/") else "/..."
    return f"{m.group('scheme').lower()}://{host}{suffix}"


def _shorten_url(match: "re.Match[str]") -> str:
    raw = match.group(0)
    tail = _TRAILING_PUNCT_RE.search(raw)
    if tail:
        return safe_url(raw[:tail.start()]) + tail.group(0)
    return safe_url(raw)


def redact_text(text: str) -> str:
    """Free text with every URL shortened and every credential-shaped token
    replaced. Safe to call twice."""
    text = _URL_IN_TEXT_RE.sub(_shorten_url, str(text))
    text = _BEARER_RE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    return _TOKEN_SHAPES_RE.sub(REDACTED, text)


# -- characters that must not reach a terminal or a viewer as themselves ------

#: Control (ESC, CSI, NUL, DEL), format (bidi overrides and isolates, zero
#: width, BOM, tags), surrogate, private-use and unassigned characters, and
#: the line and paragraph separators.
_UNSAFE_CATEGORIES = frozenset(("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"))
_NAMED_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _spell(ch: str) -> str:
    named = _NAMED_ESCAPES.get(ch)
    if named:
        return named
    code = ord(ch)
    if code < 0x100:
        return f"\\x{code:02x}"
    if code < 0x10000:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def sanitize(text) -> str:
    """`text` with every unsafe character (see _UNSAFE_CATEGORIES, line
    breaks and tabs included) spelled out as an escape: ESC becomes the four
    characters \\x1b. Plain text, accents, CJK and emoji pass through. Never
    raises for a string; applying it twice changes nothing."""
    text = str(text)
    if text.isprintable():  # nearly always: nothing to spell out
        return text
    return "".join(
        _spell(ch) if (not ch.isprintable()
                       and unicodedata.category(ch) in _UNSAFE_CATEGORIES)
        else ch
        for ch in text)


def sanitize_report(text: str) -> str:
    """A multi-line report with each line sanitized. Only "\\n" separates
    lines; any other line break inside a line is escaped."""
    return "\n".join(sanitize(line) for line in str(text).split("\n"))


def sanitize_tree(node):
    """A parsed JSON document with every string in it - keys included -
    sanitized. Numbers, booleans and null are untouched."""
    if isinstance(node, str):
        return sanitize(node)
    if isinstance(node, dict):
        return {sanitize(k): sanitize_tree(v) for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return [sanitize_tree(v) for v in node]
    return node


def clean(text: str) -> str:
    """Everything a message needs before it is shown: no URL path or
    credential, and no character that drives a terminal."""
    return sanitize(redact_text(text))


# -- names that mean "a credential lives here" --------------------------------

_SECRET_WORDS = frozenset((
    "TOKEN", "TOKENS", "KEY", "KEYS", "SECRET", "SECRETS", "PASSWORD",
    "PASSWORDS", "PASSWD", "PASSPHRASE", "PWD", "CREDENTIAL", "CREDENTIALS",
    "AUTHORIZATION", "BEARER", "COOKIE", "DSN", "PAT"))
_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def is_secret_name(name: str) -> bool:
    """True when a variable or flag name has a credential word in it:
    API_KEY, OPENAI_KEY, apiKey, GITHUB_PAT, --password, DB_PASSWORD.
    PUBLIC_KEY is not secret, and KEYBOARD_LAYOUT is not about keys."""
    words = [w.upper() for w in _WORD_RE.findall(str(name))]
    for i, word in enumerate(words):
        if word not in _SECRET_WORDS:
            continue
        if word in ("KEY", "KEYS") and i > 0 and words[i - 1] == "PUBLIC":
            continue
        return True
    return False


# -- a command line that is safe to show --------------------------------------

_FLAG_RE = re.compile(r"^(-{1,2}[A-Za-z0-9][\w\-.]*)(=(.*))?$", re.DOTALL)
_ASSIGN_RE = re.compile(r"^([A-Za-z_][\w.\-]*)=(.*)$", re.DOTALL)


def _mask_args(args: list[str]) -> list[str]:
    out: list[str] = []
    mask_next = False
    for arg in args:
        if mask_next and not arg.startswith("-"):
            out.append(REDACTED)
            mask_next = False
            continue
        mask_next = False
        flag = _FLAG_RE.match(arg)
        if flag:
            name, has_value = flag.group(1), flag.group(2) is not None
            if is_secret_name(name):
                if has_value:
                    out.append(f"{name}={REDACTED}")
                else:
                    out.append(name)
                    mask_next = True
                continue
            if has_value:
                out.append(f"{name}={redact_text(flag.group(3))}")
                continue
            out.append(arg)
            continue
        assign = _ASSIGN_RE.match(arg)
        if assign and "://" not in arg and is_secret_name(assign.group(1)):
            out.append(f"{assign.group(1)}={REDACTED}")
            continue
        out.append(redact_text(arg))
    return out


def command_line(cfg, limit: int = 160) -> str:
    """The launch command of a server entry as one line, with credentials
    masked and URLs shortened, cut to `limit` characters. Env values and
    headers are not part of it. Never raises."""
    try:
        if not isinstance(cfg, dict):
            return "<not a command>"
        command = cfg.get("command")
        if cfg.get("url") and not command:
            return safe_url(str(cfg["url"]))
        args = cfg.get("args")
        parts = [redact_text(str(command))] if command else []
        if isinstance(args, list):
            parts += _mask_args([str(a) for a in args])
        line = " ".join(parts)
    except Exception:  # display only: never let it take the report down
        return "<unprintable>"
    return line if len(line) <= limit else line[:limit - 3] + "..."
