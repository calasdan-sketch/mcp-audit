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
* the arguments of a launch command are never shown (see launch.py): any of
  them can be a credential, and no list of flag names is complete;
* in free text, the value that follows the name of a credential (a header
  `X-Api-Key: ...`, a JSON key `"token": "..."`, `MY_PASS=...`,
  `--auth ...`) is masked.

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
#: Any scheme://... run inside free text. The scheme is bounded: a run of
#: letters is tried from every letter of it, and an unbounded scheme made a
#: megabyte of them take hours.
_URL_IN_TEXT_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]{0,31}://[^\s'\"<>]+")
_TRAILING_PUNCT = ".,;:!?)]}"
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
    body = raw.rstrip(_TRAILING_PUNCT)
    return safe_url(body) + raw[len(body):]


def redact_text(text: str) -> str:
    """Free text with every URL shortened, every credential-shaped token
    replaced and the value after the name of a credential masked (see
    _mask_pairs). Safe to call twice."""
    text = _URL_IN_TEXT_RE.sub(_shorten_url, str(text))
    text = _BEARER_RE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    text = _TOKEN_SHAPES_RE.sub(REDACTED, text)
    return _mask_pairs(text)


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

#: A word that says a credential lives here, wherever it stands in a name.
_SECRET_WORDS = frozenset((
    "TOKEN", "TOKENS", "KEY", "KEYS", "SECRET", "SECRETS", "PASSWORD",
    "PASSWORDS", "PASSWD", "PASSPHRASE", "PASSCODE", "PWD", "CREDENTIAL",
    "CREDENTIALS", "AUTHORIZATION", "BEARER", "COOKIE", "COOKIES", "DSN",
    "PAT",
    # run together, the way people type them: apikey, authtoken, secretkey
    "APIKEY", "APIKEYS", "APITOKEN", "APISECRET", "AUTHTOKEN", "ACCESSTOKEN",
    "ACCESSKEY", "SECRETKEY", "PRIVATEKEY", "CLIENTSECRET", "REFRESHTOKEN"))
#: These only as the LAST word: MY_PASS and BASIC_AUTH hold a credential,
#: AUTH_URL, AUTH0_DOMAIN and PASS_THROUGH do not.
_SECRET_LAST_WORDS = frozenset(("AUTH", "PASS"))
#: Words that make a flag, header or key worth masking when its value is about
#: to be printed, though a variable named with one of them is too often plain
#: configuration to be reported as a secret (SESSION_TYPE, PRIVATE_NETWORK).
_MASKED_WORDS = frozenset(("AUTH", "PASS", "SESSION", "SESSIONID", "PRIVATE",
                           "SIGNATURE", "OTP", "JWT"))
_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def _has_credential_word(name: str, anywhere=frozenset()) -> bool:
    words = [w.upper() for w in _WORD_RE.findall(str(name))]
    for i, word in enumerate(words):
        if not (word in _SECRET_WORDS or word in anywhere
                or (word in _SECRET_LAST_WORDS and i == len(words) - 1)):
            continue
        if word in ("KEY", "KEYS") and i > 0 and words[i - 1] == "PUBLIC":
            continue
        return True
    return False


def is_secret_name(name: str) -> bool:
    """True when a variable or flag name has a credential word in it:
    API_KEY, OPENAI_KEY, apiKey, GITHUB_PAT, --password, DB_PASSWORD, MY_PASS,
    BASIC_AUTH. PUBLIC_KEY is not secret, KEYBOARD_LAYOUT is not about keys,
    and AUTH_URL and PASS_THROUGH are settings, not credentials."""
    return _has_credential_word(name)


def is_credential_name(name: str) -> bool:
    """True when the value that goes with this header, flag or key must not be
    printed: everything is_secret_name says, and also AUTH or PASS anywhere in
    the name, SESSION, PRIVATE, SIGNATURE, OTP and JWT (`X-Session-Id`,
    `--private-url`: masking too much only costs a "[redacted]")."""
    return _has_credential_word(name, _MASKED_WORDS)


#: An option that starts with one of these turns something off (--no-auth,
#: --skip-password): no credential follows it.
_NEGATIONS = frozenset(("NO", "WITHOUT", "SKIP", "DISABLE", "DISABLED"))


def takes_a_credential(option: str) -> bool:
    """True for an option that is handed a credential as its value (--auth,
    --token, --api-key, --private-key), not for one that switches something
    off (--no-auth, --skip-password)."""
    words = [w.upper() for w in _WORD_RE.findall(str(option))]
    return bool(words) and words[0] not in _NEGATIONS and is_credential_name(
        option)


def is_negation(option: str) -> bool:
    """True for an option that switches something off (--no-cache,
    --skip-auth, --without-x, --disable-y): by habit a switch, which takes no
    value."""
    words = [w.upper() for w in _WORD_RE.findall(str(option))]
    return bool(words) and words[0] in _NEGATIONS


# -- the value that follows the name of a credential ---------------------------
#
# Free text that reaches an output can quote a command line (a finding, a
# probe note). Wherever one does, `name: value` / `name=value` / `--name value`
# / `"name": "value"` with a credential in the name loses its value. This is
# the last line of defense, not the first: launch commands are not printed at
# all (launch.py), because no rule about names is complete.

_PAIR_RE = re.compile(
    # a whole word: not the end of a longer one, of a path or of a file name
    r"(?<![A-Za-z0-9_\-/\\.])"
    r"(?P<name>-{0,2}[A-Za-z][A-Za-z0-9_\-]{0,63})"
    r"(?P<quote>[\"']?)"
    r"(?P<sep>[ \t]*[:=][ \t]*|[ \t]+(?=[^\s\-]))")
#: Where an unquoted value ends: a header runs to the end of its line or to the
#: quote that closes the argument it is in; anything else is one word.
_HEADER_END_RE = re.compile(r"[\r\n\"'`]")
_WORD_END_RE = re.compile(r"[\s\"'`&,;]")
#: ...and a bare value after a quoted key is a JSON number, true or null.
_JSON_END_RE = re.compile(r"[\s\"'`&,;}\]]")
_LINE_END_RE = re.compile(r"[\r\n]")
#: Header names whose value is "<scheme> <credential>" or longer, with quotes
#: of its own (`Digest username="u", response="..."`).
_WHOLE_LINE_WORDS = frozenset(("AUTHORIZATION", "COOKIE", "COOKIES"))
_pair_cache: dict = {}


def _pair_kind(name: str) -> "str | None":
    """None when a value after `name` is nobody's business, else "line" (a
    header whose value runs to the end of the line) or "plain"."""
    kind = _pair_cache.get(name, False)
    if kind is False:
        if not is_credential_name(name):
            kind = None
        else:
            words = {w.upper() for w in _WORD_RE.findall(name)}
            kind = "line" if words & _WHOLE_LINE_WORDS else "plain"
        if len(_pair_cache) < 4096:
            _pair_cache[name] = kind
    return kind


def _value_end(text: str, i: int, header: bool, whole_line: bool,
               json_key: bool = False) -> int:
    """Index just after the value that starts at text[i]."""
    n = len(text)
    if i >= n:
        return i
    if text.startswith(REDACTED, i):  # masked already: leave it, and the quote
        return i + len(REDACTED)
    c = text[i]
    if c in "\"'" and not whole_line:
        j = i + 1
        while j < n:
            if text[j] == "\\":
                j += 2
            elif text[j] == c:
                return j + 1
            else:
                j += 1
        return n
    ender = (_LINE_END_RE if whole_line else
             _HEADER_END_RE if header else
             _JSON_END_RE if json_key else _WORD_END_RE)
    m = ender.search(text, i)
    return m.start() if m else n


def _mask_pairs(text: str) -> str:
    """`text` with the value after every credential name replaced by
    [redacted]: `X-Api-Key: v` and `Authorization: Bearer v` (a header),
    `"token": "v"` and `{token: 'v'}` (JSON and its relatives), `MY_PASS=v`
    and `--auth=v` (an assignment), `--auth v` (a flag; the word after it).
    Linear in the length of the text."""
    out: list[str] = []
    pos = 0
    for m in _PAIR_RE.finditer(text):
        if m.start() < pos:  # inside a value that is masked already
            continue
        name, sep = m.group("name"), m.group("sep")
        by_space = not sep.strip()
        if by_space and not name.startswith("-"):
            continue  # "word word" is prose; only a flag takes its next word
        kind = _pair_kind(name)
        if kind is None:
            continue
        start = m.end()
        # a header's value may hold quotes of its own; a JSON key's is a JSON
        # value, which ends where its quote does
        quoted_key = bool(m.group("quote"))
        end = _value_end(text, start, header=":" in sep and not quoted_key,
                         whole_line=(kind == "line" and ":" in sep
                                     and not quoted_key),
                         json_key=quoted_key)
        if end <= start:
            continue
        value = text[start:end]
        if value == REDACTED:
            continue
        q = value[0] if value[0] in "\"'" and not (
            kind == "line" and not m.group("quote")) else ""
        closed = len(value) > 1 and value[-1] == q
        out.append(text[pos:start])
        out.append(q + REDACTED + (q if closed else "") if q else REDACTED)
        pos = end
    out.append(text[pos:])
    return "".join(out)
