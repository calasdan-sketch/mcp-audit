"""JSON with comments and trailing commas (JSONC).

VS Code and Zed write their settings.json as JSONC, and people comment other
clients' files too. Strict `json.load` rejected all of them, so a config with
a `//` note was skipped (a warning, and a clean exit under --fail-on). The
scan is string-aware: a `//` or `/*` inside a string - a URL, a Windows path
- is text, and a comma inside a string is never removed.
"""

from __future__ import annotations

import json
from . import _depth as depth_mod
import re

# One token at a time, from a position. The alternatives are exclusive and
# none of them can fail, so the scan is linear in the size of the text. In
# particular an unterminated string runs to the end of the text instead of
# being retried from every later quote (a crafted file made that quadratic).
_TOKEN_RE = re.compile(
    r'(?P<string>"[^"\\]*(?:\\[\s\S][^"\\]*)*(?:"|\\?\Z))'
    r"|(?P<line>//[^\n]*)"
    r"|(?P<block>/\*)"
    r"|(?P<comma>,)"
    r"|(?P<closer>[}\]])"
    r"|(?P<space>\s+)"
    r'|(?P<other>[^\s"/,}\]]+|/)')

# A comma that follows one of these is not "trailing": `{,}`, `[,]`, `[1,,]`
# and `{"a":,}` stay errors.
_NO_VALUE_BEFORE = "{[,:"


def strip(text: str) -> str:
    """`text` without comments and trailing commas.

    Comments become nothing (a block comment keeps its line breaks, so error
    positions still point at the right line). An unterminated block comment
    is left in place, so that parsing the result fails like any other
    malformed JSON."""
    out: list[str] = []
    prev = ""       # the last significant character kept
    comma = -1      # where in `out` a comma sits that a closer would make trailing
    pos, size = 0, len(text)
    while pos < size:
        m = _TOKEN_RE.match(text, pos)
        kind, token, pos = m.lastgroup, m.group(), m.end()
        if kind == "space":
            out.append(token)
        elif kind == "line":
            continue
        elif kind == "block":
            end = text.find("*/", pos)
            if end < 0:
                out.append(text[m.start():])
                break
            out.append("\n" * text.count("\n", m.start(), end) or " ")
            pos = end + 2
        elif kind == "comma":
            comma = len(out) if prev and prev not in _NO_VALUE_BEFORE else -1
            out.append(token)
            prev = ","
        elif kind == "closer":
            if comma >= 0:
                out[comma] = ""
            comma = -1
            out.append(token)
            prev = token
        else:  # a string, or a run of anything else
            comma = -1
            out.append(token)
            prev = token[-1]
    return "".join(out)


def loads(text: str):
    """Parse JSON or JSONC. Raises ValueError for malformed text,
    RecursionError for text nested too deeply and MemoryError when it is
    too large."""
    depth_mod.check(text)       # our own limit, the same on every Python version
    try:
        return json.loads(text)  # plain JSON (nearly always): nothing to strip
    except ValueError:
        pass
    return json.loads(strip(text))
