r"""Where does a URL point? One answer that does not depend on the parser.

mcp-audit decides whether an endpoint in a config is the local machine or a
host it trusts. Python's urllib and the parsers MCP servers are written with
(the WHATWG URL standard: Node's `new URL`, Deno, Bun, browsers) read some
strings differently, so an allowlist that believed only urllib could be walked
around:

* `https://evil.example\@api.github.com/c` - urllib: the host is
  api.github.com and `evil.example\` is userinfo; WHATWG: a backslash is a
  slash, so the host is evil.example;
* `http://localhost<TAB>.evil.example/` - a WHATWG parser deletes tabs and line
  feeds wherever they are, and the host is localhost.evil.example;
* `http:\\evil.example` and `http:///evil.example` - WHATWG skips any run of
  slashes and backslashes after a special scheme; urllib sees no host.

parse() returns every host a parser could take the URL to point to (its
"readings"). A caller treats a URL as safe only when ALL of them are, so a
disagreement can only make a URL louder, never quieter.

Hosts that cannot be judged from the text alone are marked not exact and are
never taken for the local machine or a trusted host: percent escapes in a host
(`%6c%6f%63...` decodes to a name the text does not show) and non-ASCII names
(mapped to ASCII by IDNA rules that differ between parsers). Numeric hosts in
unusual spellings (`0x7f.1`, `2130706433`) are plain names here, so they are
never taken for the local machine either.

Stdlib only; nothing here resolves a name or touches the network.
"""

from __future__ import annotations

import ipaddress
import re
from typing import NamedTuple

#: What a WHATWG parser deletes from anywhere in the string.
DROPPED = {9: None, 10: None, 13: None}

#: Schemes the WHATWG standard calls "special" (file: aside, whose host is a
#: different matter): a backslash is a slash in them and any run of slashes
#: after the scheme is skipped.
_SPECIAL = frozenset(("http", "https", "ws", "wss", "ftp"))
_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:")
#: What a WHATWG parser strips from both ends of a URL.
C0_AND_SPACE = "".join(chr(c) for c in range(0x21))
_SPACE = re.compile(r"\s")
#: Characters no real host name has. A WHATWG parser accepts a quote in one
#: (`localhost'.evil.example` is a name it resolves) and rejects the others,
#: but other parsers take them: none of these hosts is ever taken for a
#: known one.
_ODD = re.compile(r"['\"<>\x00-\x1f\x7f]")
_END_RFC = re.compile(r"[/?#]")
_END_WHATWG = re.compile(r"[/\\?#]")
_MAX_SHOWN = 120
_MAX_HOST = 2048


class UnparseableUrl(ValueError):
    """The URL cannot be taken apart (a broken `[...]`, a host that does not
    encode, no host at all where one is required)."""


class NoHost(UnparseableUrl):
    """There is an authority, but no host in it (`http://`, `http://?x`)."""


class Reading(NamedTuple):
    host: str     # lower-case ASCII, IPv6 compressed and without brackets,
    #               one trailing dot removed: what decisions are made on
    exact: bool   # False: the text alone does not say which host this is
    shown: str    # host[:port] as it may be printed (no userinfo)
    tail: str     # how to print what follows the host: "", "/" or "/..."


class Url(NamedTuple):
    scheme: str                 # lower-case; "" when there is no scheme
    readings: "tuple[Reading, ...]"
    ambiguous: bool             # parsers can disagree about the host


def _split_host(info: str) -> "tuple[str, str, bool]":
    """(host, port, bracketed) of `host[:port]` or `[ipv6][:port]`."""
    if info.startswith("["):
        end = info.find("]")
        if end < 0:
            raise UnparseableUrl("unterminated [")
        tail = info[end + 1:]
        if tail and not tail.startswith(":"):
            raise UnparseableUrl("text after ]")
        return info[1:end], tail[1:], True
    if "[" in info or "]" in info:
        raise UnparseableUrl("stray bracket")
    host, _, port = info.partition(":")
    return host, port, False


def _reading(rest: str, end_re: "re.Pattern[str]") -> "Reading | None":
    """The host in `rest` (what follows the slashes of `scheme://`), or None
    when it is empty."""
    m = end_re.search(rest)
    end = m.start() if m else len(rest)
    authority, tail = rest[:end], rest[end:]
    # What follows the last "@" is the host; before it is userinfo, which may
    # hold anything - a space or a quote there is how a URL is split in two.
    # Nothing after a space in the host can be connected to (a parser rejects
    # it, a shell word ends there): the rest is prose.
    info = authority.rpartition("@")[2]
    blank = _SPACE.search(info)
    host, port, bracketed = _split_host(info[:blank.start()] if blank
                                        else info)
    if not host:
        return None
    port_text = f":{port}" if port.isascii() and port.isdigit() and \
        len(port) <= 5 else ""
    tail = "" if not tail else "/" if tail in ("/", "\\") else "/..."
    if bracketed:
        if "%" in host:
            raise UnparseableUrl("zone id in an IPv6 address")
        try:
            ip = ipaddress.IPv6Address(host)
        except ValueError:
            raise UnparseableUrl("not an IPv6 address") from None
        # One spelling for an IPv4-mapped address on every Python version
        # (3.13 prints ::ffff:127.0.0.1, 3.12 prints ::ffff:7f00:1).
        name = (f"::ffff:{ip.ipv4_mapped}" if ip.ipv4_mapped is not None
                else str(ip))
        return Reading(name, True, f"[{host}]{port_text}", tail)
    if len(host) > _MAX_HOST:
        raise UnparseableUrl("host too long")
    name, exact = host, True
    if not host.isascii():
        try:
            name = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            raise UnparseableUrl("host does not encode as IDNA") from None
        exact = False
    name = name.lower()
    if "%" in name or _ODD.search(name):
        exact = False
    if name.endswith("."):
        name = name[:-1]
    if not name:
        raise NoHost("empty host")
    shown = host if len(host) <= _MAX_SHOWN else host[:_MAX_SHOWN] + "..."
    return Reading(name, exact, shown + port_text, tail)


def looks_like_host(reading: Reading) -> bool:
    """True when a reading's host is plainly a dotted name or an address.
    When parsers disagree about a URL, the host one of them reads can be the
    start of its userinfo (`https://TOKEN\\@host/`), so only a host like this
    is safe to print."""
    return any(c in reading.host for c in ".:%")


def parse(url: str) -> Url:
    """Every reading of `url`'s host. Raises UnparseableUrl when the URL is
    broken. A string with no scheme and authority (`localhost:3000`, `abc`)
    has no readings."""
    s = str(url).translate(DROPPED).strip(C0_AND_SPACE)
    m = _SCHEME_RE.match(s)
    if not m:
        return Url("", (), False)
    scheme = m.group(0)[:-1].lower()
    after = s[m.end():]
    found: "list[Reading | None]" = []
    if after.startswith("//"):
        found.append(_reading(after[2:], _END_RFC))
    if scheme in _SPECIAL:
        found.append(_reading(after.lstrip("/\\"), _END_WHATWG))
    if not found:
        return Url(scheme, (), False)
    readings: "list[Reading]" = []
    for r in found:
        if r is not None and not any(
                (r.host, r.exact) == (x.host, x.exact) for x in readings):
            readings.append(r)
    if not readings:
        raise NoHost("no host")
    ambiguous = (len({r.host for r in readings}) > 1
                 or any("%" in r.host for r in readings))
    return Url(scheme, tuple(readings), ambiguous)
