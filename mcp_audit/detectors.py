"""Static detectors: config-level checks needing no network and no execution."""

from __future__ import annotations

import ipaddress
import json
import ntpath
import re
import urllib.request
from importlib import resources
from typing import NamedTuple

from . import redact, urls

#: The advisory feed, shipped as package data next to this module.
FEED_NAME = "advisories.json"

# A finding: {"severity": "critical|high|medium|low",
#             "check": str, "message": str}
SEVERITIES = ("critical", "high", "medium", "low")

# A URL as a WHATWG parser (Node's `new URL`, a browser) reads it: after the
# scheme, any run of slashes and backslashes leads to the host
# (`http:\\evil.example`, `http:/evil.example`). It ends at white space or a
# quote, as it does in a shell script; _values() covers a URL that is a whole
# argument and so may hold both.
URL_RE = re.compile(r"(?:https?|wss?):[/\\]+[^\s'\"<>/\\][^\s'\"<>]*",
                    re.IGNORECASE)
_START_RE = re.compile(r"(?:https?|wss?):[/\\]+", re.IGNORECASE)
# Where the URL starts in a text a program is handed whole: at its start, or
# after the "@" of a package spec (`name @ URL`, `name@URL`), and after the
# version-control prefix of a repository (`git+URL`). pip, uv and npm read the
# URL that is left; the rest is what they call the package or the kind of
# repository. It is the first "@" that a URL follows: `@scope/name@URL` has
# two.
_SPEC_URL_RE = re.compile(
    r"(?:^|@)[\x00-\x20]*(?:(?:git|hg|svn|bzr)\+)?(?=(?:https?|wss?):[/\\])",
    re.IGNORECASE)
_MAX_JSON_ARG = 1_000_000
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
#: Hosts of git forges. A package a runner installs from a repository there is
#: judged by its pin (`git-source`), not as a remote endpoint. `--allow-host`
#: adds a forge of your own.
GIT_FORGES = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
#: The default package registries: a runner pointed at one is not reported.
DEFAULT_REGISTRIES = ("registry.npmjs.org", "registry.yarnpkg.com",
                      "pypi.org", "pypi.python.org", "files.pythonhosted.org")
#: Programs that connect a client to a remote MCP server whose URL they are
#: given; that URL is a remote server, as a `url` entry is.
BRIDGES = frozenset({"mcp-remote", "mcp-proxy", "supergateway"})
_BRIDGE_URL_OPTS = frozenset({"--sse", "--streamablehttp", "--url",
                              "--remote"})
#: Environment variables that point a package manager at a registry.
_REGISTRY_ENV = frozenset({
    "npm_config_registry", "yarn_npm_registry_server", "uv_index_url",
    "uv_default_index", "uv_extra_index_url", "pip_index_url",
    "pip_extra_index_url"})
#: Addresses that are a service on the local network, not a callback to
#: someone else: RFC 1918 and link-local. (Python's is_private also takes the
#: documentation ranges, which are exactly what an example callback uses.)
_LAN = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"))
_LABEL = r"[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?"
_HOST_PATTERN_RE = re.compile(r"%s(?:\.%s)*" % (_LABEL, _LABEL))
#: Shells that run a command string (`sh -c`, `cmd /c`, `powershell -Command`).
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh",
                    "tcsh"})
WIN_SHELLS = frozenset({"cmd", "powershell", "pwsh"})
DOWNLOADERS = frozenset({"curl", "wget", "iwr", "irm", "invoke-webrequest",
                         "invoke-restmethod", "start-bitstransfer",
                         "bitsadmin", "certutil"})
#: Never a server binary either: PowerShell's eval, cmd's `start` (detaches
#: from the stdio a server needs) and binaries malware loaders live off.
LAUNCHERS = frozenset({"iex", "invoke-expression", "start", "mshta",
                       "rundll32", "regsvr32", "wscript", "cscript"})
#: A server entry running any of these is critical. A shell that is given a
#: command string is judged by what that string runs, not by being a shell.
SUSPICIOUS_CMDS = SHELLS | WIN_SHELLS | DOWNLOADERS | LAUNCHERS
#: What a pipe must not lead into.
SHELL_TARGETS = SHELLS | WIN_SHELLS | {"iex", "invoke-expression"}
INTERPRETERS = {"python", "python3", "py", "node", "deno", "bun", "ruby",
                "perl", "php"}
INLINE_FLAGS = {"-c", "-e", "--eval", "-p", "--print"}
PS_ENCODED_RE = re.compile(r"^[-/](e|ec|en\w*)$", re.IGNORECASE)
PS_COMMAND_RE = re.compile(r"^[-/](c|com\w*)$", re.IGNORECASE)


#: How much of an attacker-sized string (a package name, a version) one
#: message echoes, and the most any one message holds.
_SHOWN_MAX = 80
_MESSAGE_MAX = 1500


def _echo(text, limit: int = _SHOWN_MAX) -> str:
    """`text` for a message: cut at `limit` characters, with its full length
    when that cut something off."""
    text = str(text)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... ({len(text)} characters)"


def _finding(severity: str, check: str, message: str) -> dict:
    if len(message) > _MESSAGE_MAX:
        message = message[:_MESSAGE_MAX] + "... (cut)"
    return {"severity": severity, "check": check, "message": message}


def _cmd_name(cfg: dict) -> str:
    """Bare, lower-case name of the config's command (see _prog_name)."""
    return _prog_name(str(cfg.get("command") or ""))


def _is_local(host: str) -> bool:
    """The local machine: `localhost`, or a loopback or unspecified address
    (an IPv4-mapped IPv6 address counts as the IPv4 address in it, on every
    Python version). `host` is lower-case, without brackets or a trailing
    dot, as in urls.Reading.host."""
    host = (host or "").lower()
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_unspecified


def host_pattern(text: str) -> str:
    """A host for --allow-host in the form the allowlist uses: a lower-case
    name, or `.suffix` for any host below a name (`*.corp.example`). Raises
    ValueError, with the reason, for anything else: a URL, a port, a path, a
    pattern with a wildcard anywhere but in front, a name that is not ASCII,
    or `*.com` (a whole top-level domain)."""
    raw = text.strip().lower()
    wildcard = raw.startswith(("*.", "."))
    name = raw[2:] if raw.startswith("*.") else raw[1:] if wildcard else raw
    name = name[:-1] if name.endswith(".") else name
    if not name.isascii():
        raise ValueError("write an international host name in its ASCII "
                         "(punycode, xn--) form")
    if len(name) > 253 or not _HOST_PATTERN_RE.fullmatch(name):
        raise ValueError("expected a host name such as api.example.com or "
                         "*.example.com - not a URL, a port or another "
                         "kind of pattern")
    if wildcard and "." not in name:
        raise ValueError("a wildcard over a whole top-level domain would "
                         "trust every host under it")
    return ("." if wildcard else "") + name


def _listed(host: str, patterns) -> bool:
    """`host` is one of `patterns`: a name, or `.suffix` for any subdomain."""
    return any(host.endswith(h) if h.startswith(".") else host == h
               for h in patterns)


def _is_allowed_api(scheme: str, host: str) -> bool:
    if scheme not in ("https", "wss") or not host:
        return False
    return _listed(host, ALLOWED_API_HOSTS)


def _is_lan(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.version == 4 and any(ip in net for net in _LAN)


def _trusted(scheme: str, host: str, allow) -> bool:
    """`host` is one the user named with --allow-host (https and wss only:
    anything else can be read or changed on the way)."""
    return scheme in ("https", "wss") and _listed(host, allow)


def _quiet(scheme: str, reading: urls.Reading, local_only: bool = False,
           allow=()) -> bool:
    """True when this reading of a URL's host is the local machine, a host
    the user trusts or (unless local_only) a trusted API host. A host the
    text does not pin down (a percent escape, a non-ASCII name) is never
    quiet."""
    if not reading.exact:
        return False
    return (_is_local(reading.host) or _trusted(scheme, reading.host, allow)
            or (not local_only and _is_allowed_api(scheme, reading.host)))


def _shown(parsed: urls.Url, loud: "list[urls.Reading]") -> str:
    """The URL as it is printed: scheme://host[:port], then "/..." if a path,
    query or fragment followed - never the userinfo. When parsers disagree
    about a URL, the host one of them reads may be the start of its userinfo,
    so a host that is not plainly a name or an address is not printed."""
    pick = next((r for r in loud
                 if not parsed.ambiguous or urls.looks_like_host(r)), None)
    if pick is None:
        return f"{parsed.scheme}://<host>/..."
    return f"{parsed.scheme}://{pick.shown}{pick.tail}"


def _judge(url: str, whole: bool = False, allow=()
           ) -> "list[tuple[str, str]]":
    """What is wrong with one URL found in text, as (kind, endpoint) pairs:
    nothing when every host a parser could read it as is local or trusted,
    ("unparseable", "") when it cannot be taken apart, else ("url", printable
    form) for the reading that is not quiet, plus ("ambiguous", "") when the
    parsers disagree about the host. `whole`: the text is a whole argument,
    which may be prose that starts with `https://`: no host is no URL."""
    try:
        parsed = urls.parse(url)
    except urls.NoHost:
        return [] if whole else [("unparseable", "")]
    except urls.UnparseableUrl:
        return [("unparseable", "")]
    if not parsed.readings:
        return [("unparseable", "")]
    loud = [r for r in parsed.readings
            if not _quiet(parsed.scheme, r, allow=allow)]
    if not loud:
        return []
    found = [("url", _shown(parsed, loud))]
    if parsed.ambiguous:
        found.append(("ambiguous", ""))
    return found


def _endpoints(text: str, allow=()) -> list[tuple[str, str]]:
    """Remote, non-allowlisted endpoints (URLs and bare IP:port) in text, as
    (kind, endpoint). kind is "url" (endpoint: its printable form), "hostport"
    (a bare IP:port, which has no userinfo or path to hide anything in),
    "unparseable" for a URL that could not be taken apart, or "ambiguous"
    (right after its "url") for a URL whose host depends on the parser. URLs
    are handled one at a time, so one malformed URL can neither hide another
    one nor take the whole detector down.

    A WHATWG parser deletes tabs and line breaks from anywhere in a URL, so
    a text that has any is read a second time without them
    (`ht<TAB>tps://evil.example`, `http://localhost<TAB>.evil.example`)."""
    out: list[tuple[str, str]] = []
    squashed = text.translate(urls.DROPPED)
    for t in (text,) if squashed == text else (text, squashed):
        before = set(out)
        for m in URL_RE.finditer(t):
            group = _judge(m.group(0).rstrip(".,;)"), allow=allow)
            if group and (t is text or group[0] not in before):
                out.extend(group)
    # The text may itself be a URL, and a program parses that whole: a space
    # or a quote before an "@" is userinfo to it, but ends the word above
    # (`https://localhost y@evil.example`). Only what is new is added.
    seen = set(out)
    for value in _values(text):
        group = _judge(value, whole=True, allow=allow)
        if group and group[0] not in seen:
            out.extend(group)
            seen.add(group[0])
    for m in IP_PORT_RE.finditer(text):
        try:
            ipaddress.ip_address(m.group(1))
        except ValueError:
            continue  # not an IP (e.g. a version string)
        if not (_is_local(m.group(1)) or _is_lan(m.group(1))
                or _listed(m.group(1), allow)):
            out.append(("hostport", m.group(0)))
    return out


def _json_strings(text: str) -> "list[str]":
    """Every string in `text` when it is a JSON object or array (a program
    gets a URL out of `--config '{"url": ...}'`), else nothing."""
    s = text.strip()
    if s[:1] not in ("{", "[") or len(s) > _MAX_JSON_ARG:
        return []
    try:
        doc = json.loads(s)
    except (ValueError, RecursionError):
        return []
    out: list[str] = []
    stack = [doc]
    while stack and len(out) < 1000:
        node = stack.pop()
        if isinstance(node, str):
            out.append(node)
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


def _values(text: str) -> "list[str]":
    """The strings in `text` that a program would parse whole as a URL: the
    text itself (an argument, an env value), what follows its first "="
    (`--url=...`, `KEY=...`) and, when it is JSON, every string in it - and in
    each of those, what a package spec leaves of it as the URL: what follows
    `name @` or `name@` and a version-control prefix (`git+`). Only those
    that start like a URL."""
    out: list[str] = []
    for cand in (text, text.partition("=")[2], *_json_strings(text)):
        cand = cand.translate(urls.DROPPED).strip(urls.C0_AND_SPACE)
        found = _SPEC_URL_RE.search(cand)
        if found:
            cand = cand[found.end():]
            if cand not in out:
                out.append(cand)
    return out


def _unparseable_url(where: str) -> dict:
    # Deliberately does not echo the URL: it cannot be told apart from a
    # secret, and nothing about it could be established anyway.
    return _finding(
        "high", "unparseable-url",
        f"unparseable URL in {where}: it could not be taken apart, so where "
        "it points is unknown - treated as unsafe")


def _ambiguous_url(where: str) -> dict:
    # Like _unparseable_url, it does not echo the URL.
    return _finding(
        "high", "unparseable-url",
        f"ambiguous URL in {where}: URL parsers disagree about its host (a "
        "backslash or a percent escape before the path, for example), so "
        "where it points is unknown - treated as unsafe")


def _units(cfg: dict) -> list[tuple[str, str]]:
    """(where, text) pairs worth scanning, one by one: each argument, each env
    value and the command. An argument is what a program gets a URL from, so
    the arguments are not joined into one text."""
    units = [("args", str(a)) for a in cfg.get("args") or []]
    units += [(f"env:{k}", str(v)) for k, v in (cfg.get("env") or {}).items()]
    if cfg.get("command"):
        units.append(("command", str(cfg.get("command"))))
    return units


#: The keys a server entry names a remote server's URL by: `url` (Claude
#: Code, Cursor, VS Code, Zed ...) and `serverUrl`, which a reviewer reports
#: Windsurf and Devin write (not checked against their pages: reading a key
#: a client does not use only widens what is audited).
REMOTE_URL_KEYS = ("url", "serverUrl")


def remote_urls(cfg: dict) -> "list[tuple[str, str]]":
    """(key, URL) for each key of a server entry that names a remote server."""
    return [(key, str(cfg[key])) for key in REMOTE_URL_KEYS if cfg.get(key)]


def detect_exfiltration(name: str, cfg: dict, allow_hosts=()) -> list[dict]:
    """Remote URLs baked into a server's launch config. `allow_hosts`: hosts
    the user trusts (--allow-host, as host_pattern() writes them).

    A URL that is plainly where a package comes from (a repository on a git
    forge), which registry it comes through, or the remote server a bridge
    connects to is judged as that (see "Where a launch gets its code from");
    every other URL is a remote endpoint. A remote server (a `url` or
    `serverUrl` entry) is one more finding - and the launch arguments and
    environment of an entry that has both are read all the same: a URL
    field must not switch the reading of a command off."""
    findings: list[dict] = []
    # Remote (non-stdio) servers are inherently networked — note it.
    for key, url in remote_urls(cfg):
        findings.extend(f for f in _remote_server(url, allow_hosts, key=key)
                        if f not in findings)
    judged: "dict[str, list[dict]]" = {}
    for role in _roles(cfg):
        if role.value not in judged and len(judged) >= _MAX_ROLES:
            continue  # beyond the limit, a value is an endpoint like any other
        found = _role_findings(role, allow_hosts)
        if found is not None:
            judged.setdefault(role.value, []).extend(found)
    for where, text in _units(cfg):
        findings.extend(_unit_findings(where, text, judged, allow_hosts,
                                       findings))
    # A script is read as it is written above, and a quote ends a URL there.
    # The shell takes the quotes out (`ht''tps://''host` is `https://host`),
    # so the words it hands over are read as well - and what was found
    # already is not found twice.
    words, complete = _script_urls(cfg)
    known = {(f["severity"], f["check"], f["message"]) for f in findings}
    for text in words:
        for f in _unit_findings("args", text, judged, allow_hosts, findings):
            key = (f["severity"], f["check"], f["message"])
            if key not in known:
                known.add(key)
                findings.append(f)
    if not complete:
        findings.append(_finding(
            "high", "detector-error",
            f"could not analyze URLs and endpoints (a launch script holds "
            f"more than {_MAX_SCRIPT_URLS} different URLs); treat this "
            "server as unaudited"))
    return findings


#: The most different URL-like words of a script that are read once the shell
#: has handed them over. A real script has a handful; a hostile one can have
#: as many as it has characters, and past this many the entry is reported as
#: unaudited rather than read on (or passed as clean).
_MAX_SCRIPT_URLS = 2000


def _script_urls(cfg: dict) -> "tuple[list[str], bool]":
    """The words of the commands a shell script runs that look like a URL
    once the shell has handed them over - each once - and whether that is all
    of them. (The arguments of the entry itself are not run through a shell:
    the program is handed them as they are.)"""
    try:
        words = _scan_launch(cfg).words
    except _TooComplex:
        return [], True   # detect_suspicious_command reports that
    out: "dict[str, None]" = {}
    for word in words:
        if word in out or not _START_RE.search(word):
            continue
        if len(out) >= _MAX_SCRIPT_URLS:
            return list(out), False
        out[word] = None
    return list(out), True


def _unit_findings(where: str, text: str, judged: "dict[str, list[dict]]",
                   allow_hosts, findings: "list[dict]") -> "list[dict]":
    """The findings of one piece of text of the entry (`where` it is): those
    of the values that get a verdict of their own and stand in it, and one
    for each remote endpoint left. `findings`: what there is already."""
    new: "list[dict]" = []
    for value, found in judged.items():
        text, hit = _mask(text, value)
        if hit:
            new.extend(f for f in found if f not in findings and f not in new)
    for kind, shown in _endpoints(text, allow_hosts):
        if kind == "unparseable":
            new.append(_unparseable_url(where))
            continue
        if kind == "ambiguous":
            new.append(_ambiguous_url(where))
            continue
        # A remote endpoint baked into launch args is critical. In env it
        # is usually service config (API base URLs), so medium: worth a
        # look, not a verdict. Well-known API hosts are not reported.
        sev = "medium" if where.startswith("env:") else "critical"
        new.append(_finding(
            sev, "exfiltration-endpoint",
            f"remote endpoint in {where}: {shown}"))
    return new


def _remote_server(url: str, allow=(), via: str = "",
                   key: str = "url") -> list[dict]:
    """Findings for a `url` entry: a remote server by design (medium), unless
    every host a parser could read it as is the local machine or one the user
    trusts. (`via`: the bridge it is reached through; `key`: the field of the
    entry that holds it.)"""
    try:
        parsed = urls.parse(url)
    except urls.UnparseableUrl:
        return [_unparseable_url(key)]
    loud = [r for r in parsed.readings
            if not _quiet(parsed.scheme, r, local_only=True, allow=allow)]
    if parsed.readings and not loud:
        return []
    shown = (_shown(parsed, loud) if loud else redact.safe_url(url))
    findings = [_finding(
        "medium", "remote-server",
        f"remote MCP server URL (traffic leaves the machine): {shown}"
        + (f" (reached through {via})" if via else ""))]
    if parsed.ambiguous:
        findings.append(_ambiguous_url(key))
    return findings


# -- Reading shell commands ---------------------------------------------------
#
# A server entry is judged by what it RUNS. `cmd /c npx ...` and
# `bash -lc "npx ..."` are how npx is started on Windows and from login
# shells, so the wrapper itself says nothing; the script inside it does.
# Scripts are read with a small tokenizer (quotes, $( ) and backticks, the
# operators | & ; and newlines), not a full shell: aliases, functions,
# here-documents, sourced files and command names that come out of a variable
# cannot be followed (see "Limitations" in the README).

_MAX_SCRIPT = 1_000_000   # characters
#: Characters of shell script read in one run, all servers together. A
#: million-character script of quotes takes seconds; a config of many of them
#: must not take minutes. Past it an entry is a visible `detector-error`.
MAX_SCRIPT_WORK = 4_000_000
_script_work = [MAX_SCRIPT_WORK]


def reset_work_budget() -> None:
    """Start counting the script text of a new run (see MAX_SCRIPT_WORK)."""
    _script_work[0] = MAX_SCRIPT_WORK
_MAX_DEPTH = 8            # nested $( ) / backticks / shells inside shells

_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_DURATION_RE = re.compile(r"\d+(?:\.\d+)?[smhd]?$")
# `curl ... | sh`, `... |& sudo -E bash`: a pipe that is not `||`.
_PIPE_RE = re.compile(r"(?<!\|)\|(?!\|)&?")

#: Commands that only run another command, and the options of each that take
#: a value (so that `sudo -u root sh` is read as running `sh`).
_PREFIX_OPTS = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-T",
                       "-U", "--user", "--group", "--host", "--prompt",
                       "--close-from", "--chdir", "--role", "--type",
                       "--other-user"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C", "-S", "--unset", "--chdir",
                      "--split-string"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p", "-P", "-u"}),
    "timeout": frozenset({"-s", "-k", "--signal", "--kill-after"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "exec": frozenset({"-a"}),
    "nohup": frozenset(), "command": frozenset(), "builtin": frozenset(),
    "time": frozenset(), "setsid": frozenset(), "call": frozenset(),
}
#: Shell syntax that sits in front of a command.
_SYNTAX_WORDS = frozenset({"!", "{", "}", "if", "then", "else", "elif", "do",
                           "while", "until"})

_ESCAPES = {"posix": "\\", "cmd": "^", "ps": "`"}


class _TooComplex(ValueError):
    """A launch command too long or too deeply nested to be read. Raised
    (not guessed at): audit_server turns it into a visible HIGH finding."""


class _Stage:
    """One simple command of a script: its words as (text, dynamic) - dynamic
    when an expansion ($VAR, $(...), backticks) is part of the word - and
    whether its standard input is a pipe."""

    __slots__ = ("words", "piped")

    def __init__(self, piped: bool = False):
        self.words: "list[tuple[str, bool]]" = []
        self.piped = piped


def _lex(script: str, dialect: str) -> "list[_Stage]":
    """The simple commands of `script`; dialect is "posix", "cmd" or "ps".
    Never raises on odd input (an unbalanced quote just runs to the end);
    only on input too large or too deeply nested to read."""
    if len(script) > _MAX_SCRIPT:
        raise _TooComplex("script too long to read")
    _script_work[0] -= len(script)
    if _script_work[0] < 0:
        raise _TooComplex("too much script text in this run to read")
    out: "list[_Stage]" = []
    _lex_into(script, 0, dialect, 0, out, False)
    return out


def _lex_into(s: str, i: int, dialect: str, depth: int,
              out: "list[_Stage]", in_subst: bool) -> int:
    """Read commands from s[i:] into `out`; with in_subst, up to and
    including the `)` that closes a `$(`. Returns the index after what was
    read."""
    if depth > _MAX_DEPTH:
        raise _TooComplex("command substitutions nested too deeply")
    n = len(s)
    esc = _ESCAPES[dialect]
    single_quotes = dialect != "cmd"
    substitutions = dialect != "cmd"        # $( ... )
    backticks = dialect == "posix"          # `...`
    stage = _Stage()
    word: "list[str]" = []
    started = False      # a word is being read (possibly an empty "")
    dynamic = False
    parens = 0

    def end_word() -> None:
        nonlocal word, started, dynamic
        if started:
            stage.words.append(("".join(word), dynamic))
        word, started, dynamic = [], False, False

    def end_stage(piped: bool = False) -> None:
        nonlocal stage
        end_word()
        if stage.words:
            out.append(stage)
        stage = _Stage(piped)

    while i < n:
        c = s[i]
        if c in " \t\r\f\v":
            end_word()
            i += 1
        elif c == "\n":
            end_word()
            if stage.words:  # a pipe at the end of a line goes on below
                end_stage()
            i += 1
        elif c == esc:
            nxt = s[i + 1] if i + 1 < n else ""
            if nxt == "\n" and dialect == "posix":  # line continuation
                i += 2
            else:
                word.append(nxt or c)
                started = True
                i += 2 if nxt else 1
        elif c == "'" and single_quotes:
            j = s.find("'", i + 1)
            if j < 0:
                j = n
            word.append(s[i + 1:j])
            started = True
            i = j + 1
        elif c == '"':
            started = True
            i += 1
            while i < n and s[i] != '"':
                d = s[i]
                if d == esc and dialect != "cmd" and i + 1 < n:
                    word.append(s[i + 1])
                    i += 2
                elif d == "$" and substitutions:
                    dynamic = True
                    if s.startswith("$(", i):
                        i = _lex_into(s, i + 2, dialect, depth + 1, out, True)
                    else:
                        word.append(d)
                        i += 1
                elif d == "`" and backticks:
                    dynamic = True
                    i = _lex_backticks(s, i, dialect, depth, out)
                else:
                    word.append(d)
                    i += 1
            i += 1
        elif c == "$" and substitutions:
            dynamic = started = True
            if s.startswith("$(", i):
                i = _lex_into(s, i + 2, dialect, depth + 1, out, True)
            else:
                word.append(c)
                i += 1
        elif c == "`" and backticks:
            dynamic = started = True
            i = _lex_backticks(s, i, dialect, depth, out)
        elif c == "|":
            if s.startswith("||", i):
                end_stage()
                i += 2
            else:
                end_stage(piped=True)
                i += 2 if s.startswith("|&", i) else 1
        elif c == "&":
            end_stage()
            i += 2 if s.startswith("&&", i) else 1
        elif c == ";" and dialect != "cmd":
            end_stage()
            i += 1
        elif c == "(":
            end_stage()
            parens += 1
            i += 1
        elif c == ")":
            end_stage()
            if parens:
                parens -= 1
            elif in_subst:
                return i + 1
            i += 1
        elif c == "#" and dialect != "cmd" and not started:
            j = s.find("\n", i)
            i = n if j < 0 else j
        else:
            word.append(c)
            started = True
            i += 1
    end_stage()
    return n


def _lex_backticks(s: str, i: int, dialect: str, depth: int,
                   out: "list[_Stage]") -> int:
    """`s[i]` is a backtick: read the commands inside it into `out` and
    return the index after the closing backtick."""
    n = len(s)
    j = i + 1
    while j < n and s[j] != "`":
        j += 2 if s[j] == "\\" else 1
    _lex_into(s[i + 1:min(j, n)], 0, dialect, depth + 1, out, False)
    return j + 1


def _prog_name(word: str) -> str:
    """Bare, lower-case program name for POSIX or Windows paths:
    C:\\...\\PowerShell.exe -> "powershell", npx.cmd -> "npx"."""
    name = ntpath.basename(str(word)).lower()
    for ext in (".exe", ".cmd", ".bat"):
        if name.endswith(ext):
            return name[:-len(ext)]
    return name


def _program_index(words: "list[str]") -> "int | None":
    """Index of the program a command line runs: past `NAME=value` and
    wrappers such as `sudo -u root`, `env -i A=1`, `exec`, `nohup`."""
    i, n = 0, len(words)
    while i < n:
        w = words[i]
        if _ASSIGN_RE.match(w):
            i += 1
            continue
        name = _prog_name(w)
        if name in _SYNTAX_WORDS:
            i += 1
            continue
        takes_value = _PREFIX_OPTS.get(name)
        if takes_value is None:
            return i
        i += 1
        while i < n and len(words[i]) > 1 and words[i].startswith("-"):
            if words[i] == "--":
                i += 1
                break
            i += 2 if words[i] in takes_value else 1
        if name == "timeout" and i < n and _DURATION_RE.match(words[i]):
            i += 1
    return None


def _wrapper_kind(name: str) -> "str | None":
    """The script dialect a program runs, if it is a shell."""
    if name in SHELLS:
        return "posix"
    if name == "cmd":
        return "cmd"
    if name in ("powershell", "pwsh"):
        return "ps"
    return None


def _wrapper_script(kind: str, args: "list[str]") -> "str | None":
    """The command string handed to a shell, or None when it is given none
    (it runs a file, reads stdin, or the command is encoded and cannot be
    read)."""
    if kind == "posix":  # sh -c SCRIPT, bash -lc SCRIPT, bash -o x -c SCRIPT
        i, n, want_script = 0, len(args), False
        while i < n:
            a = args[i]
            if a == "--":
                i += 1
                break
            if a in ("-o", "+o", "-O", "+O"):
                i += 2
            elif a.startswith("--"):
                i += 2 if a in ("--rcfile", "--init-file") else 1
            elif len(a) > 1 and a[0] in "-+":
                want_script = want_script or (a[0] == "-" and "c" in a[1:])
                i += 1
            else:
                break
        return args[i] if want_script and i < n else None
    if kind == "cmd":  # cmd /d /s /c rest...
        for i, a in enumerate(args):
            low = a.lower()
            if low in ("/c", "/k", "/r"):
                rest = args[i + 1:]
                return " ".join(rest) if rest else None
            if low[:3] in ("/c ", "/k ", "/r "):
                return " ".join([a[3:]] + args[i + 1:])
        return None
    for i, a in enumerate(args):  # powershell -Command rest...
        if PS_ENCODED_RE.match(a):
            return None
        if PS_COMMAND_RE.match(a):
            rest = args[i + 1:]
            return " ".join(rest) if rest else None
    return None


def _raw_pipe_to_shell(text: str) -> bool:
    """For a command that is not a shell wrapper (its args are not shell
    syntax, but `curl x | sh` split over them says what its author meant):
    does a pipe lead into a shell? Quotes are ignored on purpose."""
    for seg in _PIPE_RE.split(text)[1:]:
        seg = re.split(r"[;&\n]", seg, maxsplit=1)[0]
        words = [w for w in (w.strip("'\"`()") for w in seg.split()) if w]
        idx = _program_index(words)
        if idx is not None and _prog_name(words[idx]) in SHELL_TARGETS:
            return True
    return False


class _Launch:
    """What a server entry would run, seen through the shells around it."""

    def __init__(self) -> None:
        #: (program, wrappers it sits in) for every command that would run
        self.programs: "list[tuple[str, tuple[str, ...]]]" = []
        #: (program, args) pairs for the inline-code check
        self.inline: "list[tuple[str, list[str]]]" = []
        #: (program, args) of every plain command, i.e. not a shell wrapper
        self.launches: "list[tuple[str, list[str]]]" = []
        #: the words of every plain command inside a script, as the shell
        #: hands them over (quotes taken out)
        self.words: "list[str]" = []
        #: the program word of every plain command (`/tmp/evil` in
        #: `sh -c /tmp/evil`), as the shell hands it over
        self.progwords: "list[str]" = []
        self.pipe = False   # something is piped into a shell
        self.eval = False   # `eval` of generated text
        #: names of the wrappers in front of a program (`sudo -u root node`)
        self.prefixes: "set[str]" = set()


_scan_memo: "list" = [None, None]


def _scan_launch(cfg: dict) -> _Launch:
    """What the entry would run. The detectors that read it run one after the
    other on the same entry, so the last answer is kept: a long script is
    read once, not once per detector."""
    command = str(cfg.get("command") or "")
    words = ([command] if command else []) + [
        str(a) for a in (cfg.get("args") or [])]
    key = tuple(words)
    if _scan_memo[0] == key:
        return _scan_memo[1]
    out = _Launch()
    _scan_words(out, words, (), 0)
    _scan_memo[0], _scan_memo[1] = key, out
    return out


def _scan_words(out: _Launch, words: "list[str]", via: "tuple[str, ...]",
                depth: int) -> None:
    """One command line: a config's command + args, or one command of a
    script that ran inside the shells named in `via`."""
    idx = _program_index(words)
    if idx is None:
        return
    name = _prog_name(words[idx])
    rest = words[idx + 1:]
    out.prefixes.update(_prog_name(w) for w in words[:idx])
    out.inline.append((name, rest))
    kind = _wrapper_kind(name)
    script = _wrapper_script(kind, rest) if kind else None
    if script is not None:
        if via:  # a shell started by a shell is not a server launch
            out.programs.append((name, via))
        _scan_script(out, script, kind, via + (name,), depth + 1)
        return
    # Not a wrapper, or a shell that runs a file / an unreadable command:
    # it is judged as the program it is.
    out.programs.append((name, via))
    out.launches.append((name, rest))
    out.progwords.append(words[idx])
    if via:
        out.words.extend(words)
    if not via and _raw_pipe_to_shell(" ".join(words)):
        out.pipe = True


def _scan_script(out: _Launch, script: str, kind: str,
                 via: "tuple[str, ...]", depth: int) -> None:
    if depth > _MAX_DEPTH:
        raise _TooComplex("shells nested too deeply")
    for stage in _lex(script, kind):
        words = [w for w, _ in stage.words]
        idx = _program_index(words)
        if idx is None:
            continue
        name = _prog_name(words[idx])
        if stage.piped and name in SHELL_TARGETS:
            out.pipe = True
        elif (kind == "posix" and name == "eval"
              and any(dyn for _, dyn in stage.words[idx + 1:])):
            out.eval = True
        else:
            _scan_words(out, words, via, depth)


def _names(items) -> str:
    seen: "list[str]" = []
    for item in items:
        if item not in seen:
            seen.append(item)
    shown = ", ".join(f"'{x}'" for x in seen[:5])
    return shown + (f" (+{len(seen) - 5} more)" if len(seen) > 5 else "")


def detect_suspicious_command(name: str, cfg: dict) -> list[dict]:
    scan = _scan_launch(cfg)
    findings = []
    bad = [(prog, via) for prog, via in scan.programs
           if prog in SUSPICIOUS_CMDS]
    if bad:
        said = []
        if any(not via for _, via in bad):
            said.append("launches via " + _names(
                p for p, via in bad if not via))
        if any(via for _, via in bad):
            said.append("runs " + _names(p for p, via in bad if via)
                        + " inside " + _names(via[0] for _, via in bad
                                              if via))
        findings.append(_finding(
            "critical", "suspicious-command",
            f"server {' and '.join(said)} \u2014 a downloader/shell, not a "
            "server binary"))
    # Piping a remote download into a shell (curl ... | sh, wget ... | bash)
    # is CRITICAL, in the args and inside sh -c "..." alike. So is `eval` of
    # generated text (eval "$(curl ...)"), which is the same thing.
    if scan.pipe or scan.eval:
        what = []
        if scan.pipe:
            what.append("command pipes content into a shell (classic "
                        "curl|sh pattern)")
        if scan.eval:
            what.append("command evals generated text (eval \"$(...)\")")
        findings.append(_finding("critical", "pipe-to-shell",
                                 "; ".join(what)))
    seen = set()
    for prog, args in scan.inline:
        for f in _inline_code(prog, args):
            if f["message"] not in seen:
                seen.add(f["message"])
                findings.append(f)
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


# -- Packages a server fetches ------------------------------------------------

class Package(NamedTuple):
    """A package an npx/uvx-style launcher downloads and runs."""

    name: str
    version: "str | None"  # as written ("1.2.3", "latest", "^1.2.0"), if any
    exact: bool            # one release (or a digest): the same on every launch
    ecosystem: str         # "npm" or "PyPI"
    spec: str = ""         # the argument it was read from: "pkg@1.2.3"
    #: False when an option mcp-audit does not know comes before it: the word
    #: read as the package could be that option's value (a credential, say),
    #: so it is never printed or sent anywhere (see _only_known).
    sure: bool = True

    def release(self) -> "str | None":
        """The exact release number, or None when only a range, a tag or a
        digest is known."""
        if not self.exact or not self.version or _DIGEST_RE.fullmatch(
                self.version):
            return None
        return self.version.lstrip("=v")


_DIGEST_RE = re.compile(r"(?:sha(?:1|224|256|384|512)|md5):[0-9A-Fa-f]{16,}")
# A spec that is not a registry name: URL, git shorthand, file:, a path, a
# drive letter. Not judged for pinning.
_NON_REGISTRY_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]*:|\.{1,2}[/\\]|[/\\~]")
_NPM_SPEC_RE = re.compile(r"(@[^/@\s]+/[^@\s]+|[^@\s/]+)(?:@(.*))?", re.DOTALL)
# node-semver: an exact version, optionally "=" or "v" in front
_NPM_EXACT_RE = re.compile(
    r"=?v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?")
_PY_SPEC_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?(.*)",
                         re.DOTALL)
_PY_RELEASE_RE = re.compile(r"[0-9][0-9A-Za-z.+!_\-]*")


def _npm_package(spec: str) -> "Package | None":
    if _NON_REGISTRY_RE.match(spec):
        return None
    m = _NPM_SPEC_RE.fullmatch(spec)
    if not m:
        return None
    version = m.group(2) or None
    exact = version is not None and bool(
        _NPM_EXACT_RE.fullmatch(version) or _DIGEST_RE.fullmatch(version))
    return Package(m.group(1), version, exact, "npm", spec)


def _py_package(spec: str) -> "Package | None":
    spec = spec.strip()
    if (_NON_REGISTRY_RE.match(spec) or " @ " in spec
            or spec.startswith("-")):
        return None
    m = _PY_SPEC_RE.fullmatch(spec)
    if not m:
        return None
    name = m.group(1)
    rest = m.group(2).split(";", 1)[0].strip()  # drop an environment marker
    if not rest:
        return Package(name, None, False, "PyPI", spec)
    if rest.startswith("@"):  # uvx pkg@1.2.3, uvx pkg@latest
        version = rest[1:].strip() or None
        exact = version is not None and (
            _PY_RELEASE_RE.fullmatch(version) is not None
            or _DIGEST_RE.fullmatch(version) is not None)
        return Package(name, version, exact, "PyPI", spec)
    for clause in rest.split(","):  # PEP 440: any exact clause pins it
        c = re.fullmatch(r"\s*===?\s*(\S+)\s*", clause)
        if c and _PY_RELEASE_RE.fullmatch(c.group(1)):
            return Package(name, c.group(1), True, "PyPI", spec)
    return Package(name, rest, False, "PyPI", spec)


#: Options of the npm-style runners that take a value, so that the value is
#: not mistaken for the package (`npx --registry URL -y pkg`).
_NPM_VALUE_OPTS = frozenset({
    "-p", "--package", "--registry", "--cache", "--userconfig",
    "--globalconfig", "--loglevel", "-w", "--workspace", "--prefix",
    "--scope", "--tag", "--node-options", "--before", "--otp",
    "--fetch-retries", "--fetch-timeout", "--fetch-retry-mintimeout",
    "--fetch-retry-maxtimeout", "--script-shell", "--cwd", "--dir", "-C",
    "--filter"})
_PY_VALUE_OPTS = frozenset({
    "--from", "--with", "--with-editable", "--with-requirements", "--python",
    "-p", "--index", "--default-index", "-i", "--index-url",
    "--extra-index-url", "-f", "--find-links", "--constraints", "-c",
    "--overrides", "--build-constraints", "--env-file", "--directory",
    "--project", "--config-file", "--cache-dir", "--exclude-newer",
    "--index-strategy", "--keyring-provider", "--resolution", "--prerelease",
    "--reinstall-package", "--upgrade-package", "-P", "--no-binary-package",
    "--no-build-package", "--refresh-package", "--link-mode", "--color",
    "--allow-insecure-host", "--python-platform", "--torch-backend",
    "--spec", "--pip-args", "--python-preference"})
#: Options that take no value, so that the word after one is the package. An
#: option in neither this table nor the one above (and not a --no-/--skip-
#: switch: redact.is_negation) may take a value, and then the word after it
#: is that value and not the package.
_NPM_FLAG_OPTS = frozenset({
    "-y", "--yes", "-n", "--no", "-q", "--quiet", "-s", "--silent", "-d",
    "--dd", "--ddd", "--verbose", "--prefer-offline", "--prefer-online",
    "--offline", "--ignore-existing", "--ignore-scripts", "--legacy-peer-deps",
    "-f", "--force", "--include-workspace-root", "-ws", "--workspaces", "-c",
    "--call", "--shell-mode", "--bun", "-b", "--production", "-h", "--help"})
_PY_FLAG_OPTS = frozenset({
    "-q", "-qq", "--quiet", "-v", "-vv", "-vvv", "--verbose", "--isolated",
    "--refresh", "--offline", "--native-tls", "--managed-python",
    "--reinstall", "-U", "--upgrade", "--active", "--compile-bytecode",
    "--system-site-packages", "--pypackages", "--path", "--frozen",
    "--locked", "--exact", "--preview", "-h", "--help"})
_NPM_RUNNERS = frozenset({"npx", "bunx", "pnpx"})
#: (tool, subcommand) pairs that fetch and run a package like npx does.
_NPM_VIA = frozenset({("pnpm", "dlx"), ("yarn", "dlx"), ("npm", "exec"),
                      ("npm", "x"), ("bun", "x")})


def _split_runner_args(args: "list[str]", value_opts) -> tuple:
    """(options, first positional) of a runner's arguments. Options are
    (name, value|None); everything after the positional belongs to the
    program being run. An option named for a credential (`--auth`, `--token`,
    `--password`) takes the next argument as its value even when the runner
    is not known to give it one: that argument is a secret, not the
    package."""
    opts: "list[tuple[str, str | None]]" = []
    i, n = 0, len(args)
    while i < n:
        a = args[i]
        if a == "--":
            i += 1
            break
        if len(a) < 2 or not a.startswith("-"):
            break
        if a.startswith("--") and "=" in a:
            k, v = a.split("=", 1)
            opts.append((k, v))
            i += 1
        elif (a in value_opts or redact.takes_a_credential(a)) and i + 1 < n:
            opts.append((a, args[i + 1]))
            i += 2
        else:
            opts.append((a, None))
            i += 1
    return opts, (args[i] if i < n else None)


def _only_known(opts: "list[tuple[str, str | None]]", flag_opts) -> bool:
    """True when the word after `opts` can be taken for the package: each
    option came with its value (`--opt=value`, or an option of the tables that
    takes one) or is a switch (in `flag_opts`, or a --no-/--skip- option). An
    option that is none of these might take the next word as its value, and
    then that word is a value - a credential, say - and not the package."""
    return all(value is not None or opt in flag_opts
               or redact.is_negation(opt) for opt, value in opts)


def _npm_packages(args: "list[str]", call_is_command: bool
                  ) -> "list[Package]":
    """call_is_command: `-c` hands the runner a command string (npx, npm
    exec) and so runs no package; for pnpm and bun it is only a flag."""
    opts, positional = _split_runner_args(args, _NPM_VALUE_OPTS)
    specs = [(v, True) for o, v in opts if o in ("-p", "--package") and v]
    called = call_is_command and any(o in ("-c", "--call") for o, _ in opts)
    if not specs and positional and not called:
        specs = [(positional, _only_known(opts, _NPM_FLAG_OPTS))]
    return [p._replace(sure=sure) for p, sure in
            ((_npm_package(spec), sure) for spec, sure in specs) if p]


def _py_packages(args: "list[str]", spec_opt: str = "--from"
                 ) -> "list[Package]":
    opts, positional = _split_runner_args(args, _PY_VALUE_OPTS)
    froms = [v for o, v in opts if o == spec_opt and v]
    main = (froms[0], True) if froms else (
        positional, _only_known(opts, _PY_FLAG_OPTS))
    specs = ([main] if main[0] else []) + [(v, True) for o, v in opts
                                           if o == "--with" and v]
    return [p._replace(sure=sure) for p, sure in
            ((_py_package(spec), sure) for spec, sure in specs) if p]


class _Runner(NamedTuple):
    """How a package runner reads its command line."""

    ecosystem: str          # "npm" or "py"
    args: "list[str]"       # what follows the runner (and `dlx`, `run` ...)
    call_is_command: bool   # `-c` hands it a command string, so no package
    spec_opt: str           # the option that names the package, if not first


def _runner(name: str, args: "list[str]") -> "_Runner | None":
    """`name args...` read as a package runner (npx, pnpm dlx, uvx, pipx run
    ...), or None when it is not one."""
    if name in _NPM_RUNNERS:
        return _Runner("npm", args, name == "npx", "")
    if name in ("pnpm", "yarn", "npm", "bun"):
        rest = [a for a in args if not a.startswith("-")][:1]
        if rest and (name, rest[0]) in _NPM_VIA:
            i = args.index(rest[0])
            return _Runner("npm", args[i + 1:], name == "npm", "")
        return None
    if name == "uvx":
        return _Runner("py", args, False, "--from")
    if name == "uv" and args[:2] == ["tool", "run"]:
        return _Runner("py", args[2:], False, "--from")
    if name == "pipx" and args[:1] == ["run"]:
        return _Runner("py", args[1:], False, "--spec")
    return None


def _packages_of(name: str, args: "list[str]") -> "list[Package]":
    """What `name args...` downloads, if it is a package runner."""
    runner = _runner(name, args)
    if runner is None:
        return []
    if runner.ecosystem == "npm":
        return _npm_packages(runner.args, runner.call_is_command)
    return _py_packages(runner.args, runner.spec_opt)


def _launched(cfg: dict) -> "list[tuple[str, list[str]]]":
    """(program, args) of every command a server entry would run, shells and
    wrappers looked through. A script too complex to read yields nothing
    here: detect_suspicious_command reports that."""
    try:
        return _scan_launch(cfg).launches
    except _TooComplex:
        return []


def _iter_packages(cfg: dict) -> "list[Package]":
    """The packages an entry downloads (npx, bunx, pnpm dlx, uvx ...)."""
    out: "list[Package]" = []
    for name, args in _launched(cfg):
        out.extend(_packages_of(name, args))
    return out


# -- Where a launch gets its code from ----------------------------------------
#
# A URL in a server's arguments is a remote endpoint, and critical. Three
# shapes of it are ordinary, and are judged as what they are:
#
#   a package source    uvx --from git+https://github.com/o/r pkg, npx github:o/r
#   a registry          npx --registry=https://r.example/, uvx --index-url URL
#   a bridge's server   npx mcp-remote https://vendor.example/sse
#
# A value gets a verdict of its own only when it qualifies in every way a
# parser could read it: one host, spelled out, the same to every parser, and
# for a source a git forge. A look-alike host, a backslash or an escape in it
# sends the value back to the scan for endpoints, which is critical.

class _Role(NamedTuple):
    kind: str             # "source", "registry" or "bridge"
    value: str            # exactly as written: an argument or an option's value
    via: str              # the option, variable or program it came from
    ecosystem: str = ""   # "npm" or "py", for a source


_SOURCE_OPTS = {"npm": frozenset({"-p", "--package"}),
                "py": frozenset({"--from", "--spec", "--with",
                                 "--with-editable"})}
_REGISTRY_OPTS = {
    "npm": frozenset({"--registry"}),
    "py": frozenset({"--index-url", "-i", "--index", "--default-index",
                     "--extra-index-url", "--extra-index", "-f",
                     "--find-links"})}
_SCOPED_REGISTRY_RE = re.compile(r"--@[^=\s]{1,100}:registry")
_GIT_URL_RE = re.compile(r"git\+(https?://.*)", re.IGNORECASE | re.DOTALL)
_GIT_SHORT_RE = re.compile(r"(github|gitlab|bitbucket):([\w.\-]+/[\w.\-]+)"
                           r"(?:#(.*))?", re.IGNORECASE | re.DOTALL)
_SHORT_HOSTS = {"github": "github.com", "gitlab": "gitlab.com",
                "bitbucket": "bitbucket.org"}
_COMMIT_RE = re.compile(r"[0-9a-fA-F]{7,64}")
_TAG_RE = re.compile(r"(?:refs/tags/)?v?\d+(?:\.\d+){1,3}"
                     r"(?:[-+.][0-9A-Za-z.\-]+)?")
_EDGE_BEFORE = frozenset(" \t\r\n'\"=")
_EDGE_AFTER = frozenset(" \t\r\n'\"")
#: Distinct values of one entry that get a verdict of their own. A real entry
#: has a handful; the rest of a crowd is judged as endpoints (critical).
_MAX_ROLES = 64


def _bridge_roles(bridge: str, args: "list[str]") -> "list[_Role]":
    """The URL of the server a bridge connects to: the value of the option
    that takes it (`--sse URL`, `--sse=URL`) or, failing that, the first
    argument that is a URL. A bridge has one server: any other URL it is given
    (a callback, say) is an endpoint like any other, and critical."""
    for i, arg in enumerate(args):
        opt, eq, value = arg.partition("=")
        if opt.lower() not in _BRIDGE_URL_OPTS:
            continue
        if not eq:
            value = args[i + 1] if i + 1 < len(args) else ""
        if _START_RE.match(value):
            return [_Role("bridge", value, bridge)]
    for arg in args:
        if _START_RE.match(arg):
            return [_Role("bridge", arg, bridge)]
    return []


def _roles(cfg: dict) -> "list[_Role]":
    """The values of an entry that say where its code comes from."""
    out: "list[_Role]" = []
    for name, args in _launched(cfg):
        if name in BRIDGES:
            out.extend(_bridge_roles(name, args))
            continue
        runner = _runner(name, args)
        if runner is None:
            continue
        eco = runner.ecosystem
        opts, positional = _split_runner_args(
            runner.args, _NPM_VALUE_OPTS if eco == "npm" else _PY_VALUE_OPTS)
        for opt, value in opts:
            if not value:
                continue
            if opt in _REGISTRY_OPTS[eco] or (
                    eco == "npm" and _SCOPED_REGISTRY_RE.fullmatch(opt)):
                out.append(_Role("registry", value, opt))
            elif opt in _SOURCE_OPTS[eco]:
                out.append(_Role("source", value, opt, eco))
        if positional:
            out.append(_Role("source", positional, name, eco))
            package = (_npm_package if eco == "npm"
                       else _py_package)(positional)
            if package is not None and package.name.lower() in BRIDGES:
                after = runner.args[runner.args.index(positional) + 1:]
                out.extend(_bridge_roles(package.name.lower(), after))
    for key, value in (cfg.get("env") or {}).items():
        if str(key).lower() in _REGISTRY_ENV:
            out.append(_Role("registry", str(value), str(key)))
    return out


def _single(parsed: urls.Url) -> "urls.Reading | None":
    """The one host every parser reads `parsed` as, when there is one and the
    text spells it out; else None. (Parsers that disagree give readings with
    different hosts, and an escape, a non-ASCII name or a character no host
    has gives a reading that is not exact.)"""
    if not parsed.readings:
        return None
    first = parsed.readings[0]
    if all(r.exact and r.host == first.host for r in parsed.readings):
        return first
    return None


def _git_ref(url: str, npm: bool) -> "str | None":
    """The commit, tag or branch a git URL names, if it names one: npm writes
    it after `#`, pip and uv after an `@` in the path."""
    base, _, fragment = url.partition("#")
    if npm:
        return fragment or None
    path = (base.split("://", 1)[1] if "://" in base else base).partition(
        "/")[2]
    if "@" not in path:
        return None
    return path.rpartition("@")[2] or None


def _source_findings(role: _Role, allow) -> "list[dict] | None":
    spec, ref = role.value, None
    match = _GIT_URL_RE.fullmatch(spec)
    if match:
        parsed = urls.parse(match.group(1))
        reading = _single(parsed)
        if reading is None or parsed.scheme != "https":
            return None
        host, shown = reading.host, _shown(parsed, [reading])
        ref = _git_ref(match.group(1), role.ecosystem == "npm")
    else:
        short = (_GIT_SHORT_RE.fullmatch(spec) if role.ecosystem == "npm"
                 else None)
        if short is None:
            return None
        host = _SHORT_HOSTS[short.group(1).lower()]
        shown, ref = f"https://{host}/...", short.group(3) or None
    if not (_listed(host, GIT_FORGES) or _trusted("https", host, allow)):
        return None
    if ref and _COMMIT_RE.fullmatch(ref):
        severity, detail = "low", "pinned to a commit"
    elif ref and _TAG_RE.fullmatch(ref):
        severity, detail = "low", ("pinned to a tag, which can be moved to "
                                  "other code")
    elif ref:
        severity, detail = "medium", ("pinned to a branch or a range, so "
                                      "every launch can run different code")
    else:
        severity, detail = "medium", ("no commit or tag pinned, so every "
                                      "launch runs whatever the default "
                                      "branch holds")
    message = (f"package comes from a git repository, not a registry: "
               f"{shown} ({detail})")
    if severity != "low" or "tag" in detail:
        message += "; pin it to a commit"
    return [_finding(severity, "git-source", message)]


def _registry_findings(role: _Role, allow) -> "list[dict] | None":
    parsed = urls.parse(role.value)
    reading = _single(parsed)
    if reading is None or parsed.scheme not in ("http", "https"):
        return None
    host = reading.host
    if _is_local(host) or (parsed.scheme == "https" and (
            _listed(host, DEFAULT_REGISTRIES)
            or _trusted("https", host, allow))):
        return []
    shown = _shown(parsed, [reading])
    if parsed.scheme == "http":
        return [_finding(
            "high", "package-registry",
            f"package registry over plain http ({role.via}): {shown}; "
            "anyone on the way can swap what it serves, and every package "
            "this server installs comes from there")]
    return [_finding(
        "medium", "package-registry",
        f"package registry other than the default ({role.via}): {shown}; "
        "every package this server installs comes from there, so it can run "
        "code as you. Point it only at a registry you run or trust "
        "(--allow-host marks one)")]


def _bridge_findings(role: _Role, allow) -> "list[dict] | None":
    # (a bridge role is a value that starts like an http, https, ws or wss URL)
    if _single(urls.parse(role.value)) is None:
        return None
    return _remote_server(role.value, allow, via=role.via)


def _role_findings(role: _Role, allow) -> "list[dict] | None":
    """The findings for a role's value - none when it is as expected - or
    None when it does not qualify for a verdict of its own."""
    try:
        if role.kind == "source":
            return _source_findings(role, allow)
        if role.kind == "registry":
            return _registry_findings(role, allow)
        return _bridge_findings(role, allow)
    except urls.UnparseableUrl:
        return None


def _mask(text: str, value: str) -> "tuple[str, bool]":
    """`text` without the places where `value` stands as a whole word (not
    as the start of a longer host: `https://registry.npmjs.org.evil.example`
    is not `https://registry.npmjs.org`), and whether there were any."""
    if not value:
        return text, False
    out, start, hit = [], 0, False
    i = text.find(value)
    while i >= 0:
        end = i + len(value)
        if ((i == 0 or text[i - 1] in _EDGE_BEFORE)
                and (end == len(text) or text[end] in _EDGE_AFTER)):
            out += [text[start:i], " "]
            start, hit = end, True
        # Searching on from the end of a place, whether it was masked or not,
        # keeps this linear; a place that overlaps it stays unmasked, and the
        # scan for endpoints sees it.
        i = text.find(value, end)
    out.append(text[start:])
    return "".join(out), hit


def detect_floating_version(name: str, cfg: dict) -> list[dict]:
    """Packages that are not pinned to one release: no version, a tag
    (`latest`, `next`) or a range (`^1.2.0`, `>=1`, `1.x`, `*`)."""
    findings = []
    seen = set()
    for p in _iter_packages(cfg):
        if p.exact:
            continue
        shown = _echo(p.name)
        hint = (f"{shown}==x.y.z" if p.ecosystem == "PyPI"
                else f"{shown}@x.y.z")
        if not p.sure:
            # (the word may be the value of an option, so it is not quoted)
            msg = ("package not shown: an option mcp-audit does not know "
                   "comes before it, so its name cannot be told from that "
                   "option's value. If it is not pinned to one release, every "
                   "launch can pull a different (possibly compromised) one: "
                   "pin it with name@x.y.z")
        elif p.version is None:
            msg = (f"unpinned package '{shown}' — every launch can pull "
                   "a different (possibly compromised) release; pin with "
                   f"{hint}")
        else:
            msg = (f"package '{shown}' is not pinned to one release: "
                   f"'{_echo(p.version)}' can resolve to a different version on "
                   f"any launch (possibly a compromised one); pin with {hint}")
        if msg not in seen:
            seen.add(msg)
            findings.append(_finding("medium", "floating-version", msg))
    return findings


class AdvisoryFeedError(RuntimeError):
    """The shipped advisory feed is missing, unreadable or malformed.

    Never swallowed into "no advisories": an install that lost its feed
    would grade every known-vulnerable package as clean."""


def _read_feed_text() -> str:
    # Package data, so it also works from a wheel or a zip. The feed is
    # UTF-8 (it has em dashes); decoding it with a Windows code page would
    # garble titles or, on some pages, drop the feed.
    return resources.files(__package__).joinpath(FEED_NAME).read_text(
        encoding="utf-8")


def load_advisories() -> list[dict]:
    """The advisory feed. Raises AdvisoryFeedError if it cannot be used."""
    try:
        feed = json.loads(_read_feed_text())
    except Exception as e:  # missing, unreadable, not JSON, not a package
        raise AdvisoryFeedError(
            f"the advisory feed {FEED_NAME} cannot be read "
            f"({type(e).__name__}); this install is broken") from None
    if not isinstance(feed, list) or not all(
            isinstance(a, dict) and isinstance(a.get("package"), str)
            and a["package"] for a in feed):
        raise AdvisoryFeedError(
            f"the advisory feed {FEED_NAME} is malformed (expected a list of "
            "objects that each name a package)")
    return feed


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
    pkgs = {p.name.lower(): p.release() for p in _iter_packages(cfg)}
    # also match plain command names (uvx mcp-server-git -> "mcp-server-git")
    haystack = (set(pkgs) | {name for name, _ in _launched(cfg)}
                | {_cmd_name(cfg)})
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
    findings = []
    for p in _iter_packages(cfg):
        pkg, ver, eco = p.name, p.release(), p.ecosystem
        if not ver or not p.sure:  # a range, a tag - or maybe not a package
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
                                     f"OSV lookup for {_echo(pkg)}@{_echo(ver)} failed: {e}"))
            continue
        for v in vulns:
            findings.append(_finding(
                "high", "known-vulnerable",
                f"{_echo(pkg)}@{_echo(ver)} is affected by {v.get('id')} (OSV): "
                f"{v.get('summary') or 'see https://osv.dev/' + str(v.get('id'))}"))
    return findings


def detect_unauditable(name: str, cfg: dict) -> list[dict]:
    """An entry with nothing to launch or connect to cannot be analyzed -
    say so instead of letting it read as a clean bill of health (for
    instance a Zed server provided by an extension, whose command lives in
    the extension and not in settings.json)."""
    if cfg.get("command") or remote_urls(cfg):
        return []
    return [_finding(
        "low", "unauditable",
        "entry has no 'command' and no 'url' or 'serverUrl' (provided by an "
        "extension?): what it runs is not in this config, so nothing could "
        "be audited")]


def detect_secret_env(name: str, cfg: dict) -> list[dict]:
    findings = []
    secrets = [k for k in (cfg.get("env") or {}) if redact.is_secret_name(k)]
    if secrets:
        shown = ", ".join(sorted(secrets)[:5])
        more = f" (+{len(secrets) - 5} more)" if len(secrets) > 5 else ""
        findings.append(_finding(
            "medium", "secret-env",
            f"server receives secrets via env: {shown}{more} — "
            f"a compromised server leaks these"))
    return findings


# -- How the server is launched: secrets in args, privileges, temp folders ----

#: Programs that run what follows with more rights than the user has.
_PRIVILEGE = frozenset({"sudo", "doas", "pkexec", "su", "runas", "gsudo"})
_CONTAINER_RUNTIMES = frozenset({"docker", "podman", "nerdctl"})
#: A value that is a reference or a placeholder, not a credential.
_REFERENCE_RE = re.compile(r"^\s*(?:\$|%|<|\{\{|\[|@)")
#: The last word of an option that names where a credential is, not what it is.
_NOT_A_VALUE = frozenset({"FILE", "PATH", "ENV", "VAR", "DIR", "NAME", "URL",
                          "ID", "TYPE", "MODE", "ENABLED", "LENGTH", "SIZE",
                          "LOCATION", "HEADER", "FORMAT", "PROMPT", "STORE",
                          "HELPER", "PROVIDER", "SOURCE", "REF"})
#: A word anywhere in an option's name that says it holds an amount, not a
#: credential: --max-tokens, --token-limit, --token-ttl, --retry-count.
_AMOUNT_WORDS = frozenset({"LIMIT", "LIMITS", "MAX", "MIN", "COUNT", "TTL",
                           "TIMEOUT", "EXPIRY", "EXPIRES", "LIFETIME",
                           "BUDGET", "THRESHOLD", "QUOTA", "RATE"})
_DIGITS_RE = re.compile(r"[0-9][0-9_,.]*")
#: `scheme://user:password@host`: the password is group 1.
_URL_PASSWORD_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]{0,31}://[^/\s:@?#]*:([^/\s@?#]+)@")
#: Programs whose short option hands the next word, or the rest of the same
#: word, to them as a password: `sshpass -p hunter22`, `mysql -phunter22`,
#: `redis-cli -a hunter22`, `curl -u me:hunter22`. (`mysql -p hunter22` makes
#: hunter22 a database name, and `psql -p 5432` is a port: neither is here.)
_PASSWORD_SHORT = {
    "sshpass": ("-p", True), "mongosh": ("-p", True), "mongo": ("-p", True),
    "redis-cli": ("-a", True), "mysql": ("-p", False),
    "mysqldump": ("-p", False), "mysqladmin": ("-p", False),
    "mariadb": ("-p", False), "mysqlsh": ("-p", False),
}
_PLAIN_WORDS = frozenset({"true", "false", "none", "null", "yes", "no",
                          "required", "optional", "enabled", "disabled",
                          "oauth", "basic", "bearer", "stdin", "prompt"})
#: A folder every user of the machine can write to.
_TEMP_RE = re.compile(
    r"""(?ix)^["']?(?:
        /(?:private/)?(?:var/)?tmp[/\\]. | /dev/shm[/\\]. |
        /(?:private/)?var/folders/. |
        (?:%t(?:e)?mp%|\$\{?t(?:e)?mp(?:dir)?\}?)[/\\]. |
        [a-z]:[/\\]windows[/\\]temp[/\\]. |
        [a-z]:[/\\]users[/\\][^/\\]+[/\\]appdata[/\\]local[/\\]temp[/\\].
    )""")
#: Folders under a temporary one that are not reported. Empty; the tests set
#: it when the checkout they run from is itself in a temporary folder.
_TEMP_EXEMPT: "tuple[str, ...]" = ()
_CODE_EXT_RE = re.compile(
    r"(?i)\.(?:sh|bash|py|js|mjs|cjs|ts|rb|pl|php|jar|exe|bat|cmd|ps1|so|dll"
    r"|run|appimage|whl|tgz|tar\.gz|egg)[\"']?$")
_DANGEROUS_CAPS = frozenset({"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE",
                             "SYS_RAWIO", "DAC_READ_SEARCH", "NET_ADMIN"})
_SENSITIVE_MOUNTS = frozenset({"/", "/etc", "/root", "/proc", "/sys", "/dev",
                               "/boot", "/var/run", "/run"})
_HOME_MOUNTS = frozenset({"~", "$home", "${home}", "/home", "/users",
                          "%userprofile%", "c:\\users", "c:\\"})
#: Folders (whole path segments) that hold credentials: a mount of
#: /home/me/.config/x is one, a mount of /srv/.configs is not.
_SECRET_DIRS = frozenset((".ssh", ".aws", ".gnupg", ".kube", ".docker",
                          ".config"))


def _credential_in(words: "list[str]") -> "tuple[bool, bool]":
    """(shape, named): is there a word that looks like a well-known credential
    (ghp_..., sk-..., a JWT, `Bearer ...`), and one that is the value of a
    credential-named option (`--token abc123`, `--api-key=abc123`,
    `MY_PASS=abc123`)? Values are never returned."""
    shape = named = False
    n = len(words)
    for i, w in enumerate(words):
        if redact._TOKEN_SHAPES_RE.search(w) or redact._BEARER_RE.search(w) \
                or redact._redact_jwts(w) != w:
            shape = True
        if named:
            continue
        m = _URL_PASSWORD_RE.search(w)
        if m and _plausible_secret(m.group(1)):
            named = True
            continue
        name, value = None, None
        if w.startswith("-") and "=" in w:
            name, _, value = w.partition("=")
        elif w.startswith("-") and i + 1 < n and not words[i + 1].startswith("-"):
            name, value = w, words[i + 1]
        elif not w.startswith("-") and "=" in w and re.match(
                r"[A-Za-z_][A-Za-z0-9_]*=", w):
            name, _, value = w.partition("=")
        if name is None or value is None:
            continue
        bare = name.lstrip("-")
        parts = [x.upper() for x in redact._WORD_RE.findall(bare)]
        if not parts or parts[-1] in _NOT_A_VALUE:
            continue
        if _AMOUNT_WORDS.intersection(parts):
            continue
        if name.startswith("-") and not redact.takes_a_credential(name):
            continue
        if not name.startswith("-") and not redact.is_secret_name(name):
            continue
        value = value.strip().strip("'\"")
        # `--tokens 250000` counts tokens; `--token 250000` is still a token
        if parts[-1] == "TOKENS" and _DIGITS_RE.fullmatch(value):
            continue
        if _plausible_secret(value):
            named = True
    if not named:
        named = _short_password(words)
    return shape, named


def _plausible_secret(value: str) -> bool:
    """A value long enough to be a credential that is not a reference
    ($TOKEN, %TOKEN%, <your-token>) or a plain word (true, oauth)."""
    value = value.strip().strip("'\"")
    return (len(value) >= 6 and not _REFERENCE_RE.match(value)
            and value.lower() not in _PLAIN_WORDS)


def _short_password(words: "list[str]") -> bool:
    """Is a password given to a known program as its short option (see
    _PASSWORD_SHORT)? `curl -u user:password` is the other shape."""
    prog = None
    for i, w in enumerate(words):
        base = _prog_name(w) if not w.startswith("-") else ""
        if base in _PASSWORD_SHORT or base == "curl":
            prog = base
            rest = words[i + 1:]
            break
    if prog is None:
        return False
    if prog == "curl":
        for j, w in enumerate(rest):
            value = None
            if w in ("-u", "--user") and j + 1 < len(rest):
                value = rest[j + 1]
            elif w.startswith("--user="):
                value = w.split("=", 1)[1]
            elif w.startswith("-u") and not w.startswith("--") and len(w) > 2:
                value = w[2:]
            if value and ":" in value and _plausible_secret(
                    value.split(":", 1)[1]):
                return True
        return False
    opt, separate = _PASSWORD_SHORT[prog]
    for j, w in enumerate(rest):
        if w == opt and separate and j + 1 < len(rest):
            if _plausible_secret(rest[j + 1]) and not rest[j + 1].startswith("-"):
                return True
        elif w.startswith(opt) and len(w) > len(opt) and w[2] != "-":
            if _plausible_secret(w[len(opt):]):
                return True
    return False


def _mount_sources(args: "list[str]") -> "list[str]":
    """The host side of every -v/--volume/--mount in a container command."""
    out = []
    for i, a in enumerate(args):
        value = None
        if (a in ("-v", "--volume", "--mount") or (
                len(a) > 2 and a.startswith("-") and not a.startswith("--")
                and a.endswith("v")
                and all(c in _RUN_SHORT_SWITCHES for c in a[1:-1]))
                ) and i + 1 < len(args):     # -v, or -itv
            value = args[i + 1]
        elif a.startswith(("--volume=", "--mount=")):
            value = a.split("=", 1)[1]
        elif a.startswith("-v") and len(a) > 2 and not a.startswith("-v="):
            value = a[2:]
        if value is None:
            continue
        if "source=" in value or "src=" in value:
            m = re.search(r"(?:^|,)(?:source|src)=([^,]*)", value)
            if m:
                out.append(m.group(1))
        else:
            # <host>:<container>[:opts]; a Windows drive letter is "C:\"
            m = re.match(r"([A-Za-z]:[\\/][^:]*|[^:]*)", value)
            out.append(m.group(1) if m else value)
    return out


#: `docker run` options that are switches: they take no value.
_RUN_SWITCHES = frozenset({
    "--privileged", "--rm", "--init", "--read-only", "--interactive",
    "--tty", "--detach", "--sig-proxy", "--oom-kill-disable",
    "--no-healthcheck", "--publish-all", "--quiet", "--disable-content-trust",
    "--help"})
_RUN_SHORT_SWITCHES = frozenset("itdPq")
#: ...and short options that take one (`-v a:b`, `-vA:B`, `-eX=1`).
_RUN_SHORT_VALUES = frozenset("vepuwlmhacgnsx")


def _run_options(args: "list[str]") -> "list[str]":
    """The options of a `docker run` / `create`, up to the image: everything
    after the image name is the container's own command line (`docker run img
    --privileged` hands --privileged to the program in the container).

    An option this does not know, followed by a word that is not an option, is
    taken to have that word as its value. That can only make the image appear
    later than it is, never earlier, so a risky option is never skipped."""
    start = next((i for i, a in enumerate(args) if a in ("run", "create")),
                 None)
    if start is None:
        return list(args)
    out = list(args[:start + 1])
    i, n = start + 1, len(args)
    while i < n:
        a = args[i]
        if a == "--" or not a.startswith("-") or a == "-":
            break               # `--`, or the image
        out.append(a)
        i += 1
        if a.startswith("--"):
            if "=" in a or a in _RUN_SWITCHES:
                continue
        else:
            letters = a[1:]
            if letters and letters[0] in _RUN_SHORT_VALUES and len(a) > 2:
                continue        # -vA:B, -eX=1: the value is attached
            if letters and all(c in _RUN_SHORT_SWITCHES for c in letters):
                continue        # -it, -d
        if i < n and not args[i].startswith("-"):
            out.append(args[i])  # its value
            i += 1
    return out


def _segments(path: str) -> "list[str]":
    return [x for x in re.split(r"[/\\]+", path.lower()) if x]


def _container_risks(args: "list[str]") -> "list[tuple[str, str]]":
    """[(severity, what)] for the options of a `docker run` that hand the
    container the host."""
    found: "list[tuple[str, str]]" = []
    args = _run_options(args)

    def option(*names):
        """The values given to one of these options."""
        vals = []
        for i, a in enumerate(args):
            for nm in names:
                if a == nm and i + 1 < len(args):
                    vals.append(args[i + 1])
                elif a.startswith(nm + "="):
                    vals.append(a.split("=", 1)[1])
        return vals
    if any(a == "--privileged" or a.startswith("--privileged=")
           and a.split("=", 1)[1].lower() != "false" for a in args):
        found.append(("high", "--privileged (full access to the host)"))
    for cap in option("--cap-add"):
        if cap.upper().removeprefix("CAP_") in _DANGEROUS_CAPS:
            found.append(("high", f"--cap-add {_echo(cap, 24)}"))
    for kind in ("--pid", "--userns", "--ipc"):
        if any(v.lower() == "host" for v in option(kind)):
            found.append(("high", f"{kind}=host"))
    if any(v.lower() == "host" for v in option("--net", "--network")):
        found.append(("medium", "--network=host"))
    for v in option("--security-opt"):
        if "unconfined" in v.lower() or "label=disable" in v.lower():
            found.append(("high", "--security-opt with the sandbox turned off"))
    if option("--device"):
        found.append(("medium", "--device (a host device)"))
    for src in _mount_sources(args):
        norm = src.strip("'\"").rstrip("/\\") or "/"
        low = norm.lower()
        if low.endswith((".sock",)) and "docker" in low or \
                low.endswith(("podman.sock", "containerd.sock", "crio.sock")):
            found.append(("high", "the container runtime's socket (control of "
                                  "every container and the host)"))
        elif norm in _SENSITIVE_MOUNTS or _SECRET_DIRS.intersection(
                _segments(norm)):
            found.append(("high", f"a mount of '{_echo(norm, 40)}'"))
        elif low in _HOME_MOUNTS:
            found.append(("medium", "a mount of the home directory"))
    return found


def _temp_candidates(word: str) -> "list[str]":
    """The paths a word may hold: the word, the value of `--opt=value`, and
    the path inside a file:// URL."""
    out = [word]
    if word.startswith("-") and "=" in word:
        out.append(word.split("=", 1)[1])
    for w in list(out):
        if w.lower().lstrip("'\"").startswith("file://"):
            path = w.lstrip("'\"")[7:]
            if path.lower().startswith("localhost/"):
                path = path[9:]
            if re.match(r"/[A-Za-z]:[/\\]", path):    # file:///C:/...
                path = path[1:]
            out.append(path)
    return out


def detect_risky_launch(name: str, cfg: dict) -> list[dict]:
    """How the server is started: a credential written into its arguments
    (visible to every process on the machine and kept in the config), extra
    privileges (`sudo`, a privileged or host-mounting container) and code
    that sits in a folder anyone can write to."""
    try:
        scan = _scan_launch(cfg)
    except _TooComplex:
        return []   # detect_suspicious_command reports it
    findings = []
    command = str(cfg.get("command") or "")
    words = ([command] if command else []) + [
        str(a) for a in (cfg.get("args") or [])]
    # the args as the config gives them, and as a script's commands do
    shape, named = _credential_in(words + [w for w in scan.words
                                           if w not in words])
    if shape:
        findings.append(_finding(
            "high", "secret-in-args",
            "an argument holds what looks like a live credential (a token "
            "or key written into the command line) — it is visible to every "
            "process on the machine; pass it through the environment or a "
            "secret store"))
    elif named:
        findings.append(_finding(
            "medium", "secret-in-args",
            "a credential (the value of --token, --api-key, --password ..., "
            "or a password inside a URL) is written in the arguments — it is "
            "visible to every "
            "process on the machine; pass it through the environment or a "
            "secret store"))
    boss = sorted((set(p for p, _ in scan.programs) | scan.prefixes)
                  & _PRIVILEGE)
    if boss:
        findings.append(_finding(
            "high", "privileged-launch",
            f"server is started with {_names(boss)} — it runs with more "
            "rights than your own account; a server should not need them"))
    for prog, args in scan.launches:
        if prog in _CONTAINER_RUNTIMES and any(
                a in ("run", "create") for a in args):
            risks = _container_risks(args)
            for sev in ("high", "medium"):
                said = [w for s_, w in risks if s_ == sev]
                if said:
                    findings.append(_finding(
                        sev, "container-escape",
                        f"'{prog}' starts the server with host access: "
                        + "; ".join(dict.fromkeys(said))))
    temp = []
    progs = {command} | set(scan.progwords)
    for w in words + [x for x in scan.words if x not in words]:
        for cand in _temp_candidates(w):
            if (_TEMP_RE.match(cand) and not cand.startswith(_TEMP_EXEMPT)
                    and (w in progs or _CODE_EXT_RE.search(cand))):
                temp.append(cand)
                break
    if temp:
        findings.append(_finding(
            "high", "temp-binary",
            "server runs code from a temporary folder "
            f"('{_echo(temp[0], 40)}') that other users and programs can "
            "write to — anyone who can replace that file controls the "
            "server"))
    return findings


def detect_known_ioc(name: str, cfg: dict, campaigns=None) -> list[dict]:
    """An indicator from a published campaign report (iocs.json)."""
    from . import iocs
    return iocs.findings(name, cfg,
                         iocs.default_feed() if campaigns is None
                         else campaigns)


STATIC_DETECTORS = (
    detect_unauditable,
    detect_suspicious_command,
    detect_exfiltration,
    detect_known_bad,
    detect_floating_version,
    detect_secret_env,
    detect_risky_launch,
    detect_known_ioc,
)


#: What each detector looks at, for the "could not analyze ..." finding.
DETECTOR_SUBJECT = {
    "detect_unauditable": "what the entry runs",
    "detect_suspicious_command": "the launch command",
    "detect_exfiltration": "URLs and endpoints",
    "detect_known_bad": "known-vulnerable packages",
    "detect_floating_version": "package pinning",
    "detect_secret_env": "secrets in env",
    "detect_risky_launch": "how the server is launched",
    "detect_known_ioc": "known campaign indicators",
}


def _config_problem(cfg) -> str | None:
    """Why an entry cannot be analyzed at all, or None. Only types are
    named, never values (a value may be a secret)."""
    if not isinstance(cfg, dict):
        return f"server entry is not a JSON object (got {type(cfg).__name__})"
    for key, want in (("command", str), ("args", list), ("env", dict),
                      ("url", str), ("serverUrl", str)):
        value = cfg.get(key)
        if value is not None and not isinstance(value, want):
            return (f"'{key}' must be {'a ' + want.__name__} "
                    f"(got {type(value).__name__})")
    return None


def audit_server(name: str, cfg: dict,
                 advisories: list[dict] | None = None,
                 allow_hosts=(), campaigns=None) -> list[dict]:
    """Run all static detectors against one server entry. `allow_hosts`: the
    hosts the user trusts (--allow-host), as host_pattern() writes them.

    Fails closed: an entry that cannot be analyzed, or a detector that
    raises, is a HIGH finding (so --fail-on high trips) - never a quiet
    pass. The exception's message is not shown, only its class, because the
    message may quote the config (a secret, say).
    """
    problem = _config_problem(cfg)
    if problem:
        return [_finding("high", "invalid-config",
                         f"{problem}; this entry cannot be analyzed")]
    findings: list[dict] = []
    for det in STATIC_DETECTORS:
        try:
            if det is detect_known_bad:
                findings.extend(det(name, cfg, advisories))
            elif det is detect_exfiltration:
                findings.extend(det(name, cfg, allow_hosts))
            elif det is detect_known_ioc:
                findings.extend(det(name, cfg, campaigns))
            else:
                findings.extend(det(name, cfg))
        except Exception as e:  # incl. RecursionError and MemoryError
            subject = DETECTOR_SUBJECT.get(det.__name__, det.__name__)
            findings.append(_finding(
                "high", "detector-error",
                f"could not analyze {subject} ({type(e).__name__}); treat "
                "this server as unaudited"))
    for f in findings:  # last line of defense: no detector may leak
        f["message"] = redact.clean(f["message"])
    return findings
