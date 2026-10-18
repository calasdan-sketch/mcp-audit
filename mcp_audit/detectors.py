"""Static detectors: config-level checks needing no network and no execution."""

from __future__ import annotations

import ipaddress
import json
import ntpath
import re
import urllib.parse
import urllib.request
from importlib import resources
from typing import NamedTuple

from . import redact

#: The advisory feed, shipped as package data next to this module.
FEED_NAME = "advisories.json"

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


def _finding(severity: str, check: str, message: str) -> dict:
    return {"severity": severity, "check": check, "message": message}


def _cmd_name(cfg: dict) -> str:
    """Bare, lower-case name of the config's command (see _prog_name)."""
    return _prog_name(str(cfg.get("command") or ""))


def _is_local(host: str) -> bool:
    host = (host or "").strip("[]").lower()
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _is_allowed_api(parts: urllib.parse.SplitResult) -> bool:
    host = (parts.hostname or "").lower()
    if parts.scheme.lower() not in ("https", "wss") or not host:
        return False
    return any(host.endswith(h) if h.startswith(".") else host == h
               for h in ALLOWED_API_HOSTS)


def _endpoints(text: str) -> list[tuple[str, str]]:
    """Remote, non-allowlisted endpoints (URLs and bare IP:port) in text, as
    (kind, endpoint). kind is "url", "hostport" (a bare IP:port, which has no
    userinfo or path to hide anything in) or "unparseable" for a URL that
    could not be taken apart: URLs are handled one at a time, so one
    malformed URL can neither hide another one nor take the whole detector
    down."""
    out = []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;)")
        try:
            parts = urllib.parse.urlsplit(url)
            remote = (not _is_local(parts.hostname or "")
                      and not _is_allowed_api(parts))
        except ValueError:
            out.append(("unparseable", url))
            continue
        if remote:
            out.append(("url", url))
    for m in IP_PORT_RE.finditer(text):
        try:
            ipaddress.ip_address(m.group(1))
        except ValueError:
            continue  # not an IP (e.g. a version string)
        if not _is_local(m.group(1)):
            out.append(("hostport", m.group(0)))
    return out


def _unparseable_url(where: str) -> dict:
    # Deliberately does not echo the URL: it cannot be told apart from a
    # secret, and nothing about it could be established anyway.
    return _finding(
        "high", "unparseable-url",
        f"unparseable URL in {where}: it could not be taken apart, so where "
        "it points is unknown - treated as unsafe")


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
        try:
            local = _is_local(urllib.parse.urlsplit(url).hostname or "")
        except ValueError:
            return [_unparseable_url("url")]
        if not local:
            findings.append(_finding(
                "medium", "remote-server",
                "remote MCP server URL (traffic leaves the machine): "
                f"{redact.safe_url(url)}"))
        return findings
    for where, text in _text_blobs(cfg):
        for kind, url in _endpoints(text):
            if kind == "unparseable":
                findings.append(_unparseable_url(where))
                continue
            # A remote endpoint baked into launch args is critical. In env it
            # is usually service config (API base URLs), so medium: worth a
            # look, not a verdict. Well-known API hosts are not reported.
            sev = "medium" if where.startswith("env:") else "critical"
            shown = redact.safe_url(url) if kind == "url" else url
            findings.append(_finding(
                sev, "exfiltration-endpoint",
                f"remote endpoint in {where}: {shown}"))
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
        self.pipe = False   # something is piped into a shell
        self.eval = False   # `eval` of generated text


def _scan_launch(cfg: dict) -> _Launch:
    out = _Launch()
    command = str(cfg.get("command") or "")
    words = ([command] if command else []) + [
        str(a) for a in (cfg.get("args") or [])]
    _scan_words(out, words, (), 0)
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
    return Package(m.group(1), version, exact, "npm")


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
        return Package(name, None, False, "PyPI")
    if rest.startswith("@"):  # uvx pkg@1.2.3, uvx pkg@latest
        version = rest[1:].strip() or None
        exact = version is not None and (
            _PY_RELEASE_RE.fullmatch(version) is not None
            or _DIGEST_RE.fullmatch(version) is not None)
        return Package(name, version, exact, "PyPI")
    for clause in rest.split(","):  # PEP 440: any exact clause pins it
        c = re.fullmatch(r"\s*===?\s*(\S+)\s*", clause)
        if c and _PY_RELEASE_RE.fullmatch(c.group(1)):
            return Package(name, c.group(1), True, "PyPI")
    return Package(name, rest, False, "PyPI")


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
_NPM_RUNNERS = frozenset({"npx", "bunx", "pnpx"})
#: (tool, subcommand) pairs that fetch and run a package like npx does.
_NPM_VIA = frozenset({("pnpm", "dlx"), ("yarn", "dlx"), ("npm", "exec"),
                      ("npm", "x"), ("bun", "x")})


def _split_runner_args(args: "list[str]", value_opts) -> tuple:
    """(options, first positional) of a runner's arguments. Options are
    (name, value|None); everything after the positional belongs to the
    program being run."""
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
        elif a in value_opts and i + 1 < n:
            opts.append((a, args[i + 1]))
            i += 2
        else:
            opts.append((a, None))
            i += 1
    return opts, (args[i] if i < n else None)


def _npm_packages(args: "list[str]", call_is_command: bool
                  ) -> "list[Package]":
    """call_is_command: `-c` hands the runner a command string (npx, npm
    exec) and so runs no package; for pnpm and bun it is only a flag."""
    opts, positional = _split_runner_args(args, _NPM_VALUE_OPTS)
    specs = [v for o, v in opts if o in ("-p", "--package") and v]
    called = call_is_command and any(o in ("-c", "--call") for o, _ in opts)
    if not specs and positional and not called:
        specs = [positional]
    return [p for p in map(_npm_package, specs) if p]


def _py_packages(args: "list[str]", spec_opt: str = "--from"
                 ) -> "list[Package]":
    opts, positional = _split_runner_args(args, _PY_VALUE_OPTS)
    froms = [v for o, v in opts if o == spec_opt and v]
    main = froms[0] if froms else positional
    specs = ([main] if main else []) + [v for o, v in opts
                                        if o == "--with" and v]
    return [p for p in map(_py_package, specs) if p]


def _packages_of(name: str, args: "list[str]") -> "list[Package]":
    """What `name args...` downloads, if it is a package runner."""
    if name in _NPM_RUNNERS:
        return _npm_packages(args, call_is_command=(name == "npx"))
    if name in ("pnpm", "yarn", "npm", "bun"):
        rest = [a for a in args if not a.startswith("-")][:1]
        if rest and (name, rest[0]) in _NPM_VIA:
            i = args.index(rest[0])
            return _npm_packages(args[i + 1:],
                                 call_is_command=(name == "npm"))
        return []
    if name == "uvx":
        return _py_packages(args)
    if name == "uv" and args[:2] == ["tool", "run"]:
        return _py_packages(args[2:])
    if name == "pipx" and args[:1] == ["run"]:
        return _py_packages(args[1:], spec_opt="--spec")
    return []


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


def detect_floating_version(name: str, cfg: dict) -> list[dict]:
    """Packages that are not pinned to one release: no version, a tag
    (`latest`, `next`) or a range (`^1.2.0`, `>=1`, `1.x`, `*`)."""
    findings = []
    seen = set()
    for p in _iter_packages(cfg):
        if p.exact:
            continue
        hint = (f"{p.name}==x.y.z" if p.ecosystem == "PyPI"
                else f"{p.name}@x.y.z")
        if p.version is None:
            msg = (f"unpinned package '{p.name}' — every launch can pull "
                   "a different (possibly compromised) release; pin with "
                   f"{hint}")
        else:
            msg = (f"package '{p.name}' is not pinned to one release: "
                   f"'{p.version}' can resolve to a different version on "
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
        if not ver:  # a range or a tag: nothing exact to look up
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


def detect_unauditable(name: str, cfg: dict) -> list[dict]:
    """An entry with nothing to launch or connect to cannot be analyzed -
    say so instead of letting it read as a clean bill of health (for
    instance a Zed server provided by an extension, whose command lives in
    the extension and not in settings.json)."""
    if cfg.get("command") or cfg.get("url"):
        return []
    return [_finding(
        "low", "unauditable",
        "entry has no 'command' and no 'url' (provided by an extension?): "
        "what it runs is not in this config, so nothing could be audited")]


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


STATIC_DETECTORS = (
    detect_unauditable,
    detect_suspicious_command,
    detect_exfiltration,
    detect_known_bad,
    detect_floating_version,
    detect_secret_env,
)


#: What each detector looks at, for the "could not analyze ..." finding.
DETECTOR_SUBJECT = {
    "detect_unauditable": "what the entry runs",
    "detect_suspicious_command": "the launch command",
    "detect_exfiltration": "URLs and endpoints",
    "detect_known_bad": "known-vulnerable packages",
    "detect_floating_version": "package pinning",
    "detect_secret_env": "secrets in env",
}


def _config_problem(cfg) -> str | None:
    """Why an entry cannot be analyzed at all, or None. Only types are
    named, never values (a value may be a secret)."""
    if not isinstance(cfg, dict):
        return f"server entry is not a JSON object (got {type(cfg).__name__})"
    for key, want in (("command", str), ("args", list), ("env", dict),
                      ("url", str)):
        value = cfg.get(key)
        if value is not None and not isinstance(value, want):
            return (f"'{key}' must be {'a ' + want.__name__} "
                    f"(got {type(value).__name__})")
    return None


def audit_server(name: str, cfg: dict,
                 advisories: list[dict] | None = None) -> list[dict]:
    """Run all static detectors against one server entry.

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
