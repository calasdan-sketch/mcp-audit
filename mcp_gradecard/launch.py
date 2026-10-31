"""What a server entry runs, said without printing its arguments.

The --deep launch list and the --fix plan have to tell a person what is about
to run. Arguments are where credentials live, and no list of flag names is
complete (`--auth X`, `--pass X`, `-e MY_PASS=X`, `--header "X-API-Key: X"`,
`--config '{"token": "X"}'`, a bare positional token), so they are counted,
never printed. What is printed has a fixed shape that cannot carry one:

* the name of the program (`npx`, `node`, `curl`), looked for through the
  shells and wrappers around it (`cmd /c npx ...` runs npx, `env A=1 node
  s.js` runs node);
* the package an npx/uvx-style launcher fetches (`some-server@1.2.3`), the
  script it starts (`server.js`) or the module (`-m mcp_server_fetch`), when
  it is plainly one (after an option that mcp-gradecard does not know, the word
  that looks like the package could be the option's value: the line says
  `(package not shown)` instead);
* how many arguments were left out;
* the host of every http(s)/ws(s) URL in them, as everywhere else
  (`scheme://host[:port]`, then `/...` if anything followed) - in a shell
  script also the URLs as the shell hands them over (`https://''host`).

The config file named next to it has the rest.
"""

from __future__ import annotations

import re

from . import detectors, urls

#: A line is cut here (one server per line in a notice).
_LIMIT = 240
_MAX_URLS = 3
_SCRIPT_EXTENSIONS = (
    "js", "mjs", "cjs", "jsx", "ts", "mts", "cts", "tsx", "py", "pyw", "pyz",
    "rb", "php", "pl", "lua", "sh", "bash", "ps1", "bat", "cmd", "exe", "jar",
    "dll", "wasm")
#: A file that runs: a path made of ordinary path characters, then a known
#: extension. (A secret does not look like this.) Spaces are allowed because
#: Windows paths have them.
_SCRIPT_RE = re.compile(
    r"(?:[A-Za-z]:)?[\w@%+,./\\ ~\-]+\.(?:" + "|".join(_SCRIPT_EXTENSIONS)
    + ")", re.IGNORECASE)
_MAX_SCRIPT = 200
_MODULE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_PYTHON_RE = re.compile(r"(?:python[0-9.]*|py|pypy[0-9]*)")
_PROGRAM_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+\-]{0,63}")
#: `pkg`, `@scope/pkg@^1.2.0`, `pkg==1.2.3`, `pkg[extra]>=1,<2`
_SPEC_RE = re.compile(r"[A-Za-z0-9@][A-Za-z0-9_.@/+=<>!~^*,\[\]\-]{0,119}")
#: A command that is one path with spaces in it (C:\Program Files\...\node.exe)
#: and not a command line.
_SPACED_PATH_RE = re.compile(r"(?:[A-Za-z]:)?[\\/][^\r\n]*\.(?:exe|cmd|bat|com)",
                             re.IGNORECASE)


def summary(cfg) -> str:
    """One line that says what the entry runs: `npx some-server@1.2.3 (+3
    arguments not shown)`, `curl (+4 arguments not shown); URL:
    https://evil.example/...`. Never contains an argument as written, and
    never raises."""
    try:
        return _cut(_summary(cfg))
    except Exception:  # display only: never let it take a report down
        return "<unprintable>"


def _cut(line: str) -> str:
    return line if len(line) <= _LIMIT else line[:_LIMIT - 3] + "..."


def _words(cfg: dict) -> "tuple[str, list[str]]":
    """(the command, the arguments after it). A `command` that holds a whole
    command line is split into its program and the arguments it carries."""
    command = cfg.get("command")
    command = command.strip() if isinstance(command, str) else ""
    args = cfg.get("args")
    args = [str(a) for a in args] if isinstance(args, list) else []
    if re.search(r"\s", command) and not _SPACED_PATH_RE.fullmatch(command):
        first, *rest = command.split()
        return first, rest + args
    return command, args


def _name(word: str) -> str:
    """The program name of a word, or a placeholder when it is not a plain
    name."""
    name = detectors._prog_name(word)
    return name if _PROGRAM_RE.fullmatch(name) else "<command>"


def _target(program: str, args: "list[str]"
            ) -> "tuple[str, list[str]] | None":
    """(what to show, the arguments it is made of) for the package, module or
    script a launch starts, if it is plainly one. A package that follows an
    option mcp-gradecard does not know could be that option's value, a credential
    perhaps: it is not shown ("(package not shown)", made of no argument)."""
    unsure = False
    for package in detectors._packages_of(program, args):
        if not package.sure:
            unsure = True
        elif _SPEC_RE.fullmatch(package.spec):
            return package.spec, [package.spec]
    if _PYTHON_RE.fullmatch(program):
        for i, arg in enumerate(args[:-1]):
            if arg == "-m":
                if _MODULE_RE.fullmatch(args[i + 1]):
                    return "-m " + args[i + 1], [arg, args[i + 1]]
                break
    for arg in args:
        if (not arg.startswith("-") and len(arg) <= _MAX_SCRIPT
                and _SCRIPT_RE.fullmatch(arg)):
            return arg, [arg]
    return ("(package not shown)", []) if unsure else None


def _url_text(raw: str) -> str:
    try:
        parsed = urls.parse(raw)
    except urls.UnparseableUrl:
        return "<unparseable URL>"
    if not parsed.readings:
        return "<URL>"
    return detectors._shown(parsed, list(parsed.readings))


def _urls_in(words: "list[str]") -> "list[str]":
    found: "list[str]" = []
    for word in words:
        for m in detectors.URL_RE.finditer(word):
            text = _url_text(m.group(0).rstrip(".,;)"))
            if text not in found:
                found.append(text)
    return found


def _summary(cfg) -> str:
    if not isinstance(cfg, dict):
        return "<not a command>"
    command, words = _words(cfg)
    if not command:
        remote = detectors.remote_urls(cfg)
        if remote:
            return "remote server " + _url_text(remote[0][1])
        return "<no command>"
    own = _name(command)
    try:
        launches = detectors._scan_launch(
            {"command": command, "args": words}).launches
    except detectors._TooComplex:
        launches = []
    spliced, _ = detectors._script_urls({"command": command, "args": words})
    launches = launches or [(own, words)]
    program, largs = launches[0]
    shown = None
    for name, args in launches:
        found = _target(name, args)
        if found:
            program, shown = name, found
            break
    program = program if _PROGRAM_RE.fullmatch(program) else "<command>"

    # arguments that are printed (as the target, or as the program's name)
    # are not "not shown"
    printed = list(shown[1]) if shown else []
    program_is_an_argument = program != own
    hidden = 0
    for word in words:
        if word in printed:
            printed.remove(word)
        elif program_is_an_argument and detectors._prog_name(word) == program:
            program_is_an_argument = False
        else:
            hidden += 1

    line = program + (" " + shown[0] if shown else "")
    if program != own:
        line += " via " + own
    if hidden:
        line += " (+%d argument%s not shown)" % (hidden,
                                                  "" if hidden == 1 else "s")
    links = _urls_in(words + [command] + spliced)
    if links:
        more = len(links) - _MAX_URLS
        line += "; URL%s: %s%s" % (
            "" if len(links) == 1 else "s", ", ".join(links[:_MAX_URLS]),
            " (+%d more)" % more if more > 0 else "")
    return line
