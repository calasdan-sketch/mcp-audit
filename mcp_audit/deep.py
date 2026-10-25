"""Deep probe (--deep): actually speak MCP to each server and read its tools.

Launches the server over stdio, runs the initialize handshake, lists its
tools (following pagination) and scans the descriptions for prompt-injection
patterns.

This EXECUTES the server, with the rights of whoever runs mcp-audit. It is
opt-in (--deep); the CLI lists what it is about to launch before it launches
anything, and leaves out servers that have critical static findings unless
--probe-critical says otherwise. What bounds a probe:

* one deadline for the whole probe, enforced here whatever the server (or a
  process it started) does with its pipes;
* the server starts in its own session (POSIX) or process group (Windows)
  and the whole tree is killed when the probe ends, however it ends - a
  signal that ends mcp-audit itself (Ctrl-C, SIGTERM, SIGHUP) included: see
  stop_on_signals;
* it starts in an empty directory of its own (private, in the temp directory,
  removed afterwards) unless the caller names one, and its program is looked
  up on PATH only: see _find_program. The directory mcp-audit was run from
  is the one a clone you are auditing fills, and the one Windows searches
  first - without this, --deep run there would run the clone's files through
  your own servers (a node_modules copy for `npx -y @acme/mcp-thing`);
* its output is read by a thread in raw chunks, with a cap on the length of a
  line and on the total, and only well-formed JSON-RPC responses are kept;
* it gets a minimal environment (PATH, HOME and the like) plus the `env` of
  its own config entry - not the secrets of the shell that ran mcp-audit.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import os
import queue
import shutil
import signal
import subprocess
import tempfile
import threading
import time

from . import __version__
from .detectors import remote_urls
from .scoring import DESCRIPTION_CHECK

#: Added to every finding that is not critical: the scanner matches patterns,
#: it does not understand the text (see poisoning.py for what it looks for).
HEURISTIC_NOTE = "manual review required — heuristic match only"

#: What a critical match says in its place: it is no proof either, and a tool
#: that only quotes an attack - a scanner for prompt injection - matches too.
CRITICAL_NOTE = ("manual review advised \u2014 heuristic match; a tool that "
                 "only quotes an attack matches too")

#: What reading one server's descriptions may cost: each text counts its
#: length and _TEXT_COST more. Fifty tools send some 25,000 characters, two
#: thousand some 2,000,000 - the most this reads (a few seconds); what is left
#: is reported as unread, never passed. At most MAX_LISTED findings are listed
#: per server; any others are counted in one more.
MAX_SCANNED = 2_000_000
_TEXT_COST = 20
MAX_LISTED = 100

#: A line of server output longer than this, or more output than this in
#: total, ends the probe and kills the server. (A tools/list answer for a big
#: server is a few hundred KB; a runaway server wrote 4 GB in 9 seconds.)
MAX_LINE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
#: Tools scanned per server, and tools/list pages followed.
MAX_TOOLS = 2000
MAX_PAGES = 100
#: Characters of a tool name shown in a finding (the name comes from the
#: server).
_NAME_SHOWN = 80

# Windows is a flag, not a check at each use, so the tests can walk the
# Windows branches on any machine.
_IS_WINDOWS = os.name == "nt"

# What a launched server inherits from the environment of mcp-audit: the
# variables MCP's own client SDKs pass, plus the locale and temp directory.
# Everything else - API keys, tokens, proxy URLs with passwords - stays out;
# a server that needs a variable gets it from `env` in its config entry.
_KEEP_ENV_POSIX = frozenset(("HOME", "LOGNAME", "PATH", "SHELL", "TERM",
                             "USER", "LANG", "LC_ALL", "TMPDIR"))
_KEEP_ENV_WINDOWS = frozenset((
    "APPDATA", "COMSPEC", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH",
    "PATHEXT", "PROCESSOR_ARCHITECTURE", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP",
    "TMP", "USERNAME", "USERPROFILE", "WINDIR"))


def scan_description(text: str) -> list[str]:
    """What a description says that a reader should not accept, in words (an
    empty list when nothing adds up to a finding)."""
    from . import poisoning     # not imported by a run that never goes deep
    verdict = poisoning.scan(text or "")
    return list(verdict.labels) if verdict else []


def not_launchable(cfg) -> str | None:
    """Why a server entry cannot be probed over stdio, or None when it can."""
    if not isinstance(cfg, dict):
        return "the entry is not an object; not launched"
    if remote_urls(cfg) or not cfg.get("command"):
        return "remote or command-less server; stdio probe skipped"
    args, env = cfg.get("args"), cfg.get("env")
    if (not isinstance(cfg["command"], str)
            or not (args is None or isinstance(args, list))
            or not (env is None or isinstance(env, dict))):
        return "the entry is malformed (see invalid-config); not launched"
    return None


#: What Windows runs when it finds no PATHEXT.
_WINDOWS_PATHEXT = ".COM;.EXE;.BAT;.CMD"


def _same_place(a: str, b: str) -> bool:
    """True when two paths are one directory: links followed, and the case
    ignored where the file system ignores it."""
    return (os.path.normcase(os.path.realpath(a))
            == os.path.normcase(os.path.realpath(b)))


def _find_program(name: str, path: str, windows: bool | None = None,
                  pathext: str | None = None, avoid=()) -> str | None:
    """The file that the bare `name` stands for on `path` (the value of a
    PATH variable), or None.

    shutil.which would find a file in the current directory first on Windows
    (by default, in every Python up to 3.14), where CreateProcess searches it
    first too, and an empty or relative entry of PATH means the current
    directory on POSIX.
    What a server runs must not depend on where mcp-audit was started, so
    only absolute entries count, and not the directories in `avoid` (the one
    mcp-audit was run from, the one the server starts in) even when PATH
    names them.

    Windows (`windows`): the extensions of `pathext` are tried in order, a
    file without one is no program (npm leaves a shell script called `npx`
    beside npx.cmd), and the quotes Windows allows around an entry go.
    Elsewhere the file must be executable."""
    windows = _IS_WINDOWS if windows is None else windows
    names = [name]
    if windows:
        extensions = [e for e in (pathext or _WINDOWS_PATHEXT).split(";") if e]
        if not any(name.lower().endswith(e.lower()) for e in extensions):
            names = [name + e for e in extensions]
    for entry in path.split(os.pathsep):
        if windows:
            entry = entry.strip().strip('"')
        if not entry or not os.path.isabs(entry):
            continue
        if any(_same_place(entry, place) for place in avoid):
            continue
        for candidate in names:
            full = os.path.join(entry, candidate)
            if os.path.isfile(full) and (windows or os.access(full, os.X_OK)):
                return full
    return None


def _program(command: str, env: dict, start: str,
             windows: bool | None = None) -> str | None:
    """The file to run for the `command` of a config entry, or None when a
    bare name is nowhere on the PATH of `env`.

    A path is used as written; a relative one is taken from `start`, the
    directory the server starts in, on every system (Popen would take it from
    there on POSIX but from our own directory on Windows). A bare name is
    looked up by _find_program, never in `start` or in the current
    directory."""
    windows = _IS_WINDOWS if windows is None else windows
    if os.path.isabs(command):
        return command
    if os.sep in command or (os.altsep and os.altsep in command):
        return os.path.join(start, command)

    def variable(name):
        value = None
        for key, found in env.items():
            if (key.upper() if windows else key) == name:
                value = found
        return value

    path = variable("PATH")
    avoid = [start]
    try:
        avoid.append(os.getcwd())
    except OSError:     # the directory was removed from under us
        pass
    return _find_program(
        command, os.defpath if path is None else path, windows=windows,
        pathext=variable("PATHEXT") or os.environ.get("PATHEXT"), avoid=avoid)


def switched_off(cfg) -> str | None:
    """How a server entry says its client should not start it - `"disabled":
    true` or `"enabled": false` - or None. Only a JSON boolean counts: any
    other value is not a switch that mcp-audit can say it understands. Which
    clients write these keys is unverified."""
    if isinstance(cfg, dict):
        if cfg.get("disabled") is True:
            return '"disabled": true'
        if cfg.get("enabled") is False:
            return '"enabled": false'
    return None


def child_env(cfg: dict) -> dict:
    """The environment a probed server gets: the kept variables of this
    process (see _KEEP_ENV_*) with the server's own `env` on top."""
    keep = _KEEP_ENV_WINDOWS if _IS_WINDOWS else _KEEP_ENV_POSIX
    env = {k: v for k, v in os.environ.items()
           if (k.upper() if _IS_WINDOWS else k) in keep}
    own = cfg.get("env")
    if isinstance(own, dict):
        env.update({str(k): str(v) for k, v in own.items() if v is not None})
    return env


def _group_kwargs() -> dict:
    """Popen arguments that make the server the leader of its own session
    (POSIX) or process group (Windows), so the whole tree can be killed."""
    if _IS_WINDOWS:
        return {"creationflags":
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)}
    return {"start_new_session": True}


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the server and everything it started. POSIX: SIGKILL to its
    process group. Windows: `taskkill /T /F`, which follows the parent chain
    (killing only the shell shim would orphan npx's node). Never raises."""
    if _IS_WINDOWS:
        try:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(proc.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
        except OSError:  # nothing of the group is left
            pass
    try:
        proc.kill()
    except OSError:
        pass


class _Fail(Exception):
    """The probe cannot go on; the message is the reason, and is printable
    (it never quotes the server)."""


# Queue items other than responses.
_EOF = object()
_LINE_TOO_LONG = object()
_TOO_MUCH = object()


def _response(line: bytes):
    """The JSON-RPC response in a line of server output, or None for anything
    else: a log line, a notification, a request."""
    if not line.lstrip().startswith(b"{"):
        return None
    try:
        msg = json.loads(line.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return None
    if isinstance(msg, dict) and "id" in msg and (
            "result" in msg or "error" in msg):
        return msg
    return None


class _Reader(threading.Thread):
    """Reads the server's stdout in raw chunks so that nothing the server
    does can block the prober, and puts its JSON-RPC responses on a queue.
    It is a daemon that owns the stream: the prober never closes a pipe
    another thread is blocked on (that wedged the old probe for as long as a
    grandchild that had escaped the process group kept the pipe open)."""

    def __init__(self, stream) -> None:
        super().__init__(name="mcp-audit-reader", daemon=True)
        self._stream = stream
        self.messages: queue.Queue = queue.Queue()

    def run(self) -> None:
        try:
            self._pump()
        except Exception:  # whatever went wrong, the stream is over
            pass
        finally:
            self.messages.put(_EOF)
            try:
                self._stream.close()
            except Exception:
                pass

    def _pump(self) -> None:
        total = 0
        pending = b""
        while True:
            chunk = self._stream.read(65536)
            if not chunk:
                return
            total += len(chunk)
            if total > MAX_TOTAL_BYTES:
                self.messages.put(_TOO_MUCH)
                return
            *lines, pending = (pending + chunk).split(b"\n")
            for line in lines:
                if len(line) > MAX_LINE_BYTES:
                    self.messages.put(_LINE_TOO_LONG)
                    return
                message = _response(line)
                if message is not None:
                    self.messages.put(message)
            if len(pending) > MAX_LINE_BYTES:
                self.messages.put(_LINE_TOO_LONG)
                return


def _send(proc: subprocess.Popen, message: dict) -> None:
    data = memoryview((json.dumps(message) + "\n").encode("utf-8"))
    try:
        while data:
            written = proc.stdin.write(data)
            if not written:
                raise OSError("short write")
            data = data[written:]
    except (OSError, ValueError):
        raise _Fail("the server closed its input") from None


def _await(reader: _Reader, req_id: int, deadline: float,
           timeout: float) -> dict:
    """The response to `req_id`, or _Fail at the deadline, at the end of the
    server's output, or when it sends too much. Anything else the server
    says is skipped."""
    while True:
        try:
            item = reader.messages.get(
                timeout=max(0.0, deadline - time.monotonic()))
        except queue.Empty:
            raise _Fail(f"probe timed out after {timeout}s; "
                        "server killed") from None
        if item is _EOF:
            raise _Fail("the server exited without answering")
        if item is _LINE_TOO_LONG:
            raise _Fail("the server sent too much output (a line over "
                        f"{MAX_LINE_BYTES} bytes); killed")
        if item is _TOO_MUCH:
            raise _Fail("the server sent too much output (over "
                        f"{MAX_TOTAL_BYTES} bytes in total); killed")
        if item.get("id") == req_id:
            return item


def _text(value) -> str:
    return value if isinstance(value, str) else ("" if value is None
                                                 else str(value))


#: Texts of a tool's input schema that are read, and how far into the schema
#: (a server chooses its schema: it can be deep and wide).
MAX_PARAMETER_TEXTS = 200
MAX_SCHEMA_NODES = 500
MAX_SCHEMA_DEPTH = 8
_SCHEMA_MAPS = ("properties", "patternProperties", "$defs", "definitions",
                "dependentSchemas")
_SCHEMA_NODES = ("items", "additionalProperties", "not", "if", "then", "else",
                 "contains", "propertyNames")
_SCHEMA_LISTS = ("anyOf", "oneOf", "allOf", "prefixItems")


def _parameters(schema) -> list[dict]:
    """The texts of a tool's input schema that an agent reads: the
    description and title of each property, its default and constant, the
    members of its enum, its examples - as {"name": property, "description":
    text}. The agent is told about a parameter in these words as much as in
    the description of the tool."""
    found: list[dict] = []
    stack = [("", schema, 0)]
    nodes = 0
    while stack and nodes < MAX_SCHEMA_NODES \
            and len(found) < MAX_PARAMETER_TEXTS:
        name, node, depth = stack.pop()
        if not isinstance(node, dict):
            continue
        nodes += 1
        texts = [node.get(k) for k in ("description", "title", "default",
                                       "const")]
        for key in ("enum", "examples"):
            if isinstance(node.get(key), list):
                texts += node[key][:20]
        found += [{"name": name, "description": t} for t in texts
                  if isinstance(t, str) and t.strip()]
        if depth >= MAX_SCHEMA_DEPTH:
            continue
        children = []
        for key in _SCHEMA_MAPS:
            if isinstance(node.get(key), dict):
                children += [(str(n)[:_NAME_SHOWN], c) for n, c in
                             itertools.islice(node[key].items(),
                                              MAX_SCHEMA_NODES)]
        for key in _SCHEMA_NODES:
            children.append((name, node.get(key)))
        for key in _SCHEMA_LISTS:
            if isinstance(node.get(key), list):
                children += [(name, c) for c in
                             node[key][:MAX_SCHEMA_NODES]]
        stack += [(n, c, depth + 1) for n, c in reversed(children)]
    return found[:MAX_PARAMETER_TEXTS]


def _server_texts(result) -> dict:
    """What the answer to `initialize` says in words a model may be shown:
    `instructions` (clients put it in the model's prompt) and the title and
    description in `serverInfo` - as {"instructions" | "title" |
    "description": text}, the ones that are non-empty strings."""
    found: dict = {}
    if isinstance(result, dict):
        info = result.get("serverInfo")
        for key, value in (("instructions", result.get("instructions")),
                           ("title", info.get("title")
                            if isinstance(info, dict) else None),
                           ("description", info.get("description")
                            if isinstance(info, dict) else None)):
            if isinstance(value, str) and value.strip():
                found[key] = value
    return found


def _converse(proc, reader: _Reader, deadline: float, timeout: float) -> dict:
    """The handshake and tools/list on a running server."""
    _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "mcp-audit",
                                           "version": __version__}}})
    answer = _await(reader, 1, deadline, timeout)
    if "error" in answer:
        raise _Fail("initialize handshake failed")
    server = _server_texts(answer.get("result"))
    _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    tools: list[dict] = []
    raw: list = []     # the tools as the server sent them (for the lockfile)
    note = None
    cursor = None
    for page in range(MAX_PAGES):
        req_id = 2 + page
        _send(proc, {"jsonrpc": "2.0", "id": req_id, "method": "tools/list",
                     "params": {"cursor": cursor} if cursor else {}})
        response = _await(reader, req_id, deadline, timeout)
        result = response.get("result")
        if "error" in response or not isinstance(result, dict) \
                or not isinstance(result.get("tools"), list):
            if page == 0:
                raise _Fail("tools/list failed")
            note = f"tools/list failed on page {page + 1}; the rest of the " \
                   "tools were not scanned"
            break
        for tool in result["tools"]:
            if len(tools) >= MAX_TOOLS:
                note = f"only the first {MAX_TOOLS} tools were scanned"
                break
            raw.append(tool)
            if isinstance(tool, dict):
                entry = {"name": _text(tool.get("name")),
                         "description": _text(tool.get("description"))}
                if isinstance(tool.get("title"), str) and tool["title"]:
                    entry["title"] = tool["title"]
                annotations = tool.get("annotations")
                if isinstance(annotations, dict) and isinstance(
                        annotations.get("title"), str) \
                        and annotations["title"].strip():
                    entry["annotations_title"] = annotations["title"]
                parameters = _parameters(tool.get("inputSchema"))
                if parameters:
                    entry["parameters"] = parameters
                outputs = _parameters(tool.get("outputSchema"))
                if outputs:
                    entry["outputs"] = outputs
                tools.append(entry)
            else:  # not a tool object: still scan whatever it says
                tools.append({"name": "", "description": _text(tool)})
        cursor = result.get("nextCursor")
        if note or not isinstance(cursor, str) or not cursor:
            break
    else:
        note = f"the tool list has more than {MAX_PAGES} pages; the rest " \
               "were not scanned"
    return {"ok": True, "tools": tools, "server": server, "error": note,
            "raw_tools": raw, "complete": note is None}


def _failure(error: str) -> dict:
    return {"ok": False, "tools": [], "error": error}


def _stop(proc: subprocess.Popen, reader: _Reader) -> None:
    """End the server and its tree, reap it, and let go of its pipes - in a
    bounded time whatever it left behind."""
    _kill_tree(proc)
    try:
        proc.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        proc.stdin.close()
    except (OSError, ValueError):
        pass
    # The reader closes stdout when the pipe ends. If a process that escaped
    # the tree still holds the pipe it never ends: leave the (daemon) reader.
    reader.join(1)


class Interrupted(BaseException):
    """A signal that ends the run (Ctrl-C, SIGTERM, SIGHUP, Ctrl-Break) came
    in during the --deep pass; `signum` is its number. It is not an Exception
    on purpose: probe_server promises never to raise one, and the handlers
    that fail closed around the scanner would take this for a failure to read
    and carry on."""

    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


class _State:
    """What the signal handler has to know. It runs between two lines of
    whatever the main thread was doing, so it takes no lock, prints nothing
    and keeps to plain attributes."""

    def __init__(self) -> None:
        #: the servers that are running (started, not yet stopped)
        self.procs: set = set()
        #: True while a server is being started: it is not known yet
        self.launching = False
        #: a signal that came in meanwhile (see _on_signal)
        self.pending: int | None = None


_STATE = _State()


def _available(module=signal) -> tuple:
    """The signals that end a run, on this platform: Ctrl-C and SIGTERM
    everywhere there is one, SIGHUP (the terminal closed) on POSIX, SIGBREAK
    (Ctrl-Break) on Windows."""
    return tuple(getattr(module, name)
                 for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK")
                 if hasattr(module, name))


def _on_signal(signum, frame) -> None:
    """Stop every server that is running, then end the pass: Interrupted is
    raised in the main thread, from wherever it was.

    A signal that comes in while a server is being started is only noted
    (the server cannot be stopped before it is known: Popen has not returned
    yet), and _probe acts on it the moment it is."""
    if _STATE.launching:
        _STATE.pending = signum
        return
    for proc in list(_STATE.procs):
        _kill_tree(proc)
    raise Interrupted(signum)


@contextlib.contextmanager
def stop_on_signals():
    """While the body runs, a signal that ends a process stops the servers
    first and ends the pass with Interrupted (see _on_signal). Servers are in
    their own session, so the Ctrl-C of a terminal, a `kill` and a SIGHUP do
    not reach them: without this they ended mcp-audit and left the servers
    running.

    The handlers that were there are put back afterwards. A signal that was
    being ignored stays ignored (`nohup mcp-audit --deep &` ignores SIGHUP on
    purpose). Only the main thread can install a handler: anywhere else this
    does nothing."""
    saved = {}
    for signum in _available():
        try:
            if signal.getsignal(signum) == signal.SIG_IGN:
                continue
            saved[signum] = signal.signal(signum, _on_signal)
        except (OSError, ValueError):   # ValueError: not the main thread
            continue
    try:
        yield
    finally:
        for signum, handler in saved.items():
            try:
                # None: the old handler was not Python's, and cannot be put
                # back by name; the default is the closest there is
                signal.signal(signum, signal.SIG_DFL if handler is None
                              else handler)
            except (OSError, ValueError):
                pass


def _probe(cfg: dict, timeout: float, cwd: str) -> dict:
    deadline = time.monotonic() + timeout
    env = child_env(cfg)
    # Windows: "npx" is really npx.cmd - found through PATH and PATHEXT.
    program = _program(cfg["command"], env, cwd)
    if program is None:
        return _failure("launch failed (program not found on PATH)")
    argv = [program] + [str(a) for a in cfg.get("args") or []]
    _STATE.launching = True
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, env=env, cwd=cwd,
            **_group_kwargs())
        _STATE.procs.add(proc)
        error = None
    except (OSError, ValueError) as e:
        proc, error = None, e
    finally:
        _STATE.launching = False
    held, _STATE.pending = _STATE.pending, None
    if proc is None:
        if held is not None:
            raise Interrupted(held)
        return _failure("launch failed (%s)" % (
            getattr(error, "strerror", None) or type(error).__name__))
    reader = _Reader(proc.stdout)
    try:
        reader.start()
        if held is not None:    # it came in while the server was starting
            raise Interrupted(held)
        return _converse(proc, reader, deadline, timeout)
    except _Fail as e:
        return _failure(str(e))
    finally:
        try:
            _stop(proc, reader)
        finally:
            _STATE.procs.discard(proc)


def probe_server(cfg, timeout: float = 15, cwd: str | None = None) -> dict:
    """Handshake + tools/list. Returns {"ok", "tools":[{name, description}],
    "error"}; never raises an Exception (Interrupted, which is not one, ends
    the pass: see stop_on_signals). `error` is set when the probe failed and
    also, with ok True, when only part of the tools could be scanned.

    The whole probe - launch, handshake, every tools/list page - has one
    deadline of `timeout` seconds, enforced from outside the server: a
    silent, wedged or malicious server (or a grandchild that keeps its pipes
    open) cannot hold the probe, or CI, past it.

    The server starts in `cwd` when one is given (and that directory is left
    as it is), else in a new empty directory that is private to this user and
    removed when the probe ends, however it ends: the directory mcp-audit was
    run from is not the server's to use (see the top of this module)."""
    reason = not_launchable(cfg)
    if reason:
        return _failure(reason)
    if switched_off(cfg):
        return _failure(f"disabled in its config ({switched_off(cfg)}); "
                        "not launched")
    scratch = None
    try:
        if cwd is None:
            try:
                scratch = tempfile.mkdtemp(prefix="mcp-audit-")
            except OSError:
                return _failure("launch failed (no directory to start it in)")
            cwd = scratch
        return _probe(cfg, timeout, cwd)
    except Exception as e:  # the contract is "never raises"
        return _failure(f"probe failed ({type(e).__name__})")
    finally:
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)


def _texts(tool: dict):
    """(where, text) for every text of a tool that is read: its description,
    its title and the title in its annotations, then each text of its input
    schema and of its output schema."""
    yield "description", tool.get("description")
    if tool.get("title"):
        yield "title", tool.get("title")
    if tool.get("annotations_title"):
        yield "annotations title", tool.get("annotations_title")
    for parameter in tool.get("parameters") or ():
        name = str(parameter.get("name"))[:_NAME_SHOWN]
        yield (f"parameter '{name}' description" if name
               else "input schema description"), parameter.get("description")
    for output in tool.get("outputs") or ():
        name = str(output.get("name"))[:_NAME_SHOWN]
        yield (f"output '{name}' description" if name
               else "output schema description"), output.get("description")


def _all_texts(tools: list[dict], server: dict | None):
    """(subject, where, text) for every text that is read: what the server
    says about itself (`instructions` first: a client puts it in the model's
    prompt), then the texts of each tool."""
    for key in ("instructions", "title", "description"):
        if isinstance((server or {}).get(key), str):
            yield "server", key, server[key]
    for t in tools:
        subject = f"tool '{str(t.get('name'))[:_NAME_SHOWN]}'"
        for where, text in _texts(t):
            yield subject, where, text


_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def audit_descriptions(tools: list[dict],
                       server: dict | None = None) -> list[dict]:
    """The findings about what a server and its tools say about themselves:
    one per text that adds up to something (see poisoning.scan), with the
    signals in words and never the text. `server` is probe_server's "server"
    entry: the instructions and the title and description from initialize. A
    text that cannot be scanned is a high finding, not a pass. The server
    chooses how much it sends, so reading is bounded: past MAX_SCANNED the
    texts are counted as unread (a medium finding), and past MAX_LISTED the
    findings are counted, not listed."""
    from . import poisoning     # not imported by a run that never goes deep
    findings: list[dict] = []
    spent = unread = unlisted = 0
    worst = "low"
    for subject, where, text in _all_texts(tools, server):
        if spent >= MAX_SCANNED:
            unread += 1
            continue
        spent += _TEXT_COST + (len(text) if isinstance(text, str) else 0)
        try:
            verdict = poisoning.scan(text)
        except Exception as e:  # fail closed: unread is not clean
            severity = "high"
            message = (f"{subject} {where} could not be scanned "
                       f"({type(e).__name__}) — {HEURISTIC_NOTE}")
        else:
            if verdict is None:
                continue
            severity = verdict.severity
            message = f"{subject} {where} " + "; ".join(verdict.labels)
            # Heuristic: never auto-removable (--fix only acts on
            # launch-time attacks), always flagged for manual review.
            if severity != "critical":
                message += f" \u2014 {HEURISTIC_NOTE}"
            else:
                message += f" \u2014 {CRITICAL_NOTE}"
        if len(findings) >= MAX_LISTED:
            unlisted += 1
            if _RANK[severity] > _RANK[worst]:
                worst = severity
            continue
        findings.append({"severity": severity, "check": DESCRIPTION_CHECK,
                         "message": message})
    if unlisted:
        findings.append({
            "severity": worst, "check": DESCRIPTION_CHECK,
            "message": f"{unlisted} more tool texts matched too; only the "
                       f"first {MAX_LISTED} findings are listed \u2014 "
                       + (CRITICAL_NOTE if worst == "critical"
                          else HEURISTIC_NOTE)})
    if unread:
        findings.append({
            "severity": "medium", "check": DESCRIPTION_CHECK,
            "message": f"{unread} more tool texts were not scanned: this "
                       "server describes its tools in more text than is read "
                       f"(about {MAX_SCANNED} characters per server) — "
                       f"{HEURISTIC_NOTE}"})
    return findings
