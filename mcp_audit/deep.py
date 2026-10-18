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
  and the whole tree is killed when the probe ends, however it ends;
* its output is read by a thread in raw chunks, with a cap on the length of a
  line and on the total, and only well-formed JSON-RPC responses are kept;
* it gets a minimal environment (PATH, HOME and the like) plus the `env` of
  its own config entry - not the secrets of the shell that ran mcp-audit.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import signal
import subprocess
import threading
import time

from . import __version__

# (regex, label, severity). The base64-blob pattern is a regex-only
# heuristic: a long blob can be a legit example key or PEM block, so it is
# capped at "high" with a manual-review note and can never trigger --fix
# removal on its own. Explicit injection phrasings stay critical.
INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
     "tells the agent to ignore previous instructions", "critical"),
    (re.compile(r"disregard\s+(all\s+)?(prior|previous|your)\s+instructions", re.I),
     "tells the agent to disregard instructions", "critical"),
    (re.compile(r"override\s+your\s+(system\s+)?instructions", re.I),
     "tells the agent to override its instructions", "critical"),
    (re.compile(r"reveal\s+(your\s+)?system\s+prompt", re.I),
     "asks the agent to reveal its system prompt", "critical"),
    (re.compile(r"do\s+not\s+tell\s+the\s+user", re.I),
     "instructs the agent to hide behavior from the user", "critical"),
    (re.compile(r"hide\s+from\s+the\s+user", re.I),
     "instructs the agent to hide behavior from the user", "critical"),
    (re.compile(r"send\s+(this|the|your)\s+\w*\s*to\s+https?://", re.I),
     "instructs the agent to send data to a URL", "critical"),
    (re.compile(r"exfiltrat", re.I),
     "mentions exfiltration", "critical"),
    (re.compile(r"you\s+must\s+always", re.I),
     "imperative override phrasing ('you must always')", "critical"),
    (re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"),
     "contains a long base64-looking blob", "high"),
]

HEURISTIC_NOTE = "manual review required — heuristic match only"

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
    hits = []
    for rx, label, _severity in INJECTION_PATTERNS:
        if rx.search(text or ""):
            hits.append(label)
    return hits


def not_launchable(cfg) -> str | None:
    """Why a server entry cannot be probed over stdio, or None when it can."""
    if not isinstance(cfg, dict):
        return "the entry is not an object; not launched"
    if cfg.get("url") or not cfg.get("command"):
        return "remote or command-less server; stdio probe skipped"
    args, env = cfg.get("args"), cfg.get("env")
    if (not isinstance(cfg["command"], str)
            or not (args is None or isinstance(args, list))
            or not (env is None or isinstance(env, dict))):
        return "the entry is malformed (see invalid-config); not launched"
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


def _converse(proc, reader: _Reader, deadline: float, timeout: float) -> dict:
    """The handshake and tools/list on a running server."""
    _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "mcp-audit",
                                           "version": __version__}}})
    if "error" in _await(reader, 1, deadline, timeout):
        raise _Fail("initialize handshake failed")
    _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    tools: list[dict] = []
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
            if isinstance(tool, dict):
                tools.append({"name": _text(tool.get("name")),
                              "description": _text(tool.get("description"))})
            else:  # not a tool object: still scan whatever it says
                tools.append({"name": "", "description": _text(tool)})
        cursor = result.get("nextCursor")
        if note or not isinstance(cursor, str) or not cursor:
            break
    else:
        note = f"the tool list has more than {MAX_PAGES} pages; the rest " \
               "were not scanned"
    return {"ok": True, "tools": tools, "error": note}


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


def _probe(cfg: dict, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    # Windows: "npx" is really npx.cmd - resolve it via PATH/PATHEXT first.
    argv = [shutil.which(cfg["command"]) or cfg["command"]]
    argv += [str(a) for a in cfg.get("args") or []]
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, env=child_env(cfg),
            **_group_kwargs())
    except (OSError, ValueError) as e:
        return _failure("launch failed (%s)" % (
            getattr(e, "strerror", None) or type(e).__name__))
    reader = _Reader(proc.stdout)
    reader.start()
    try:
        return _converse(proc, reader, deadline, timeout)
    except _Fail as e:
        return _failure(str(e))
    finally:
        _stop(proc, reader)


def probe_server(cfg, timeout: float = 15) -> dict:
    """Handshake + tools/list. Returns {"ok", "tools":[{name, description}],
    "error"}; never raises. `error` is set when the probe failed and also,
    with ok True, when only part of the tools could be scanned.

    The whole probe - launch, handshake, every tools/list page - has one
    deadline of `timeout` seconds, enforced from outside the server: a
    silent, wedged or malicious server (or a grandchild that keeps its pipes
    open) cannot hold the probe, or CI, past it."""
    reason = not_launchable(cfg)
    if reason:
        return _failure(reason)
    try:
        return _probe(cfg, timeout)
    except Exception as e:  # the contract is "never raises"
        return _failure(f"probe failed ({type(e).__name__})")


def audit_descriptions(tools: list[dict]) -> list[dict]:
    findings = []
    for t in tools:
        text = t.get("description") or ""
        name = str(t.get("name"))[:_NAME_SHOWN]
        for rx, label, severity in INJECTION_PATTERNS:
            if rx.search(text):
                message = f"tool '{name}' description {label}"
                if severity != "critical":
                    # Regex-only heuristic: never auto-removable (--fix only
                    # acts on criticals), always flagged for manual review.
                    message += f" — {HEURISTIC_NOTE}"
                findings.append({
                    "severity": severity,
                    "check": "tool-description-injection",
                    "message": message,
                })
    return findings
