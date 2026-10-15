"""Deep probe (--deep): actually speak MCP to each server and read its tools.

Spawns the server over stdio, runs the initialize handshake, calls
tools/list, and scans tool descriptions for prompt-injection patterns.

This EXECUTES the server binary, so it is opt-in only (--deep) and each
probe runs under a timeout. Never run --deep against a server you have
not already decided to trust at least enough to launch.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading

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


def scan_description(text: str) -> list[str]:
    hits = []
    for rx, label, _severity in INJECTION_PATTERNS:
        if rx.search(text or ""):
            hits.append(label)
    return hits


def _rpc(proc: subprocess.Popen, method: str, params: dict,
         req_id: int) -> dict | None:
    req = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    try:
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        return json.loads(line) if line else None
    except (OSError, ValueError):
        return None


def _kill_proc_tree(proc: subprocess.Popen) -> None:
    """SIGKILL the child and its process group (POSIX), close its pipes."""
    try:
        if os.name == "posix":
            # start_new_session=True makes the child a process-group leader
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (OSError, ProcessLookupError):
        pass
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if stream is not None:
                stream.close()
        except OSError:
            pass
    try:
        proc.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _probe_once(cfg: dict, box: dict) -> dict:
    """Blocking handshake + tools/list. Runs inside the watchdog thread."""
    cmd = [str(cfg.get("command") or "")]
    cmd += [str(a) for a in (cfg.get("args") or [])]
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
            env={**os.environ, **cfg["env"]} if cfg.get("env") else None,
            start_new_session=True,
        )
    except (OSError, ValueError) as e:
        return {"ok": False, "tools": [], "error": f"launch failed: {e}"}
    box["proc"] = proc  # lets the watchdog kill it on timeout
    try:
        init = _rpc(proc, "initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-audit", "version": "0.1.0"},
        }, 1)
        if not init or "error" in init:
            return {"ok": False, "tools": [],
                    "error": "initialize handshake failed"}
        try:
            proc.stdin.write(json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()
        except OSError:
            pass
        resp = _rpc(proc, "tools/list", {}, 2)
        tools = []
        if resp and isinstance(resp.get("result"), dict):
            for t in resp["result"].get("tools", []):
                tools.append({"name": t.get("name", ""),
                              "description": t.get("description", "")})
        return {"ok": True, "tools": tools, "error": None}
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass


def probe_server(cfg: dict, timeout: int = 15) -> dict:
    """Handshake + tools/list. Returns {"ok", "tools":[{name, description}],
    "error"} — never raises.

    The timeout is enforced by a watchdog thread: the blocking probe runs
    in a worker, and if it has not finished within `timeout` seconds the
    whole child process group is SIGKILLed and a timeout error is returned.
    A malicious or wedged server can therefore never hang the probe (or CI).
    """
    cmd = [str(cfg.get("command") or "")]
    if not cmd[0] or cfg.get("url"):
        return {"ok": False, "tools": [],
                "error": "remote or command-less server; stdio probe skipped"}

    box: dict = {}

    def _run() -> None:
        try:
            box["result"] = _probe_once(cfg, box)
        except Exception as e:  # the watchdog thread must never die loudly
            box.setdefault("result", {"ok": False, "tools": [],
                                      "error": f"probe failed: {e}"})

    worker = threading.Thread(target=_run, daemon=True,
                              name="mcp-audit-probe")
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        # Timed out: kill the child (and its group) so the blocked read
        # unwinds, then report the timeout instead of hanging.
        proc = box.get("proc")
        if proc is not None:
            _kill_proc_tree(proc)
        worker.join(5)
        return {"ok": False, "tools": [],
                "error": f"probe timed out after {timeout}s; server killed"}
    return box.get("result", {"ok": False, "tools": [],
                              "error": "probe produced no result"})


def audit_descriptions(tools: list[dict]) -> list[dict]:
    findings = []
    for t in tools:
        text = t.get("description") or ""
        for rx, label, severity in INJECTION_PATTERNS:
            if rx.search(text):
                message = f"tool '{t.get('name')}' description {label}"
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
