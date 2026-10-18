"""Shared helpers for the test-suite (not a test module).

Everything here is hermetic: temp directories only, and default discovery
never sees the real machine (see isolated_machine).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest.mock

from mcp_audit import cli as cli_mod
from mcp_audit import discovery

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# Environment variables the default discovery paths may consult.
_PATH_ENV = ("XDG_CONFIG_HOME", "COPILOT_HOME")


def write_json(path: str, data) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return path


def write_text(path: str, text: str, encoding: str = "utf-8") -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding=encoding, newline="") as f:
        f.write(text)
    return path


def write_bytes(path: str, data: bytes) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


@contextlib.contextmanager
def isolated_machine():
    """Fake home, AppData and cwd so default discovery sees only what the
    test plants - on every OS and whatever the developer's own environment.

    Sets the documented MCP_AUDIT_HOME override plus HOME, USERPROFILE,
    APPDATA and LOCALAPPDATA, drops XDG_CONFIG_HOME and COPILOT_HOME, and
    points cwd at a second empty directory. Yields (home, cwd).
    """
    root = tempfile.mkdtemp()
    home = os.path.join(root, "home")
    cwd = os.path.join(root, "cwd")
    appdata = os.path.join(home, "AppData", "Roaming")
    local_appdata = os.path.join(home, "AppData", "Local")
    for d in (home, cwd, appdata, local_appdata):
        os.makedirs(d)
    env = {discovery.HOME_ENV: home, "HOME": home, "USERPROFILE": home,
           "APPDATA": appdata, "LOCALAPPDATA": local_appdata}
    try:
        with unittest.mock.patch.dict(os.environ, env), \
                unittest.mock.patch("os.getcwd", return_value=cwd):
            for name in _PATH_ENV:
                os.environ.pop(name, None)
            yield home, cwd
    finally:
        shutil.rmtree(root, ignore_errors=True)


def client_path(client: str) -> str:
    """Where default discovery would look for `client` right now (its first
    candidate), so tests plant fixtures at the platform's real location."""
    return [p for c, p in discovery.candidate_paths() if c == client][0]


def run_cli(*argv, stdin_tty: bool = False, stdin_text: str = ""):
    """Run the CLI in-process -> (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    stdin = io.StringIO(stdin_text)
    stdin.isatty = lambda: stdin_tty  # type: ignore[method-assign]
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            unittest.mock.patch("sys.stdin", stdin):
        code = cli_mod.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def run_all_formats(*argv):
    """The same audit in human, JSON and SARIF -> {format: (code, out, err)}."""
    return {fmt: run_cli(*argv, "--format", fmt)
            for fmt in ("human", "json", "sarif")}
