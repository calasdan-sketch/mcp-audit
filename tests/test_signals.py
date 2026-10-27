"""A signal that ends mcp-audit during --deep ends the servers too (Round 2 #5).

The README says the server's whole process tree is killed "however the probe
ends". SIGTERM and SIGHUP ended mcp-audit on the spot, with the servers it had
launched left running, and Ctrl-C ended it with a traceback. Now the signals
that end the process stop the servers first, and the exit code is 128 plus the
signal number, as a shell reports it.
"""

import errno
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import unittest.mock

from mcp_audit import cli as cli_mod
from mcp_audit import deep as deep_mod

from _support import FIX, isolated_machine, run_cli, write_json
from test_deep_probe import alive, wait_dead

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(ROOT, "README.md")
POSIX = os.name == "posix"


def fixture(name):
    return os.path.join(FIX, name)


def wait_for(path, seconds=20.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            with open(path) as f:
                text = f.read()
            if text:
                return text
        except OSError:
            pass
        time.sleep(0.05)
    return None


def _default_signals():
    """Runs in the child before exec (POSIX): Ctrl-C, SIGHUP and SIGTERM act
    as they do for a program started from a terminal. A test runner that was
    itself started as a background job (`cmd &`) or under nohup hands
    "ignored" down for some of them, and a Python that inherits SIGINT
    ignored never turns Ctrl-C into KeyboardInterrupt."""
    for name in ("SIGINT", "SIGQUIT", "SIGHUP", "SIGTERM"):
        signal.signal(getattr(signal, name), signal.SIG_DFL)


@unittest.skipUnless(POSIX, "SIGTERM and SIGHUP end a process on POSIX only; "
                     "the Windows signals are covered by the tests of which "
                     "signals are taken and by the README's note that the "
                     "taskkill path is unverified")
class TestARealRun(unittest.TestCase):
    """mcp-audit as a process, a server that never answers and has a child
    in its own process group: the usual shape of `npx` starting `node`."""

    def start(self, name="family_mcp_server.py"):
        """mcp-audit with `name` as its server; (the process, (the server's
        pid, the pid of the process it started))."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, True))
        pidfile = os.path.join(tmp, "child.pid")
        cfg = write_json(os.path.join(tmp, "m.json"), {"mcpServers": {"s": {
            "command": sys.executable,
            "args": [fixture(name), pidfile, "silent"]}}})
        env = {k: v for k, v in os.environ.items()
               if k != "PYTHONUNBUFFERED"}  # buffered, as a user has it
        env["MCP_AUDIT_HOME"] = tmp
        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_audit", "--config", cfg, "--deep",
             "--format", "json"], cwd=ROOT, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, preexec_fn=_default_signals)
        self.addCleanup(self.finish, proc)
        child = wait_for(pidfile)
        server = wait_for(pidfile + ".server")
        self.assertIsNotNone(child, "the server did not start its child")
        self.assertIsNotNone(server, "the server did not start")
        pids = (int(server), int(child))
        self.addCleanup(self.reap, pids)
        for pid in pids:
            self.assertTrue(alive(pid))
        return proc, pids

    @staticmethod
    def finish(proc):
        if proc.poll() is None:
            proc.kill()
        proc.communicate()

    @staticmethod
    def reap(pids):
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass

    def check(self, signum):
        proc, pids = self.start()
        proc.send_signal(signum)
        out, err = proc.communicate(timeout=30)
        text = err.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 128 + signum, text)
        self.assertNotIn("Traceback", text)
        self.assertEqual(out, b"", "a report of a run that was cut short")
        self.assertIn(signal.Signals(signum).name, text)
        self.assertIn("no report", text)
        for pid in pids:
            self.assertTrue(wait_dead(pid), "pid %d outlived mcp-audit" % pid)

    def test_sigterm_stops_the_server_and_its_child(self):
        self.check(signal.SIGTERM)

    def test_sighup_stops_the_server_and_its_child(self):
        self.check(signal.SIGHUP)

    def test_ctrl_c_stops_them_too_and_prints_no_traceback(self):
        self.check(signal.SIGINT)

    def test_an_escaped_grandchild_cannot_hold_mcp_audit_back(self):
        # A process that left the session (setsid) keeps the server's output
        # pipe open. The README says it is not reached; it must not keep the
        # signal from ending the run either.
        proc, (server, grandchild) = self.start("holder_mcp_server.py")
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        out, err = proc.communicate(timeout=30)
        text = err.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 128 + signal.SIGTERM, text)
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(out, b"")
        self.assertTrue(wait_dead(server), "the server outlived mcp-audit")

    def test_a_deep_run_puts_the_handlers_back(self):
        before = {s: signal.getsignal(s) for s in (signal.SIGTERM,
                                                   signal.SIGHUP,
                                                   signal.SIGINT)}
        with isolated_machine() as (home, cwd):
            path = write_json(os.path.join(cwd, "m.json"), {"mcpServers": {
                "a": {"command": "node", "args": ["srv.js"]}}})
            with unittest.mock.patch.object(
                    deep_mod, "probe_server",
                    return_value={"ok": False, "tools": [], "error": "x"}):
                run_cli("--config", path, "--deep", "--format", "json")
        after = {s: signal.getsignal(s) for s in before}
        self.assertEqual(before, after)


class TestTheHandlers(unittest.TestCase):
    def _reset(self):
        # state a handler test leaves behind must not reach the next one
        deep_mod._STATE.stopping = False
        deep_mod._STATE.starting = 0
        deep_mod._STATE.launching = False
        deep_mod._STATE.pending = None
        deep_mod._STATE.procs.clear()

    def setUp(self):
        self._reset()

    def tearDown(self):
        self._reset()
        deep_mod._STATE.launching = False
        deep_mod._STATE.pending = None
        deep_mod._STATE.procs.clear()

    def test_the_signals_that_end_a_process_are_taken(self):
        posix = types.SimpleNamespace(SIGINT=2, SIGTERM=15, SIGHUP=1)
        windows = types.SimpleNamespace(SIGINT=2, SIGTERM=15, SIGBREAK=21)
        self.assertEqual(sorted(deep_mod._available(posix)), [1, 2, 15])
        self.assertEqual(sorted(deep_mod._available(windows)), [2, 15, 21])
        self.assertEqual(deep_mod._available(types.SimpleNamespace()), ())

    @unittest.skipUnless(POSIX, "needs SIGTERM and SIGHUP handlers")
    def test_they_are_installed_for_the_pass_and_put_back_after_it(self):
        sigs = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
        outer = {s: signal.getsignal(s) for s in sigs}
        try:
            # whatever the runner has (nohup ignores SIGHUP), start from the
            # usual: the default for TERM and HUP, Python's for Ctrl-C
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGHUP, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.default_int_handler)
            before = {s: signal.getsignal(s) for s in sigs}
            with deep_mod.stop_on_signals():
                for s in sigs:
                    self.assertEqual(signal.getsignal(s),
                                     deep_mod._on_signal)
            self.assertEqual({s: signal.getsignal(s) for s in sigs}, before)
        finally:
            for s, handler in outer.items():
                signal.signal(s, signal.SIG_DFL if handler is None
                              else handler)

    def test_a_handler_that_was_not_pythons_is_put_back_as_the_default(self):
        # signal() answers None for a handler that C code installed, and
        # None cannot be handed back to it
        calls = []

        def fake(signum, handler):
            calls.append((signum, handler))

        with unittest.mock.patch.object(deep_mod.signal, "signal", fake), \
                unittest.mock.patch.object(deep_mod.signal, "getsignal",
                                           return_value=None):
            with deep_mod.stop_on_signals():
                pass
        taken = [s for s, h in calls if h == deep_mod._on_signal]
        given_back = [s for s, h in calls if h == signal.SIG_DFL]
        self.assertTrue(taken)
        self.assertEqual(given_back, taken)

    def test_a_handler_that_cannot_be_put_back_hides_nothing(self):
        # the interruption is what the caller has to see, not a failure of
        # the clean-up on its way
        def fake(signum, handler):
            if handler != deep_mod._on_signal:
                raise OSError(errno.EINVAL, "Invalid argument")
            return signal.SIG_DFL

        with unittest.mock.patch.object(deep_mod.signal, "signal", fake), \
                unittest.mock.patch.object(deep_mod.signal, "getsignal",
                                           return_value=signal.SIG_DFL):
            with self.assertRaises(deep_mod.Interrupted):
                with deep_mod.stop_on_signals():
                    raise deep_mod.Interrupted(signal.SIGTERM)

    @unittest.skipUnless(POSIX, "needs SIGHUP")
    def test_a_signal_that_is_ignored_stays_ignored(self):
        # `nohup mcp-audit --deep &`: SIGHUP is ignored on purpose
        old = signal.signal(signal.SIGHUP, signal.SIG_IGN)
        try:
            with deep_mod.stop_on_signals():
                self.assertEqual(signal.getsignal(signal.SIGHUP),
                                 signal.SIG_IGN)
        finally:
            signal.signal(signal.SIGHUP, old)

    def test_off_the_main_thread_nothing_is_installed_and_nothing_fails(self):
        seen = []

        def body():
            try:
                with deep_mod.stop_on_signals():
                    seen.append("ran")
            except BaseException as e:      # noqa: B902 - the point of the test
                seen.append(e)

        t = threading.Thread(target=body)
        t.start()
        t.join(10)
        self.assertEqual(seen, ["ran"])

    def test_the_handler_stops_every_server_and_raises(self):
        class P:
            def __init__(self):
                self.pid = 1

        procs = [P(), P()]
        deep_mod._STATE.procs.update(procs)
        with unittest.mock.patch.object(deep_mod, "_kill_tree") as kill:
            with self.assertRaises(deep_mod.Interrupted) as cm:
                deep_mod._on_signal(signal.SIGTERM, None)
        self.assertEqual(cm.exception.signum, signal.SIGTERM)
        self.assertEqual({c.args[0] for c in kill.call_args_list},
                         set(procs))

    def test_it_is_not_an_exception_so_that_nothing_swallows_it(self):
        self.assertFalse(issubclass(deep_mod.Interrupted, Exception))
        # probe_server promises never to raise, and still lets it through
        with unittest.mock.patch.object(
                deep_mod, "_probe", side_effect=deep_mod.Interrupted(15)):
            with self.assertRaises(deep_mod.Interrupted):
                deep_mod.probe_server({"command": "x"})

    def test_a_signal_while_a_server_is_being_started_waits_for_it(self):
        deep_mod._STATE.launching = True
        deep_mod._on_signal(signal.SIGINT, None)      # returns, does not raise
        self.assertEqual(deep_mod._STATE.pending, signal.SIGINT)

    def test_and_is_acted_on_as_soon_as_the_server_is_known(self):
        calls = []

        class Pipe:
            def close(self):
                pass

        class Proc:
            pid = 4242
            stdin, stdout = Pipe(), Pipe()

            def wait(self, timeout=None):
                calls.append("wait")

        def popen(*args, **kwargs):
            # the signal arrives while the server is being started
            deep_mod._on_signal(signal.SIGTERM, None)
            return Proc()

        with unittest.mock.patch.object(deep_mod.subprocess, "Popen", popen), \
                unittest.mock.patch.object(
                    deep_mod, "_kill_tree",
                    side_effect=lambda p: calls.append("kill")), \
                unittest.mock.patch.object(deep_mod, "_Reader"):
            with self.assertRaises(deep_mod.Interrupted) as cm:
                deep_mod.probe_server({"command": sys.executable, "args": []})
        self.assertEqual(cm.exception.signum, signal.SIGTERM)
        self.assertIn("kill", calls)           # the server just started is gone
        self.assertEqual(deep_mod._STATE.procs, set())
        self.assertFalse(deep_mod._STATE.launching)
        self.assertIsNone(deep_mod._STATE.pending)

    def test_a_signal_during_the_talk_stops_the_server_from_the_handler(self):
        # not only the `finally` of the probe: the handler itself kills what
        # runs, so that a signal that comes in where no `finally` is waiting
        # still leaves nothing behind
        killed = []

        class Pipe:
            def close(self):
                pass

        class Proc:
            pid = 4242
            stdin, stdout = Pipe(), Pipe()

            def wait(self, timeout=None):
                pass

        proc = Proc()

        def converse(*args):
            self.assertEqual(deep_mod._STATE.procs, {proc})
            deep_mod._on_signal(signal.SIGTERM, None)

        with unittest.mock.patch.object(
                deep_mod.subprocess, "Popen", lambda *a, **k: proc), \
                unittest.mock.patch.object(
                    deep_mod, "_kill_tree", side_effect=killed.append), \
                unittest.mock.patch.object(deep_mod, "_Reader"), \
                unittest.mock.patch.object(deep_mod, "_converse", converse):
            with self.assertRaises(deep_mod.Interrupted):
                deep_mod.probe_server({"command": sys.executable, "args": []})
        # once from the handler, once by the probe that unwinds
        self.assertEqual(killed, [proc, proc])
        self.assertEqual(deep_mod._STATE.procs, set())

    def test_a_server_that_fails_to_start_does_not_lose_it_either(self):
        def popen(*args, **kwargs):
            deep_mod._on_signal(signal.SIGTERM, None)
            raise OSError(errno.ENOENT, "No such file or directory")

        with unittest.mock.patch.object(deep_mod.subprocess, "Popen", popen):
            with self.assertRaises(deep_mod.Interrupted) as cm:
                deep_mod.probe_server({"command": sys.executable, "args": []})
        self.assertEqual(cm.exception.signum, signal.SIGTERM)
        self.assertFalse(deep_mod._STATE.launching)
        self.assertIsNone(deep_mod._STATE.pending)

    def test_a_server_that_fails_to_start_is_a_failed_probe_as_before(self):
        def popen(*args, **kwargs):
            raise OSError(errno.ENOENT, "No such file or directory")

        with unittest.mock.patch.object(deep_mod.subprocess, "Popen", popen):
            probe = deep_mod.probe_server({"command": sys.executable,
                                           "args": []})
        self.assertFalse(probe["ok"])
        self.assertIn("launch failed", probe["error"])
        self.assertFalse(deep_mod._STATE.launching)
        self.assertEqual(deep_mod._STATE.procs, set())

    def test_a_probe_that_ends_on_its_own_forgets_its_server(self):
        started = []
        real = subprocess.Popen

        def popen(*args, **kwargs):
            started.append(real(*args, **kwargs))
            return started[-1]

        with unittest.mock.patch.object(deep_mod.subprocess, "Popen", popen):
            probe = deep_mod.probe_server(
                {"command": sys.executable,
                 "args": [fixture("fake_mcp_server.py")]}, timeout=20)
        self.assertTrue(probe["ok"], probe)
        # count the launches of the server: on Windows the tree kill runs
        # `taskkill`, which is a second Popen through the same name
        servers = [p for p in started
                   if fixture("fake_mcp_server.py") in list(p.args)]
        self.assertEqual(len(servers), 1)
        self.assertEqual(deep_mod._STATE.procs, set())


class TestTheCommand(unittest.TestCase):
    """What the command line does when the pass is cut short."""

    def run_with(self, exc, *extra):
        with isolated_machine() as (home, cwd):
            path = write_json(os.path.join(cwd, "m.json"), {"mcpServers": {
                "a": {"command": "node", "args": ["srv.js"]}}})
            with unittest.mock.patch.object(deep_mod, "probe_server",
                                            side_effect=exc):
                return run_cli("--config", path, "--deep", "--format", "json",
                               *extra)

    def test_an_interrupted_pass_exits_128_plus_the_signal_with_a_note(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal.Signals(signum).name):
                code, out, err = self.run_with(deep_mod.Interrupted(signum))
                self.assertEqual(code, 128 + signum)
                self.assertEqual(out, "")
                self.assertIn(signal.Signals(signum).name, err)
                self.assertIn("no report", err)
                self.assertNotIn("Traceback", err)

    def test_a_number_that_names_no_signal_is_still_reported(self):
        code, out, err = self.run_with(deep_mod.Interrupted(99))
        self.assertEqual(code, 128 + 99)
        self.assertIn("signal 99", err)
        self.assertIn("no report", err)

    def test_a_terminal_that_is_gone_does_not_change_the_code(self):
        # SIGHUP is what a closed terminal sends, and writing the note to it
        # then fails: the code is still 128 plus the signal
        for exc in (OSError(errno.EIO, "Input/output error"),
                    ValueError("I/O operation on closed file")):
            with self.subTest(type(exc).__name__):
                def note(text, exc=exc):
                    if text.startswith("interrupted"):
                        raise exc

                with unittest.mock.patch.object(cli_mod, "_note", note):
                    code, out, err = self.run_with(
                        deep_mod.Interrupted(signal.SIGTERM))
                self.assertEqual(code, 128 + signal.SIGTERM)
                self.assertEqual(out, "")

    def test_ctrl_c_anywhere_else_is_also_quiet(self):
        with isolated_machine() as (home, cwd):
            path = write_json(os.path.join(cwd, "m.json"), {"mcpServers": {
                "a": {"command": "node", "args": ["srv.js"]}}})
            with unittest.mock.patch.object(cli_mod, "_audit_all",
                                            side_effect=KeyboardInterrupt):
                code, out, err = run_cli("--config", path)
        self.assertEqual(code, 130)
        self.assertEqual(out, "")
        self.assertIn("interrupted", err)
        self.assertNotIn("Traceback", err)

    def test_an_interrupted_run_is_not_an_internal_error(self):
        # `Interrupted` must not fall into the "internal error" answer (exit 2)
        code, out, err = self.run_with(deep_mod.Interrupted(signal.SIGTERM))
        self.assertNotEqual(code, 2)
        self.assertNotIn("internal error", err)


class TestTheDocumentation(unittest.TestCase):
    @staticmethod
    def words(text):
        return " ".join(text.split()).lower()

    def test_the_readme_says_what_a_signal_does(self):
        with open(README, encoding="utf-8") as f:
            readme = self.words(f.read())
        for needle in ("128 plus the signal number", "`130`, `143`, `129`",
                       "no report", "sigterm", "sighup", "ctrl-break",
                       "`kill -9`", "nohup mcp-audit --deep &"):
            self.assertTrue(needle in readme, needle)

    def test_the_help_of_deep_says_it_too(self):
        text = cli_mod._build_parser().format_help()
        section = self.words(text.split("\n  --deep", 1)[1]
                             .split("\n  --probe-critical", 1)[0])
        for needle in ("ctrl-c", "sigterm", "sighup", "128 plus",
                       "no report"):
            self.assertTrue(needle in section, needle)


if __name__ == "__main__":
    unittest.main()
