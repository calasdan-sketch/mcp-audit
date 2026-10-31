"""A reader that goes away must not turn into a traceback or change the exit
code, on any OS. Windows words it differently from POSIX: print() of a small
output succeeds (it only fills the buffer) and the flush then fails with a
plain OSError(EINVAL) -- at interpreter exit, as "Exception ignored", with
exit status 120. The first two tests reproduce that on any platform; the
subprocess test is the real proof (and runs on Windows too)."""
from __future__ import annotations

import errno
import io
import os
import subprocess
import sys
import unittest
from unittest import mock

from mcp_gradecard import cli as cli_mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _DeadPipe(io.StringIO):
    """Writes are buffered fine; the flush says what Windows says once the
    reader of the pipe is gone."""

    def flush(self):
        raise OSError(errno.EINVAL, "Invalid argument")


class TestClosedPipeHelper(unittest.TestCase):
    def test_which_errors_mean_nobody_is_reading(self):
        gone = cli_mod._is_closed_pipe
        invalid = OSError(errno.EINVAL, "Invalid argument")
        for windows in (False, True):
            with mock.patch.object(cli_mod, "_IS_WINDOWS", windows):
                self.assertTrue(gone(BrokenPipeError()))
                self.assertTrue(gone(BrokenPipeError(errno.EPIPE, "Broken pipe")))
                self.assertFalse(gone(OSError(errno.ENOSPC, "No space left")))
                self.assertFalse(gone(ValueError("closed file")))
        with mock.patch.object(cli_mod, "_IS_WINDOWS", True):
            self.assertTrue(gone(invalid))
        with mock.patch.object(cli_mod, "_IS_WINDOWS", False):
            self.assertFalse(gone(invalid))


class TestExitCodeSurvivesAClosedPipe(unittest.TestCase):
    def _run(self, windows: bool, code: int) -> int:
        def command(*_a, **_k):
            print("some output", flush=False)
            return code

        with mock.patch.object(cli_mod, "_IS_WINDOWS", windows), \
                mock.patch.object(cli_mod, "_main", command), \
                mock.patch.object(sys, "stdout", _DeadPipe()):
            return cli_mod.main([])

    def test_verdict_is_kept_when_the_flush_fails_like_windows(self):
        for code in (0, 1, 3):
            self.assertEqual(self._run(True, code), code)

    def test_einval_is_still_an_error_off_windows(self):
        with self.assertRaises(OSError):
            self._run(False, 0)


class TestRealClosedPipe(unittest.TestCase):
    def test_help_into_a_pipe_nobody_reads(self):
        # Buffered stdout is what a user has; an environment that sets
        # PYTHONUNBUFFERED hides the failure until the very last byte.
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
        p = subprocess.Popen([sys.executable, "-m", "mcp_gradecard", "--help"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             cwd=REPO, env=env)
        p.stdout.close()
        err = p.stderr.read()
        p.stderr.close()
        rc = p.wait(timeout=60)
        self.assertNotIn(b"Traceback", err)
        self.assertNotIn(b"Exception ignored", err)
        self.assertEqual(rc, 0, err)


if __name__ == "__main__":
    unittest.main()
