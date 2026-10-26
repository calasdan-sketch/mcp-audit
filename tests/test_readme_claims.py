"""What the README says about the command line and the checks, held to the
code (Round 3, reviewer A6: `--version`, the `osv-lookup` check and the
meaning of exit status 0 were missing or wrong).
"""

import contextlib
import glob
import io
import os
import re
import tempfile
import unittest

from mcp_audit import __version__, cli, scoring

from _support import isolated_machine, run_cli, write_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def readme():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        return " ".join(f.read().split())    # line breaks are not content


class TestEveryCheckIsDocumented(unittest.TestCase):
    CALL = re.compile(r'_finding\(\s*(?:"[a-z]+"|[a-z_]+),\s*'
                      r'"([a-z]+(?:-[a-z]+)*)"')
    DICT = re.compile(r'"check":\s*"([a-z]+(?:-[a-z]+)*)"')

    def test_each_check_id_the_code_makes_has_a_row_in_the_table(self):
        ids = {scoring.DESCRIPTION_CHECK}
        for path in glob.glob(os.path.join(ROOT, "mcp_audit", "*.py")):
            with open(path, encoding="utf-8") as f:
                source = f.read()
            ids.update(m.group(1) for rx in (self.CALL, self.DICT)
                       for m in rx.finditer(source))
        self.assertGreaterEqual(len(ids), 17, ids)    # the search found them
        text = readme()
        for check in sorted(ids):
            with self.subTest(check):
                self.assertIn("| `%s` |" % check, text)


class TestTheVersionFlag(unittest.TestCase):
    def test_it_prints_the_version_and_the_readme_says_so(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                self.assertRaises(SystemExit) as stop:
            cli.main(["--version"])
        self.assertEqual(stop.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), "mcp-audit " + __version__)
        self.assertIn("mcp-audit --version", readme())


class TestWhatExitStatusZeroMeans(unittest.TestCase):
    CRITICAL = {"mcpServers": {"bad": {"command": "node", "args": [
        "x.js", "https://evil.example/c"]}}}

    def test_critical_findings_do_not_fail_a_run_without_fail_on(self):
        with isolated_machine(), tempfile.TemporaryDirectory() as tmp:
            path = write_json(os.path.join(tmp, "mcp.json"), self.CRITICAL)
            code, out, err = run_cli("--config", path)
            self.assertEqual(code, 0)
            self.assertIn("CRITICAL", out)
            code, out, err = run_cli("--config", path, "--fail-on",
                                     "critical")
            self.assertEqual(code, 1)

    def test_the_readme_says_so(self):
        self.assertIn("Without `--fail-on` the exit status is `0` even when "
                      "the report has critical findings", readme())


if __name__ == "__main__":
    unittest.main()
