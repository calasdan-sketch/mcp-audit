"""The advisory feed must ship, and a missing feed must not read as clean (M4).

pyproject.toml declared no package data, so `pip install` produced a wheel
without advisories.json; load_advisories() swallowed the OSError and returned
[]: an installed mcp-audit graded `uvx mcp-server-fetch==2026.6.4`
100/100 where a checkout said 90/100 "known vulnerable". Nothing said so.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
import zipfile

from mcp_audit import detectors

from _support import isolated_machine, run_all_formats, write_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FETCH = {"mcpServers": {"fetch": {
    "command": "uvx", "args": ["mcp-server-fetch==2026.6.4"]}}}


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as f:
        return f.read()


class TestFeedLoading(unittest.TestCase):
    def test_the_shipped_feed_loads(self):
        feed = detectors.load_advisories()
        self.assertGreaterEqual(len(feed), 1)
        self.assertTrue(all(a.get("package") for a in feed))

    def test_a_missing_feed_is_an_error_not_an_empty_list(self):
        for exc in (FileNotFoundError("gone"), PermissionError("denied"),
                    ModuleNotFoundError("mcp_audit")):
            with unittest.mock.patch.object(detectors, "_read_feed_text",
                                            side_effect=exc):
                with self.assertRaises(detectors.AdvisoryFeedError) as cm:
                    detectors.load_advisories()
            self.assertIn("advisories.json", str(cm.exception))

    def test_a_corrupt_or_misshapen_feed_is_an_error(self):
        for text in ("not json", "{}", "[1, 2]", '[{"cve": "x"}]',
                     '[{"package": ""}]', ""):
            with unittest.mock.patch.object(detectors, "_read_feed_text",
                                            return_value=text):
                with self.assertRaises(detectors.AdvisoryFeedError, msg=text):
                    detectors.load_advisories()

    def test_an_empty_feed_is_valid(self):
        with unittest.mock.patch.object(detectors, "_read_feed_text",
                                        return_value="[]"):
            self.assertEqual(detectors.load_advisories(), [])

    def test_audit_server_without_a_feed_fails_closed(self):
        with unittest.mock.patch.object(detectors, "_read_feed_text",
                                        side_effect=FileNotFoundError("x")):
            findings = detectors.audit_server(
                "fetch", FETCH["mcpServers"]["fetch"])
        self.assertIn(("high", "detector-error"),
                      [(f["severity"], f["check"]) for f in findings])

    def test_cli_exits_2_and_says_why_in_every_format(self):
        with isolated_machine() as (home, cwd):
            p = write_json(os.path.join(cwd, "m.json"), FETCH)
            with unittest.mock.patch.object(
                    detectors, "_read_feed_text",
                    side_effect=FileNotFoundError("x")):
                for fmt, (code, out, err) in run_all_formats(
                        "--config", p).items():
                    self.assertEqual(code, 2, fmt)
                    self.assertIn("advisory feed", err)
                    self.assertEqual(out, "", fmt)

    def test_the_fetch_package_is_known_vulnerable_from_a_checkout(self):
        findings = detectors.audit_server(
            "fetch", FETCH["mcpServers"]["fetch"])
        self.assertIn("known-vulnerable", [f["check"] for f in findings])


class TestPackagingMetadata(unittest.TestCase):
    def test_pyproject_declares_the_feed_as_package_data(self):
        text = read("pyproject.toml")
        m = re.search(r"(?ms)^\[tool\.setuptools\.package-data\]\s*\n(.*?)(?=^\[|\Z)",
                      text)
        self.assertIsNotNone(m, "no [tool.setuptools.package-data] table")
        self.assertIn("advisories.json", m.group(1))

    def test_manifest_includes_the_feed_for_sdists(self):
        self.assertIn("mcp_audit/advisories.json", read("MANIFEST.in"))

    def test_version_is_the_same_in_pyproject_and_package(self):
        import mcp_audit
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', read("pyproject.toml"))
        self.assertEqual(mcp_audit.__version__, m.group(1))


def _pip_wheel(src, out, env):
    return subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps",
         "--no-build-isolation", "--no-index", "--disable-pip-version-check",
         "-w", out, src],
        capture_output=True, env=env, timeout=600)


class TestBuiltWheel(unittest.TestCase):
    """Build the wheel, unpack it somewhere else and run what is inside."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        env = {k: v for k, v in os.environ.items()
               if k not in ("PYTHONUNBUFFERED", "PYTHONPATH")}
        env["PIP_CONFIG_FILE"] = os.devnull
        env["PIP_NO_INPUT"] = "1"
        cls.env = env
        # Is wheel building usable at all in this interpreter? Prove it on a
        # trivial project first, so only a broken toolchain skips the test -
        # never a broken mcp-audit.
        toy = os.path.join(cls.tmp, "toy")
        os.makedirs(os.path.join(toy, "toypkg"))
        with open(os.path.join(toy, "pyproject.toml"), "w") as f:
            f.write('[build-system]\nrequires = ["setuptools>=61"]\n'
                    'build-backend = "setuptools.build_meta"\n'
                    '[project]\nname = "toy"\nversion = "1"\n')
        with open(os.path.join(toy, "toypkg", "__init__.py"), "w") as f:
            f.write("")
        p = _pip_wheel(toy, os.path.join(cls.tmp, "toy-out"), env)
        if p.returncode != 0:
            tail = p.stderr.decode("utf-8", "replace").strip().splitlines()[-1:]
            raise unittest.SkipTest(
                "no working wheel toolchain here (a trivial project does not "
                "build either): " + " ".join(tail))
        src = os.path.join(cls.tmp, "src")
        os.makedirs(src)
        for name in ("pyproject.toml", "README.md", "LICENSE", "MANIFEST.in"):
            shutil.copy(os.path.join(ROOT, name), src)
        shutil.copytree(os.path.join(ROOT, "mcp_audit"),
                        os.path.join(src, "mcp_audit"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        out = os.path.join(cls.tmp, "wheelhouse")
        p = _pip_wheel(src, out, env)
        if p.returncode != 0:
            raise AssertionError(
                "mcp-audit itself does not build into a wheel:\n"
                + p.stdout.decode("utf-8", "replace")[-2000:]
                + p.stderr.decode("utf-8", "replace")[-2000:])
        (cls.wheel,) = [os.path.join(out, n) for n in os.listdir(out)
                        if n.endswith(".whl")]
        cls.installed = os.path.join(cls.tmp, "installed")
        with zipfile.ZipFile(cls.wheel) as z:
            cls.names = z.namelist()
            z.extractall(cls.installed)
        cls.elsewhere = os.path.join(cls.tmp, "elsewhere")
        os.makedirs(cls.elsewhere)

    def _python(self, *args, **kw):
        env = dict(self.env, PYTHONPATH=self.installed)
        return subprocess.run([sys.executable, *args], cwd=self.elsewhere,
                              env=env, capture_output=True, timeout=120, **kw)

    def test_the_wheel_contains_the_feed_and_every_module(self):
        self.assertIn("mcp_audit/advisories.json", self.names)
        for fn in os.listdir(os.path.join(ROOT, "mcp_audit")):
            if fn.endswith(".py"):
                self.assertIn("mcp_audit/" + fn, self.names)

    def test_the_installed_copy_finds_its_feed(self):
        p = self._python("-c", (
            "import mcp_audit, os\n"
            "from mcp_audit import detectors\n"
            "assert os.path.realpath(mcp_audit.__file__).startswith("
            "os.path.realpath(%r)), mcp_audit.__file__\n"
            "print(len(detectors.load_advisories()))\n") % self.installed)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertGreaterEqual(int(p.stdout.strip()), 1)

    def test_installed_and_checkout_agree_on_the_known_vulnerable_package(self):
        cfg = write_json(os.path.join(self.elsewhere, "fetch.json"), FETCH)
        p = self._python("-m", "mcp_audit", "--config", cfg, "--format",
                         "json")
        self.assertEqual(p.returncode, 0, p.stderr)
        (res,) = json.loads(p.stdout)["results"]
        self.assertIn("known-vulnerable", [f["check"] for f in res["findings"]])
        self.assertLess(res["score"], 100)
        checkout = detectors.audit_server(
            "fetch", FETCH["mcpServers"]["fetch"])
        self.assertEqual(
            sorted(f["check"] for f in res["findings"]),
            sorted(f["check"] for f in checkout))


if __name__ == "__main__":
    unittest.main()
