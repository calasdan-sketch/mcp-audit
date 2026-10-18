"""The value of an option mcp-audit does not know is not the package (Round 3
#6).

`npx --weird-opt FAKESECRET -y pkg@1.0.0`: the tables of options that take a
value do not know `--weird-opt`, so the next word was read as the package
and printed - `runs: npx FAKESECRET` on stderr and "unpinned package
'FAKESECRET'" in every format - although nothing from a config is repeated
anywhere else. A package is now named only when every option before it is one
whose shape is known; after an unknown option the name could be that option's
value, and it is not shown.
"""

import json
import os
import unittest
import unittest.mock

from mcp_audit import deep as deep_mod
from mcp_audit import detectors
from mcp_audit import launch

from _support import isolated_machine, run_all_formats, write_json

S = "FAKE-aaaa4242"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def packages(command, *args):
    return detectors._iter_packages({"command": command, "args": list(args)})


def floating(command, *args):
    return detectors.detect_floating_version(
        "s", {"command": command, "args": list(args)})


KNOWN = (
    ("npx", ["-y", "pkg"]),
    ("npx", ["--yes", "--no-install", "--prefer-offline", "pkg@1.0.0"]),
    ("npx", ["-q", "--silent", "--no-audit", "--no-fund", "-y", "pkg"]),
    ("npx", ["--registry", "https://r.example/", "pkg"]),
    ("npx", ["--registry=https://r.example/", "-y", "pkg"]),
    ("npx", ["--auth", S, "pkg"]),
    ("npx", ["--no-auth", "pkg"]),
    ("npx", ["--skip-anything", "pkg"]),
    ("npx", ["--userconfig", "/etc/npmrc", "--cache", "/tmp/c", "-y", "pkg"]),
    ("npx", ["-p", "pkg", "tool"]),
    ("npx", ["--package=pkg", "tool"]),
    ("npx", ["--", "pkg"]),
    ("pnpm", ["dlx", "--package", "pkg", "tool"]),
    ("pnpm", ["dlx", "pkg"]),
    ("yarn", ["dlx", "-q", "pkg"]),
    ("npm", ["exec", "--yes", "--", "pkg"]),
    ("bunx", ["--bun", "pkg"]),
    ("uvx", ["pkg"]),
    ("uvx", ["--isolated", "--no-cache", "--python", "3.12", "pkg"]),
    ("uvx", ["--from", "pkg", "tool"]),
    ("uvx", ["--refresh", "-q", "--with", "other", "pkg"]),
    ("uvx", ["--index-url", "https://r.example/simple", "pkg==1.0"]),
    ("uv", ["tool", "run", "--no-progress", "pkg"]),
    ("pipx", ["run", "--spec", "pkg", "tool"]),
    ("pipx", ["run", "--no-cache", "--python", "3.12", "pkg"]),
)

UNKNOWN = (
    ("npx", ["--weird-opt", S, "-y", "pkg@1.0.0"]),
    ("npx", ["-y", "--weird-opt", S, "pkg"]),
    ("npx", ["-Z", S, "pkg"]),
    ("pnpm", ["dlx", "--weird", S, "pkg"]),
    ("bunx", ["--weird", S, "pkg"]),
    ("uvx", ["--weird", S, "pkg"]),
    ("uv", ["tool", "run", "--weird", S, "pkg"]),
    ("pipx", ["run", "--weird", S, "pkg"]),
)


class TestWhatIsSure(unittest.TestCase):
    def test_known_options_leave_the_package_sure(self):
        for command, argv in KNOWN:
            with self.subTest(command=command, argv=argv):
                found = packages(command, *argv)
                self.assertTrue(found)
                self.assertTrue(all(p.sure for p in found), found)

    def test_the_package_is_still_found_after_an_unknown_option(self):
        # other checks (the advisory feed) still see it; it is only not named
        for command, argv in UNKNOWN:
            with self.subTest(command=command, argv=argv):
                found = packages(command, *argv)
                self.assertTrue(found)
                self.assertFalse(any(p.sure for p in found), found)

    def test_an_option_with_its_value_attached_does_not_hide_the_package(self):
        for command, argv in (("npx", ["--weird-opt=" + S, "-y", "pkg"]),
                              ("uvx", ["--weird=" + S, "pkg"])):
            found = packages(command, *argv)
            self.assertEqual([(p.name, p.sure) for p in found],
                             [("pkg", True)], argv)


class TestWhatIsSaid(unittest.TestCase):
    def test_the_finding_does_not_name_an_unsure_package(self):
        for command, argv in UNKNOWN:
            with self.subTest(command=command, argv=argv):
                found = floating(command, *argv)
                self.assertEqual([(f["severity"], f["check"]) for f in found],
                                 [("medium", "floating-version")])
                message = found[0]["message"]
                self.assertNotIn(S, message)
                self.assertIn("not shown", message)
                self.assertIn("name@x.y.z", message)

    def test_a_sure_package_is_named_as_before(self):
        (found,) = floating("npx", "-y", "some-server")
        self.assertIn("unpinned package 'some-server'", found["message"])
        (found,) = floating("uvx", "some-server>=1")
        self.assertIn("'some-server'", found["message"])

    def test_the_launch_line_says_so(self):
        for cfg, line in (
                ({"command": "npx", "args": ["--weird-opt", S, "-y",
                                             "pkg@1.0.0"]},
                 "npx (package not shown) (+4 arguments not shown)"),
                ({"command": "uvx", "args": ["--weird-opt", S, "pkg"]},
                 "uvx (package not shown) (+3 arguments not shown)"),
                ({"command": "bash", "args": ["-lc", "npx --weird-opt " + S
                                              + " -y pkg@1.0.0"]},
                 "npx (package not shown) via bash (+2 arguments not shown)"),
                ({"command": "npx", "args": ["--weird-opt=" + S, "-y",
                                             "pkg@1.0.0"]},
                 "npx pkg@1.0.0 (+2 arguments not shown)")):
            self.assertEqual(launch.summary(cfg), line, cfg)

    def test_known_options_keep_the_package_in_the_launch_line(self):
        for command, argv in KNOWN:
            with self.subTest(command=command, argv=argv):
                line = launch.summary({"command": command, "args": argv})
                self.assertNotIn("package not shown", line)
                self.assertIn("pkg", line)

    def test_nothing_unsure_is_sent_to_osv(self):
        sent = []

        def urlopen(request, timeout=None):
            sent.append(json.loads(request.data))
            raise OSError("offline")

        with unittest.mock.patch.object(detectors.urllib.request, "urlopen",
                                        urlopen):
            detectors.detect_osv("s", {"command": "npx", "args": [
                "--weird-opt", S + "@1.2.3", "-y", "pkg@1.0.0"]})
            self.assertEqual(sent, [])
            detectors.detect_osv("s", {"command": "npx",
                                       "args": ["-y", "pkg@1.0.0"]})
        self.assertEqual([body["package"]["name"] for body in sent], ["pkg"])


class TestEveryFormat(unittest.TestCase):
    def test_the_value_is_in_no_output(self):
        def stub(cfg, *args, **kwargs):     # nothing is started here
            return {"ok": False, "tools": [], "error": "stubbed"}

        with isolated_machine() as (home, cwd), \
                unittest.mock.patch.object(deep_mod, "probe_server", stub):
            path = write_json(os.path.join(cwd, "m.json"), {"mcpServers": {
                "a": {"command": "npx", "args": ["--weird-opt", S, "-y",
                                                 "pkg@1.0.0"]},
                "b": {"command": "uvx", "args": ["--weird-opt", S, "pkg"]}}})
            outputs = run_all_formats("--config", path, "--deep",
                                      "--probe-critical")
        for fmt, (code, out, err) in outputs.items():
            self.assertNotIn(S, out + err, fmt)
            self.assertIn("package not shown: an option", out, fmt)
            self.assertIn("(package not shown)", err, fmt)


class TestTheDocumentation(unittest.TestCase):
    def test_the_readme_says_when_a_package_is_not_shown(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            readme = " ".join(f.read().split())
        for needle in ("`(package not shown)`", "every option before it"):
            self.assertIn(needle, readme)


if __name__ == "__main__":
    unittest.main()
