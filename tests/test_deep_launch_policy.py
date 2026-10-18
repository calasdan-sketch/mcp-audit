"""--deep: which servers are launched, and what the list says about them
(Round 3 #3, #4 and #9).

The probe runs the commands in your configs, so what it leaves alone matters
as much as what it reads: a server the static audit could not read, or that
reaches a registry over plain http, was launched like any other; a server
your client has switched off was launched too; and the list did not say which
of the launches download code.
"""

import json
import os
import sys
import unittest
import unittest.mock

from mcp_audit import cli as cli_mod
from mcp_audit import deep as deep_mod

from _support import FIX, isolated_machine, run_cli, write_json

#: a command the audit cannot read to the end: a shell inside a shell ...
UNREADABLE = {"command": "bash",
              "args": ["-c", "echo " + "$(" * 20 + "x" + ")" * 20]}
#: a URL that cannot be taken apart
BAD_URL = {"command": "node", "args": ["srv.js", "http://[x"]}
#: packages from a registry that anyone on the way can change
HTTP_REGISTRY = {"command": "npx",
                 "args": ["--registry", "http://registry.insecure.example/",
                          "-y", "pkg@1.0.0"]}
PLAIN = {"command": "node", "args": ["server.js"]}


def said(result):
    """What the result says about --deep, in one string."""
    return " ".join(f["message"] for f in result["findings"]
                    if f["check"] == "deep-probe")


class LaunchCase(unittest.TestCase):
    def setUp(self):
        self.enter = isolated_machine()
        self.home, self.cwd = self.enter.__enter__()
        self.addCleanup(self.enter.__exit__, None, None, None)

    def run_deep(self, servers, *argv, project=False):
        """--deep over `servers` with the probe replaced by a recorder ->
        (the configs it was asked to launch, results, stderr). The servers
        are in a file named with --config; with `project`, in the .mcp.json
        of the current directory instead."""
        if project:
            write_json(os.path.join(self.cwd, ".mcp.json"),
                       {"mcpServers": servers})
            where = []
        else:
            where = ["--config", write_json(os.path.join(self.cwd, "m.json"),
                                            {"mcpServers": servers})]
        calls = []

        def probe(cfg, *args, **kwargs):
            calls.append(cfg)
            return {"ok": False, "tools": [], "error": "stubbed"}

        with unittest.mock.patch.object(deep_mod, "probe_server", probe):
            code, out, err = run_cli(*where, "--deep", "--format", "json",
                                     *argv)
        self.assertEqual(code, 0, err)
        return calls, json.loads(out)["results"], err


class TestWhatTheStaticAuditCouldNotSettleIsNotLaunched(LaunchCase):
    """Only critical findings held a server back. A command the audit could
    not read (a HIGH `detector-error`), a URL it could not take apart (HIGH
    `unparseable-url`) and a registry over plain http (HIGH) were launched."""

    HELD = (
        ("a command that could not be read", UNREADABLE,
         "could not analyze it"),
        ("a URL that could not be taken apart", BAD_URL,
         "could not be taken apart"),
        ("a registry over plain http", HTTP_REGISTRY,
         "registry over plain http"),
    )

    def test_each_is_left_alone_and_says_why(self):
        for label, cfg, words in self.HELD:
            with self.subTest(label):
                calls, results, err = self.run_deep({"s": cfg})
                self.assertEqual(calls, [])
                (res,) = results
                (note,) = [f for f in res["findings"]
                           if f["check"] == "deep-probe"]
                self.assertEqual(note["severity"], "low")
                self.assertIn(words, note["message"])
                self.assertIn("(--probe-critical launches it anyway)",
                              note["message"])
                self.assertIn("leaves 's'", err)
                self.assertIn(words, err)
                self.assertNotIn("LAUNCH", err)

    def test_probe_critical_launches_them_anyway(self):
        calls, results, err = self.run_deep(
            {"a": UNREADABLE, "b": BAD_URL, "c": HTTP_REGISTRY},
            "--probe-critical")
        self.assertEqual(len(calls), 3)
        self.assertIn("LAUNCH 3 MCP server", err)
        for res in results:
            self.assertNotIn("--probe-critical", said(res))

    def test_the_other_servers_are_launched_as_before(self):
        # Round 6 let these through on purpose: they are rated medium, and
        # they are how MCP servers are installed and reached
        launched = {
            "plain": PLAIN,
            "https registry": {"command": "npx", "args": [
                "--registry", "https://registry.example.com/", "-y",
                "pkg@1.0.0"]},
            "git source": {"command": "uvx", "args": [
                "--from", "git+https://github.com/o/r", "tool"]},
            "bridge": {"command": "npx", "args": [
                "-y", "mcp-remote@0.1.29", "https://mcp.linear.app/sse"]},
            "unpinned": {"command": "npx", "args": ["-y", "pkg"]},
        }
        calls, results, err = self.run_deep(dict(launched, bad=UNREADABLE))
        self.assertEqual(len(calls), len(launched))
        self.assertNotIn(UNREADABLE, calls)

    def test_a_server_held_for_two_reasons_is_told_once(self):
        both = {"command": "bash", "args": [
            "-c", "echo " + "$(" * 20 + "x" + ")" * 20,
            "https://evil.example/collect"]}
        calls, results, err = self.run_deep({"both": both})
        self.assertEqual(calls, [])
        (res,) = results
        checks = {(f["check"], f["severity"]) for f in res["findings"]}
        self.assertIn(("exfiltration-endpoint", "critical"), checks)
        self.assertIn(("detector-error", "high"), checks)
        self.assertEqual(said(res).count("--probe-critical"), 1, said(res))
        self.assertEqual(err.count("--probe-critical"), 1, err)

    def test_a_project_server_needs_the_project_flag_as_well(self):
        servers = {"proj": HTTP_REGISTRY}
        for flags in ((), ("--probe-critical",), ("--probe-project",)):
            calls, results, err = self.run_deep(servers, *flags,
                                                project=True)
            self.assertEqual(calls, [], flags)
        calls, results, err = self.run_deep(servers, project=True)
        self.assertIn("(it takes --probe-critical and --probe-project to "
                      "launch it)", said(results[0]))
        calls, results, err = self.run_deep(
            servers, "--probe-critical", "--probe-project", project=True)
        self.assertEqual(calls, [HTTP_REGISTRY])

    def test_the_decision_is_made_from_the_findings(self):
        def result(*checks):
            return {"name": "s", "client": "explicit", "path": "p",
                    "tools": [], "config": PLAIN, "score": 100, "grade": "A",
                    "findings": [{"severity": sev, "check": check,
                                  "message": "m"} for sev, check in checks]}

        hold = cli_mod._hold_reasons
        self.assertEqual(hold(result(), False, False), [])
        for checks in ((("high", "detector-error"),),
                       (("high", "unparseable-url"),),
                       (("high", "package-registry"),)):
            self.assertEqual(len(hold(result(*checks), False, False)), 1,
                             checks)
            self.assertEqual(hold(result(*checks), True, False), [], checks)
        for checks in ((("medium", "package-registry"),),
                       (("medium", "git-source"),),
                       (("medium", "remote-server"),),
                       (("medium", "floating-version"),),
                       (("high", "invalid-config"),)):
            self.assertEqual(hold(result(*checks), False, False), [], checks)


class TestSwitchedOffServersAreNotLaunched(LaunchCase):
    """An entry with `"disabled": true` or `"enabled": false` is a server its
    client does not start. --deep started it. Now it is audited like any
    other entry, listed as skipped, and not launched."""

    def marker_server(self, **extra):
        marker = os.path.join(self.cwd, "launched")
        cfg = {"command": sys.executable,
               "args": [os.path.join(FIX, "marker_mcp_server.py"), marker]}
        cfg.update(extra)
        return marker, cfg

    def test_neither_form_is_launched(self):
        for flag, how in (({"disabled": True}, '"disabled": true'),
                          ({"enabled": False}, '"enabled": false')):
            with self.subTest(how):
                marker, cfg = self.marker_server(**flag)
                calls, results, err = self.run_deep({"off": cfg})
                self.assertEqual(calls, [])
                self.assertFalse(os.path.exists(marker), "it was launched")
                (res,) = results
                (note,) = [f for f in res["findings"]
                           if f["check"] == "deep-probe"]
                self.assertEqual(note["severity"], "low")
                self.assertIn("disabled in the explicit config", note["message"])
                self.assertIn(how, note["message"])
                self.assertIn("skips 'off' <explicit>", err)
                self.assertIn("disabled in the explicit config", err)
                self.assertNotIn("LAUNCH", err)

    def test_the_real_thing_does_not_start_either(self):
        # no stand-in for the probe this time
        for flag in ({"disabled": True}, {"enabled": False}):
            marker, cfg = self.marker_server(**flag)
            path = write_json(os.path.join(self.cwd, "m.json"),
                              {"mcpServers": {"off": cfg}})
            code, out, err = run_cli("--config", path, "--deep",
                                     "--format", "json")
            self.assertEqual(code, 0, err)
            self.assertFalse(os.path.exists(marker), flag)

    def test_it_is_still_audited_statically(self):
        _, cfg = self.marker_server(disabled=True)
        cfg["env"] = {"API_TOKEN": "x"}
        calls, results, err = self.run_deep({"off": cfg})
        (res,) = results
        self.assertIn(("secret-env", "medium"),
                      {(f["check"], f["severity"]) for f in res["findings"]})

    def test_the_flags_that_launch_the_held_ones_do_not_launch_it(self):
        evil = {"command": "node",
                "args": ["a.js", "https://evil.example/collect"],
                "disabled": True}
        calls, results, err = self.run_deep(
            {"off": evil}, "--probe-critical", "--probe-project")
        self.assertEqual(calls, [])
        self.assertIn("disabled in the explicit config", said(results[0]))
        self.assertNotIn("launches it anyway", said(results[0]))
        self.assertNotIn("leaves", err)
        self.assertIn("skips 'off'", err)
        # and without the flags: skipped, not "left alone"
        calls, results, err = self.run_deep({"off": evil})
        self.assertNotIn("launches it anyway", said(results[0]))

    def test_a_project_server_that_is_switched_off_is_skipped_not_held(self):
        calls, results, err = self.run_deep(
            {"off": {"command": "node", "args": ["a.js"], "enabled": False}},
            project=True)
        self.assertEqual(calls, [])
        self.assertIn("disabled in the claude-code-project config",
                      said(results[0]))
        self.assertNotIn("--probe-project", said(results[0]))

    def test_the_others_are_launched_and_counted(self):
        calls, results, err = self.run_deep({
            "off": dict(PLAIN, disabled=True),
            "also off": dict(PLAIN, enabled=False),
            "on": dict(PLAIN, disabled=False, enabled=True),
            "plain": PLAIN})
        self.assertEqual(len(calls), 2)
        self.assertIn("LAUNCH 2 MCP server", err)
        listed = [ln for ln in err.splitlines() if " runs: " in ln]
        self.assertEqual(len(listed), 2, err)
        self.assertFalse([ln for ln in listed if "off" in ln], listed)

    def test_only_a_json_boolean_switches_a_server_off(self):
        # a flag with any other value is not one: the entry is launched
        for flag in ({"disabled": "true"}, {"disabled": 1}, {"enabled": 0},
                     {"enabled": "false"}, {"disabled": None},
                     {"disabled": []}):
            with self.subTest(flag):
                calls, results, err = self.run_deep({"s": dict(PLAIN, **flag)})
                self.assertEqual(len(calls), 1)

    def test_the_probe_itself_refuses(self):
        for flag in ({"disabled": True}, {"enabled": False}):
            probe = deep_mod.probe_server(dict(PLAIN, **flag))
            self.assertFalse(probe["ok"])
            self.assertIn("disabled", probe["error"])

    def test_how_an_entry_switches_itself_off(self):
        off = deep_mod.switched_off
        self.assertEqual(off({"disabled": True}), '"disabled": true')
        self.assertEqual(off({"enabled": False}), '"enabled": false')
        self.assertIsNone(off({"disabled": False, "enabled": True}))
        self.assertIsNone(off({}))
        self.assertIsNone(off("not an object"))


class TestTheListSaysWhatDownloadsCode(LaunchCase):
    """A server started by npx or uvx fetches its code when it starts, and
    when nothing in the config pins it, that is whatever the registry or the
    forge serves at that moment. The list says so on the line, in two fixed
    phrases (the line is made of fixed words and counts, never of the
    config's own text)."""

    def line_of(self, cfg, *argv, project=False):
        calls, results, err = self.run_deep({"s": cfg}, *argv,
                                            project=project)
        self.assertEqual(len(calls), 1, err)
        (line,) = [ln for ln in err.splitlines() if " runs: " in ln]
        return line

    def test_what_is_fetched_without_a_pin_is_marked(self):
        for label, cfg in (
                ("an unpinned package",
                 {"command": "npx", "args": ["-y", "some-server"]}),
                ("a tag", {"command": "npx",
                           "args": ["-y", "some-server@latest"]}),
                ("a Python package without a version",
                 {"command": "uvx", "args": ["some-server"]}),
                ("a git repository without a commit",
                 {"command": "uvx", "args": [
                     "--from", "git+https://github.com/o/r", "tool"]}),
                ("a github shorthand",
                 {"command": "npx", "args": ["-y", "github:o/r"]}),
                ("another registry", {"command": "npx", "args": [
                    "--registry", "https://registry.example.com/", "-y",
                    "some-server@1.2.3"]}),
                ("a registry in the environment", {
                    "command": "npx", "args": ["-y", "some-server@1.2.3"],
                    "env": {"NPM_CONFIG_REGISTRY":
                            "https://registry.example.com/"}}),
                ("through a shell", {"command": "bash", "args": [
                    "-lc", "npx -y some-server"]})):
            with self.subTest(label):
                line = self.line_of(cfg)
                self.assertIn("; downloads code", line)
                self.assertNotIn("connects to a remote server", line)

    def test_what_a_pin_fixes_is_not(self):
        for label, cfg in (
                ("a version", {"command": "npx",
                               "args": ["-y", "some-server@1.2.3"]}),
                ("a Python version", {"command": "uvx",
                                      "args": ["some-server==1.2.3"]}),
                ("a git commit", {"command": "uvx", "args": [
                    "--from", "git+https://github.com/o/r@" + "a" * 40,
                    "tool"]}),
                ("the default registry", {"command": "npx", "args": [
                    "--registry", "https://registry.npmjs.org/", "-y",
                    "some-server@1.2.3"]}),
                ("a script of your own", {"command": "node",
                                          "args": ["server.js"]}),
                ("a program of your own", {"command": "/opt/bin/server"})):
            with self.subTest(label):
                line = self.line_of(cfg)
                self.assertNotIn("downloads code", line)
                self.assertNotIn("connects", line)

    def test_a_bridge_is_said_to_connect_and_to_download_only_if_unpinned(self):
        pinned = {"command": "npx", "args": [
            "-y", "mcp-remote@0.1.29", "https://mcp.linear.app/sse"]}
        line = self.line_of(pinned)
        self.assertIn("; connects to a remote server", line)
        self.assertNotIn("downloads code", line)
        loose = dict(pinned, args=["-y", "mcp-remote",
                                   "https://mcp.linear.app/sse"])
        line = self.line_of(loose)
        self.assertIn("; downloads code; connects to a remote server", line)

    def test_a_host_you_trust_is_not_marked(self):
        registry = {"command": "npx", "args": [
            "--registry", "https://registry.corp.example/", "-y",
            "some-server@1.2.3"]}
        bridge = {"command": "npx", "args": [
            "-y", "mcp-remote@0.1.29", "https://mcp.corp.example/sse"]}
        for cfg in (registry, bridge):
            line = self.line_of(cfg)
            self.assertTrue("downloads code" in line
                            or "connects to" in line, line)
            line = self.line_of(cfg, "--allow-host", "*.corp.example")
            self.assertNotIn("downloads code", line)
            self.assertNotIn("connects to", line)

    def test_a_project_server_says_both(self):
        line = self.line_of({"command": "npx", "args": ["-y", "some-server"]},
                            "--probe-project", project=True)
        self.assertTrue(line.endswith(
            "; downloads code; starts in the current directory"), line)

    def test_the_marks_are_not_made_of_the_config(self):
        secret = "S3CR3T-MARK-VALUE"
        cfg = {"command": "npx", "args": ["-y", "some-server",
                                          "--token", secret]}
        line = self.line_of(cfg)
        self.assertNotIn(secret, line)

    def test_a_server_that_is_not_launched_is_not_marked(self):
        calls, results, err = self.run_deep({"s": {
            "command": "npx", "args": ["-y", "some-server"],
            "disabled": True}})
        self.assertNotIn("downloads", err)

    def test_the_readme_says_what_the_marks_mean(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "README.md"), encoding="utf-8") as f:
            readme = " ".join(f.read().split())
        section = readme.split("## `--deep`", 1)[1].split(" ## ", 1)[0]
        for needle in ("`downloads code`", "`connects to a remote server`"):
            self.assertIn(needle, section)


class TestTheWordsOfTheFlag(unittest.TestCase):
    @staticmethod
    def words(text):
        return " ".join(text.split())

    def test_the_help_of_the_flag_says_what_else_it_launches(self):
        text = self.words(cli_mod._build_parser().format_help())
        section = text.split("--probe-critical With", 1)[1].split(
            "--probe-project With", 1)[0]
        for needle in ("critical", "could not analyze", "plain http"):
            self.assertIn(needle, section)

    def test_the_readme_says_what_is_skipped(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "README.md"), encoding="utf-8") as f:
            readme = self.words(f.read())
        section = readme.split("## `--deep`", 1)[1].split("\n## ", 1)[0]
        for needle in ('`"disabled": true`', '`"enabled": false`',
                       "unverified"):
            self.assertIn(needle, section)

    def test_the_readme_says_what_is_left_alone(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "README.md"), encoding="utf-8") as f:
            readme = self.words(f.read())
        section = readme.split("## `--deep`", 1)[1].split("\n## ", 1)[0]
        for needle in ("could not analyze", "over plain http",
                       "`--probe-critical` launches them anyway"):
            self.assertIn(needle, section)


if __name__ == "__main__":
    unittest.main()
