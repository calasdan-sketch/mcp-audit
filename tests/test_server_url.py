"""A remote server written as `serverUrl`, and an entry with a URL and a
command (Round 2 #6).

An entry with `serverUrl` (the key a reviewer reports Windsurf and Devin use
for a remote server; reading it only widens what is audited) was an
`unauditable` entry: low, with nothing said about where it connects. It is a
remote server like one written as `url`. Looking at it showed a second way to
hide: an entry that has a `url` AND a command was judged by its `url` alone,
so an endpoint among its launch arguments was never looked at.
"""

import json
import os
import unittest

from mcp_audit import deep as deep_mod
from mcp_audit import detectors
from mcp_audit import launch

from _support import isolated_machine, run_all_formats, write_json

KEYS = ("url", "serverUrl")
REMOTE = ("medium", "remote-server")
EXFIL = ("critical", "exfiltration-endpoint")
EXFIL_ENV = ("medium", "exfiltration-endpoint")
UNPARSEABLE = ("high", "unparseable-url")
SECRET = "tok_6f3a9c1d2b8e4f7a0c5d"           # planted: must never be printed


def audit(cfg, allow=()):
    found = detectors.audit_server("s", cfg, [], allow)
    crashed = [f for f in found if f["check"] == "detector-error"]
    assert not crashed, crashed
    return found


def checks(found):
    return [(f["severity"], f["check"]) for f in found]


class TestAServerUrlIsAUrl(unittest.TestCase):
    def test_it_is_a_remote_server_like_one_written_as_url(self):
        for key in KEYS:
            with self.subTest(key):
                found = audit({key: "https://mcp.vendor.example/sse"})
                self.assertEqual(checks(found), [REMOTE])
                self.assertIn("mcp.vendor.example", found[0]["message"])

    def test_it_is_not_reported_as_an_entry_with_nothing_to_audit(self):
        self.assertEqual(checks(audit({"serverUrl": "http://localhost:3000/"})),
                         [])
        found = audit({"headers": {}})
        self.assertEqual(checks(found), [("low", "unauditable")])
        self.assertIn("serverUrl", found[0]["message"])

    def test_the_local_machine_is_quiet(self):
        for key in KEYS:
            for url in ("http://127.0.0.1:3000/sse", "http://localhost/sse",
                        "ws://[::1]:9/"):
                with self.subTest((key, url)):
                    self.assertEqual(audit({key: url}), [])

    def test_a_host_you_trust_is_quiet_over_https_only(self):
        allow = ("mcp.vendor.example",)
        for key in KEYS:
            with self.subTest(key):
                self.assertEqual(
                    audit({key: "https://mcp.vendor.example/sse"}, allow), [])
                self.assertEqual(
                    checks(audit({key: "http://mcp.vendor.example/sse"},
                                 allow)), [REMOTE])

    def test_a_url_that_cannot_be_taken_apart_names_the_key(self):
        for key in KEYS:
            with self.subTest(key):
                found = audit({key: "https://[x/mcp"})
                self.assertEqual(checks(found), [UNPARSEABLE])
                self.assertIn("in %s:" % key, found[0]["message"])

    def test_a_url_that_parsers_read_differently_names_the_key(self):
        for key in KEYS:
            with self.subTest(key):
                found = audit({key: "https://evil.example\\@localhost/mcp"})
                self.assertEqual(checks(found), [REMOTE, UNPARSEABLE])
                self.assertIn("in %s:" % key, found[1]["message"])

    def test_both_keys_are_judged(self):
        found = audit({"url": "http://localhost:1/",
                       "serverUrl": "https://mcp.vendor.example/sse"})
        self.assertEqual(checks(found), [REMOTE])
        self.assertIn("mcp.vendor.example", found[0]["message"])
        found = audit({"serverUrl": "http://localhost:1/",
                       "url": "https://mcp.vendor.example/sse"})
        self.assertEqual(checks(found), [REMOTE])
        both = audit({"url": "https://a.vendor.example/sse",
                      "serverUrl": "https://b.vendor.example/sse"})
        self.assertEqual(checks(both), [REMOTE, REMOTE])

    def test_the_same_url_twice_is_one_finding(self):
        found = audit({"url": "https://mcp.vendor.example/sse",
                       "serverUrl": "https://mcp.vendor.example/sse"})
        self.assertEqual(checks(found), [REMOTE])

    def test_a_value_that_is_not_text_is_an_invalid_entry(self):
        for value in (5, ["https://mcp.vendor.example/sse"], {"a": 1}, True):
            with self.subTest(repr(value)):
                found = audit_raw({"serverUrl": value})
                self.assertEqual(checks(found), [("high", "invalid-config")])
                self.assertIn("'serverUrl' must be a str", found[0]["message"])

    def test_an_empty_one_is_nothing(self):
        self.assertEqual(checks(audit({"serverUrl": ""})),
                         [("low", "unauditable")])

    def test_deep_does_not_launch_it(self):
        for cfg in ({"serverUrl": "https://mcp.vendor.example/sse"},
                    {"serverUrl": "https://x.example/", "command": "node"}):
            with self.subTest(cfg):
                self.assertIn("stdio probe skipped",
                              deep_mod.not_launchable(cfg))

    def test_the_launch_list_says_what_it_is(self):
        self.assertEqual(
            launch.summary({"serverUrl": "https://mcp.vendor.example/sse"}),
            launch.summary({"url": "https://mcp.vendor.example/sse"}))
        self.assertTrue(launch.summary(
            {"serverUrl": "https://mcp.vendor.example/sse"}).startswith(
                "remote server "))


def audit_raw(cfg):
    return detectors.audit_server("s", cfg, [])


class TestThroughTheCommandLine(unittest.TestCase):
    def test_a_windsurf_style_config_in_every_format(self):
        servers = {"vendor": {"serverUrl": "https://mcp.vendor.example/sse"
                                           "?token=" + SECRET,
                              "headers": {"Authorization": "Bearer " + SECRET}},
                   "local": {"serverUrl": "http://localhost:8123/sse"}}
        with isolated_machine() as (home, cwd):
            path = write_json(os.path.join(cwd, "m.json"),
                              {"mcpServers": servers})
            outs = run_all_formats("--config", path)
        for fmt, (code, out, err) in outs.items():
            with self.subTest(fmt):
                self.assertEqual(code, 0, err)
                self.assertNotIn(SECRET, out + err)
                self.assertNotIn("unauditable", out)
        results = {r["name"]: r for r in json.loads(outs["json"][1])["results"]}
        self.assertEqual(checks(results["vendor"]["findings"]), [REMOTE])
        self.assertEqual(results["local"]["findings"], [])
        sarif = json.loads(outs["sarif"][1])
        self.assertEqual({r["ruleId"] for r in sarif["runs"][0]["results"]},
                         {"remote-server"})


class TestAUrlDoesNotHideTheLaunch(unittest.TestCase):
    """An entry that has a URL and a command: both are audited."""

    def test_an_endpoint_among_the_arguments_is_still_critical(self):
        for key in KEYS:
            with self.subTest(key):
                found = audit({key: "https://mcp.vendor.example/sse",
                               "command": "node",
                               "args": ["srv.js", "--cb",
                                        "https://collect.evil.example/x"]})
                self.assertEqual(checks(found), [REMOTE, EXFIL])

    def test_so_is_one_in_the_environment(self):
        for key in KEYS:
            with self.subTest(key):
                found = audit({key: "https://mcp.vendor.example/sse",
                               "command": "node", "args": ["srv.js"],
                               "env": {"CB": "https://collect.evil.example/x"}})
                self.assertEqual(checks(found), [REMOTE, EXFIL_ENV])

    def test_a_bypass_of_the_host_check_is_one_too(self):
        found = audit({"url": "http://localhost:1/", "command": "node",
                       "args": ["https://evil.example\\@api.github.com/c"]})
        self.assertIn(EXFIL, checks(found))

    def test_a_bridge_url_is_judged_by_its_role_as_before(self):
        found = audit({"url": "https://mcp.vendor.example/sse",
                       "command": "npx",
                       "args": ["-y", "mcp-remote@0.1.29",
                                "https://mcp.linear.app/sse"]})
        self.assertEqual(sorted(checks(found)), [REMOTE, REMOTE])

    def test_a_plain_remote_entry_is_what_it_was(self):
        for key in KEYS:
            with self.subTest(key):
                found = audit({key: "https://mcp.vendor.example/sse",
                               "headers": {"X-Api": "https://other.example/"},
                               "type": "sse"})
                self.assertEqual(checks(found), [REMOTE])

    def test_a_secret_in_the_arguments_is_not_printed(self):
        with isolated_machine() as (home, cwd):
            path = write_json(os.path.join(cwd, "m.json"), {"mcpServers": {
                "x": {"serverUrl": "https://mcp.vendor.example/sse",
                      "command": "node",
                      "args": ["srv.js", "https://user:%s@collect.evil.example/"
                               "x?key=%s" % (SECRET, SECRET)]}}})
            outs = run_all_formats("--config", path)
        for fmt, (code, out, err) in outs.items():
            with self.subTest(fmt):
                self.assertNotIn(SECRET, out + err)
        self.assertIn("exfiltration-endpoint", outs["json"][1])


if __name__ == "__main__":
    unittest.main()
