"""The indicator feed: only what a public report lists is in it, a match is
a finding, and a user's own feed can extend it."""

import json
import os
import tempfile
import shutil
import unittest

from mcp_audit import detectors, iocs

from _support import run_cli, write_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Exactly what the Pillar Security report (12 Aug 2026) lists in its
#: indicator table, minus the Bitcoin address (it cannot appear in a config).
#: Adding an indicator to the feed without a source for it fails this test.
DEADBUGZ = {
    ("host", "productivity-suite-mcp.onrender.com", "active"),
    ("host", "promo-surname-xml-quantum.trycloudflare.com", "historical"),
    ("path", ".config/.cache/.sys/.deadbug-mcp.py", "active"),
    ("server-name", "productivity-suite", "active"),
    ("github-repo", "zellkernel/productivity-suite-mcp", "active"),
    ("github-account", "zellkernel", "active"),
}


def ioc_findings(name, cfg, feed=None):
    return [f for f in detectors.audit_server(name, cfg, [], (), feed)
            if f["check"] == "known-ioc"]


class TestTheShippedFeed(unittest.TestCase):
    def test_it_holds_deadbugz_and_nothing_unsourced(self):
        feed = iocs.default_feed()
        self.assertEqual([c["id"] for c in feed], ["deadbugz"])
        got = {(i["type"], i["value"], i.get("status", "active"))
               for i in feed[0]["indicators"]}
        self.assertEqual(got, DEADBUGZ)

    def test_each_campaign_names_its_source(self):
        for c in iocs.default_feed():
            self.assertTrue(c["source"].startswith("https://"))
            self.assertTrue(c["published"])
            self.assertTrue(c["checked"])

    def test_it_is_in_the_wheel_data(self):
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
            self.assertIn("iocs.json", f.read())
        with open(os.path.join(ROOT, "MANIFEST.in"), encoding="utf-8") as f:
            self.assertIn("iocs.json", f.read())


class TestMatching(unittest.TestCase):
    def test_the_endpoint_as_a_url(self):
        f = ioc_findings("x", {"url": "https://productivity-suite-mcp."
                                      "onrender.com/mcp"})
        self.assertEqual([x["severity"] for x in f], ["critical"])
        self.assertIn("Deadbugz", f[0]["message"])
        self.assertIn("Pillar Security", f[0]["message"])

    def test_the_endpoint_given_to_a_bridge(self):
        f = ioc_findings("x", {"command": "npx", "args": [
            "-y", "mcp-remote",
            "https://PRODUCTIVITY-SUITE-MCP.onrender.com/mcp"]})
        self.assertEqual(len(f), 1)

    def test_a_subdomain_of_the_host_matches(self):
        f = ioc_findings("x", {"url": "https://a.productivity-suite-mcp."
                                      "onrender.com/"})
        self.assertEqual(len(f), 1)

    def test_a_host_that_only_ends_the_same_way_does_not(self):
        for url in ("https://notproductivity-suite-mcp.onrender.com/",
                    "https://productivity-suite-mcp.onrender.com.example.org/",
                    "https://productivity-suite-mcp.onrender.community/",
                    "https://other.onrender.com/mcp"):
            self.assertEqual(ioc_findings("x", {"url": url}), [], url)

    def test_the_historical_host_is_high_not_critical(self):
        f = ioc_findings("x", {"url": "https://promo-surname-xml-quantum."
                                      "trycloudflare.com/mcp"})
        self.assertEqual([x["severity"] for x in f], ["high"])
        self.assertIn("earlier indicator", f[0]["message"])

    def test_the_file_path(self):
        for arg in ("/home/me/.config/.cache/.sys/.deadbug-mcp.py",
                    "~/.config/.cache/.sys/.deadbug-mcp.py",
                    "C:\\Users\\me\\.config\\.cache\\.sys\\.deadbug-mcp.py"):
            f = ioc_findings("x", {"command": "python3", "args": [arg]})
            self.assertEqual([x["severity"] for x in f], ["critical"], arg)

    def test_the_server_name_alone_is_only_medium(self):
        f = ioc_findings("Productivity-Suite", {"command": "npx",
                                                "args": ["something"]})
        self.assertEqual([x["severity"] for x in f], ["medium"])
        self.assertIn("proves nothing", f[0]["message"])
        self.assertEqual(ioc_findings("productivity-suites",
                                      {"command": "x"}), [])

    def test_the_repository_and_the_account(self):
        f = ioc_findings("x", {"command": "npx", "args": [
            "git+https://github.com/zellkernel/productivity-suite-mcp"]})
        self.assertEqual(sorted(x["severity"] for x in f),
                         ["critical", "high"])
        f = ioc_findings("x", {"command": "npx", "args": [
            "github:zellkernel/another-thing"]})
        self.assertEqual([x["severity"] for x in f], ["high"])
        self.assertEqual(ioc_findings("x", {"command": "npx", "args": [
            "github:zellkernelx/other"]}), [])

    def test_a_clean_server_has_no_ioc_finding(self):
        self.assertEqual(ioc_findings("files", {
            "command": "npx", "args": ["-y", "@modelcontextprotocol/"
                                       "server-filesystem@1.0.0", "/tmp"]}), [])

    def test_an_env_value_is_matched_but_never_shown(self):
        f = ioc_findings("x", {"command": "node", "args": ["s.js"],
                               "env": {"UPSTREAM": "https://user:pw123@"
                                       "productivity-suite-mcp.onrender.com/x"}})
        self.assertEqual(len(f), 1)
        self.assertNotIn("pw123", f[0]["message"])

    def test_one_finding_per_indicator(self):
        f = ioc_findings("x", {"url": "https://productivity-suite-mcp."
                                      "onrender.com/a", "args": [
            "https://productivity-suite-mcp.onrender.com/b"]})
        self.assertEqual(len(f), 1)

    def test_it_is_part_of_the_normal_audit(self):
        self.assertIn(detectors.detect_known_ioc, detectors.STATIC_DETECTORS)
        found = detectors.audit_server(
            "x", {"url": "https://productivity-suite-mcp.onrender.com/mcp"})
        self.assertTrue(any(f["check"] == "known-ioc"
                            and f["severity"] == "critical" for f in found))


class TestACustomFeed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ioc-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.feed = os.path.join(self.tmp, "feed.json")
        write_json(self.feed, {"version": 1, "campaigns": [{
            "id": "mine", "title": "Mine", "indicators": [
                {"type": "host", "value": "bad.example.net"},
                {"type": "package", "value": "evil-mcp"}]}]})

    def test_it_extends_the_built_in_one(self):
        campaigns = iocs.load_feed([self.feed])
        self.assertEqual([c["id"] for c in campaigns], ["deadbugz", "mine"])
        f = ioc_findings("x", {"url": "https://bad.example.net/"}, campaigns)
        self.assertEqual([x["severity"] for x in f], ["critical"])
        f = ioc_findings("x", {"command": "npx",
                               "args": ["-y", "evil-mcp@1.0.0"]}, campaigns)
        self.assertEqual(len(f), 1)

    def test_on_the_command_line(self):
        cfg = write_json(os.path.join(self.tmp, "m.json"), {"mcpServers": {
            "x": {"url": "https://bad.example.net/"}}})
        code, out, err = run_cli("--config", cfg, "--ioc-feed", self.feed,
                                 "--format", "json")
        doc = json.loads(out)
        checks = [f["check"] for f in doc["results"][0]["findings"]]
        self.assertIn("known-ioc", checks)
        code, out, err = run_cli("--config", cfg, "--format", "json")
        checks = [f["check"] for f in json.loads(out)["results"][0]["findings"]]
        self.assertNotIn("known-ioc", checks)

    def test_an_empty_feed_is_fine(self):
        write_json(self.feed, {"version": 1, "campaigns": []})
        self.assertEqual([c["id"] for c in iocs.load_feed([self.feed])],
                         ["deadbugz"])

    def test_bad_feeds_are_refused_not_ignored(self):
        bad = [{"version": 2, "campaigns": []}, [], {"version": 1},
               {"version": 1, "campaigns": [{"id": "a"}]},
               {"version": 1, "campaigns": [{"id": "a", "title": "A",
                "indicators": [{"type": "nonsense", "value": "x"}]}]},
               {"version": 1, "campaigns": [{"id": "a", "title": "A",
                "indicators": [{"type": "host", "value": ""}]}]},
               {"version": 1, "campaigns": [{"id": "a", "title": "A",
                "indicators": [{"type": "host", "value": "x",
                                "status": "maybe"}]}]}]
        cfg = write_json(os.path.join(self.tmp, "m.json"),
                         {"mcpServers": {"x": {"command": "y"}}})
        for doc in bad:
            write_json(self.feed, doc)
            with self.assertRaises(iocs.IocFeedError):
                iocs.load_feed([self.feed])
            code, out, err = run_cli("--config", cfg, "--ioc-feed", self.feed)
            self.assertEqual(code, 2, doc)
            self.assertNotIn("Traceback", err)

    def test_a_missing_or_unreadable_feed(self):
        with self.assertRaises(iocs.IocFeedError):
            iocs.load_feed([os.path.join(self.tmp, "nope.json")])
        with open(self.feed, "w") as f:
            f.write("{not json")
        with self.assertRaises(iocs.IocFeedError):
            iocs.load_feed([self.feed])


if __name__ == "__main__":
    unittest.main()
