"""`mcp-audit who-added`: which git commit and author put a server into a
config file. Local history only, and no repository setting may make it run
anything."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from _support import run_cli, write_json

GIT = shutil.which("git")


def git(cwd, *args, who=("Ann Author", "ann@example.com"), when="2026-01-02T03:04:05"):
    env = dict(os.environ, GIT_AUTHOR_NAME=who[0], GIT_AUTHOR_EMAIL=who[1],
               GIT_COMMITTER_NAME=who[0], GIT_COMMITTER_EMAIL=who[1],
               GIT_AUTHOR_DATE=when + " +0000",
               GIT_COMMITTER_DATE=when + " +0000",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@unittest.skipUnless(GIT, "needs git")
class TestWhoAdded(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix="whoadded-")
        self.addCleanup(shutil.rmtree, self.repo, True)
        git(self.repo, "init", "-q", "-b", "main")
        self.path = os.path.join(self.repo, ".mcp.json")

    def commit(self, servers, message, who, when):
        write_json(self.path, {"mcpServers": servers})
        git(self.repo, "add", ".mcp.json")
        git(self.repo, "commit", "-qm", message, who=who, when=when)
        return git(self.repo, "rev-parse", "HEAD")

    def run_it(self, *extra):
        return run_cli("who-added", "--config", self.path, *extra)

    def test_it_names_the_commit_and_author_that_added_each_server(self):
        a = self.commit({"files": {"command": "npx", "args": ["f"]}},
                        "add files", ("Ann Author", "ann@example.com"),
                        "2026-01-02T03:04:05")
        b = self.commit({"files": {"command": "npx", "args": ["f"]},
                         "notes": {"command": "npx", "args": ["n"]}},
                        "add the notes server", ("Bob Builder", "bob@example.com"),
                        "2026-02-03T04:05:06")
        code, out, err = self.run_it("--format", "json")
        self.assertEqual(code, 0, err)
        rows = {r["server"]: r for r in json.loads(out)}
        self.assertEqual(rows["files"]["commits"][-1]["hash"], a)
        self.assertEqual(rows["files"]["commits"][-1]["author"], "Ann Author")
        self.assertEqual(rows["notes"]["commits"][-1]["hash"], b)
        self.assertEqual(rows["notes"]["commits"][-1]["email"],
                         "bob@example.com")
        self.assertEqual(len(rows["notes"]["commits"]), 1)

    def test_human_output(self):
        a = self.commit({"files": {"command": "npx"}}, "add files",
                        ("Ann Author", "ann@example.com"), "2026-01-02T03:04:05")
        code, out, err = self.run_it()
        self.assertIn("added by:   " + a[:10] + " 2026-01-02 Ann Author "
                      "<ann@example.com> add files", out)

    def test_last_touch_is_the_latest_change(self):
        self.commit({"files": {"command": "npx", "args": ["1"]}}, "one",
                    ("Ann Author", "ann@example.com"), "2026-01-02T03:04:05")
        self.commit({"files": {"command": "npx", "args": ["2"]}}, "two",
                    ("Bob Builder", "bob@example.com"), "2026-03-03T03:04:05")
        # the server's key still occurs once: the pickaxe sees no change
        code, out, err = self.run_it("--format", "json")
        row = json.loads(out)[0]
        self.assertEqual(row["commits"][-1]["author"], "Ann Author")

    def test_a_server_removed_and_added_back_shows_both_commits(self):
        self.commit({"files": {"command": "x"}}, "add",
                    ("Ann Author", "ann@example.com"), "2026-01-01T00:00:00")
        self.commit({"other": {"command": "y"}}, "swap",
                    ("Bob Builder", "bob@example.com"), "2026-01-02T00:00:00")
        self.commit({"other": {"command": "y"}, "files": {"command": "x2"}},
                    "back", ("Cy Coder", "cy@example.com"),
                    "2026-01-03T00:00:00")
        code, out, err = self.run_it("--format", "json", "--server", "files")
        authors = [c["author"] for c in json.loads(out)[0]["commits"]]
        self.assertEqual(authors, ["Cy Coder", "Bob Builder", "Ann Author"])
        code, out, err = self.run_it("--server", "files")
        self.assertIn("added by:", out)
        self.assertIn("last touch:", out)

    def test_an_uncommitted_server(self):
        self.commit({"files": {"command": "x"}}, "add",
                    ("Ann Author", "ann@example.com"), "2026-01-01T00:00:00")
        write_json(self.path, {"mcpServers": {"files": {"command": "x"},
                                              "fresh": {"command": "y"}}})
        code, out, err = self.run_it()
        self.assertIn("no commit mentions it (it is not committed yet)", out)

    def test_a_file_outside_git(self):
        outside = tempfile.mkdtemp(prefix="nogit-")
        self.addCleanup(shutil.rmtree, outside, True)
        path = write_json(os.path.join(outside, "m.json"),
                          {"mcpServers": {"x": {"command": "y"}}})
        code, out, err = run_cli("who-added", "--config", path)
        self.assertEqual(code, 0, err)
        self.assertIn("history: not in a git repository", out)

    def test_an_untracked_file(self):
        write_json(self.path, {"mcpServers": {"x": {"command": "y"}}})
        code, out, err = self.run_it()
        self.assertIn("not tracked by git", out)

    def test_no_git_installed(self):
        write_json(self.path, {"mcpServers": {"x": {"command": "y"}}})
        from unittest import mock
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            code, out, err = self.run_it()
        self.assertEqual(code, 0)
        self.assertIn("git is not installed", out)

    def test_output_is_clean_of_terminal_tricks(self):
        self.commit({"files": {"command": "x"}}, "add \x1b[2Jboom‮",
                    ("Ann \x1b[31m", "a@example.com"), "2026-01-01T00:00:00")
        code, out, err = self.run_it()
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)

    def test_a_repository_cannot_make_it_run_a_command(self):
        marker = os.path.join(self.repo, "ran")
        self.commit({"files": {"command": "x"}}, "add",
                    ("Ann Author", "ann@example.com"), "2026-01-01T00:00:00")
        with open(os.path.join(self.repo, ".gitattributes"), "w") as f:
            f.write("*.json diff=evil\n")
        script = os.path.join(self.repo, "evil.sh")
        with open(script, "w") as f:
            f.write("#!/bin/sh\ntouch '%s'\ncat \"$1\"\n" % marker)
        os.chmod(script, 0o755)
        git(self.repo, "config", "diff.evil.textconv", script)
        git(self.repo, "config", "diff.external", script)
        git(self.repo, "config", "core.fsmonitor", script)
        git(self.repo, "config", "core.pager", script)
        # a change so that the history walk has a diff to look at
        write_json(self.path, {"mcpServers": {"files": {"command": "x"},
                                              "more": {"command": "y"}}})
        git(self.repo, "add", ".mcp.json")
        git(self.repo, "commit", "-qm", "more", who=("B", "b@example.com"))
        if os.path.exists(marker):      # git itself ran the hooks just now
            os.unlink(marker)
        code, out, err = self.run_it()
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.exists(marker), "the repository ran a command")

    def test_nothing_is_fetched(self):
        # the remote does not exist; if it were contacted this would fail
        self.commit({"files": {"command": "x"}}, "add",
                    ("Ann Author", "ann@example.com"), "2026-01-01T00:00:00")
        git(self.repo, "remote", "add", "origin", "http://127.0.0.1:9/none")
        code, out, err = self.run_it()
        self.assertEqual(code, 0, err)
        self.assertIn("added by:", out)

    def test_a_server_name_with_quotes_is_looked_up_exactly(self):
        self.commit({'we"ird': {"command": "x"}}, "add",
                    ("Ann Author", "ann@example.com"), "2026-01-01T00:00:00")
        code, out, err = self.run_it("--format", "json")
        self.assertEqual(len(json.loads(out)[0]["commits"]), 1)


if __name__ == "__main__":
    unittest.main()
