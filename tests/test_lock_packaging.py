"""The files that ship around the lockfile feature: the spec, the vectors, the
workflow example, the pre-commit hooks and the README."""

import os
import re
import unittest

from mcp_audit import __version__

from test_release_workflow import run_steps

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestShippedFiles(unittest.TestCase):
    def test_the_sdist_carries_what_its_own_tests_read(self):
        manifest = read("MANIFEST.in")
        for needed in ("recursive-include .github", "recursive-include docs",
                       "recursive-include tests", "mcp_audit/iocs.json",
                       ".pre-commit-hooks.yaml", "recursive-include examples"):
            self.assertIn(needed, manifest)

    def test_the_workflow_example_runs_real_commands(self):
        steps = run_steps(read("examples", "github-action.yml"))
        text = "\n".join(s for _, s in steps)
        self.assertIn("mcp-audit verify", text)
        self.assertIn("--from-tools-json", text)
        self.assertIn("--launch", text)
        self.assertIn("mcp-audit==" + __version__, text)

    def test_the_launching_job_is_not_run_for_pull_requests(self):
        text = read("examples", "github-action.yml")
        launch_job = text[text.index("servers-unchanged:"):]
        self.assertIn("github.event_name == 'schedule'", launch_job)
        self.assertIn("forks", launch_job)

    def test_the_hooks_file(self):
        text = read(".pre-commit-hooks.yaml")
        ids = re.findall(r"(?m)^- id: (\S+)", text)
        self.assertEqual(ids, ["mcp-audit-verify", "mcp-audit-scan"])
        for field in ("name", "entry", "language", "files"):
            self.assertEqual(len(re.findall(r"(?m)^  %s:" % field, text)), 2)
        self.assertIn("language: python", text)
        self.assertIn("rev: v" + __version__, text)
        self.assertNotIn("\t", text)

    def test_the_entry_of_the_verify_hook_is_a_real_command_line(self):
        text = read(".pre-commit-hooks.yaml")
        entry = re.search(r"(?m)^  entry: (mcp-audit verify .*)$", text).group(1)
        from _support import run_cli
        import json
        import tempfile
        import shutil
        # the arguments must be accepted by the parser (no such files here:
        # the run ends with a clear error, not a usage error)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        argv = entry.split()[1:]
        i = argv.index("--lockfile")
        argv[i + 1] = os.path.join(tmp, "mcp.lock")
        i = argv.index("--config")
        argv[i + 1] = os.path.join(tmp, ".mcp.json")
        with open(argv[i + 1], "w") as f:
            json.dump({"mcpServers": {"a": {"command": "x"}}}, f)
        code, out, err = run_cli(*argv)
        self.assertEqual(code, 2)
        self.assertIn("no lockfile", err)

    def test_the_manifest_ships_everything(self):
        manifest = read("MANIFEST.in")
        for item in ("iocs.json", ".pre-commit-hooks.yaml", "docs",
                     "examples"):
            self.assertIn(item, manifest)
        self.assertIn("iocs.json", read("pyproject.toml"))

    def test_the_readme_documents_the_feature(self):
        readme = read("README.md")
        for word in ("mcp-audit lock", "mcp-audit verify", "who-added",
                     "docs/LOCKFILE.md", "--ioc-feed", "uvx mcp-audit",
                     "pipx run", "rug pull", "--accept-changes",
                     ".pre-commit-hooks.yaml", "examples/github-action.yml",
                     "known-ioc"):
            self.assertIn(word, readme, word)

    def test_the_changelog_has_this_version(self):
        self.assertIn("## " + __version__, read("CHANGELOG.md"))

    def test_the_spec_names_the_file_format(self):
        spec = read("docs", "LOCKFILE.md")
        for word in ("command_fingerprint", "description_sha256",
                     "schema_sha256", "annotations_sha256", "NFC",
                     "mcp.lock"):
            self.assertIn(word, spec)


if __name__ == "__main__":
    unittest.main()
