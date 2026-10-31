"""--deep: where a server starts, and where its program comes from (Round 3 #1).

`mcp-audit --deep` started every server in the directory it was run from, and
found the program with shutil.which, which on Windows looks in the current
directory first. Run inside a repository you have just cloned - the README's
own "audit a clone" case - it ran the clone's files through your own servers:
a committed node_modules copy for `npx -y @acme/mcp-thing`, a `.npmrc` that
moves the registry. Now a server starts in a new, empty, private directory
(removed afterwards), a server from a project file starts in the project, and
the program is looked up on PATH only.

No real npx is needed: a fake one on PATH records where it was started and
runs the package binary of the node_modules in that directory, which is what
the real one does for a dependency that is already installed.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock

from mcp_audit import cli as cli_mod
from mcp_audit import deep as deep_mod

from _support import (isolated_machine, private_tempdir, run_cli, write_json,
                      write_text)
from test_deep_probe import server

POSIX = os.name == "posix"
NEEDS_SHEBANG = unittest.skipUnless(
    POSIX and " " not in sys.executable,
    "these write a script with a #! line (POSIX, and no space in the path of "
    "the interpreter); the Windows lookup is covered by TestFindProgram")


def same_dir(a, b):
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(
        os.path.realpath(b))


def report_of(probe):
    """What fixtures/cwd_mcp_server.py says about where it was started."""
    assert probe["ok"], probe
    return json.loads(probe["tools"][0]["description"])


def plant_clone(clone):
    """What a cloned repository can hold that a program looks for."""
    write_text(os.path.join(clone, "package.json"), "{}")
    write_text(os.path.join(clone, ".npmrc"), "registry=http://127.0.0.1:9/\n")
    write_text(os.path.join(clone, "node_modules", "x", "index.js"), "")


class TestTheStartDirectory(unittest.TestCase):
    def test_it_is_an_empty_directory_not_the_one_mcp_audit_was_run_from(self):
        with isolated_machine(chdir=True) as (home, clone), private_tempdir():
            plant_clone(clone)
            before = sorted(os.listdir(clone))
            report = report_of(deep_mod.probe_server(
                server("cwd_mcp_server.py")))
            self.assertFalse(same_dir(report["cwd"], clone), report)
            self.assertEqual(report["entries"], [], "not empty")
            self.assertEqual(sorted(os.listdir(clone)), before)

    @unittest.skipUnless(POSIX, "permission bits")
    def test_it_is_private(self):
        with isolated_machine(chdir=True), private_tempdir():
            report = report_of(deep_mod.probe_server(
                server("cwd_mcp_server.py")))
        self.assertEqual(report["mode"] & 0o077, 0, oct(report["mode"]))

    def test_it_is_in_the_temp_directory_and_gone_when_the_probe_ends(self):
        with isolated_machine(chdir=True), private_tempdir() as base:
            marker = os.path.join(base, "where")   # a file, so not "empty"
            report = report_of(deep_mod.probe_server(
                server("cwd_mcp_server.py", marker)))
            self.assertTrue(same_dir(os.path.dirname(report["cwd"]), base),
                            (report["cwd"], base))
            self.assertFalse(os.path.exists(report["cwd"]))
            os.remove(marker)
            self.assertEqual(os.listdir(base), [])

    def test_it_is_gone_however_the_probe_ends(self):
        with isolated_machine(chdir=True), private_tempdir() as base, \
                unittest.mock.patch.object(deep_mod, "MAX_LINE_BYTES", 100000):
            for label, cfg, timeout in (
                    ("a silent server", server("silent_mcp_server.py"), 1),
                    ("one that dies", server("dying_mcp_server.py"), 15),
                    ("one that floods",
                     server("flood_mcp_server.py", "longline"), 10),
                    ("a program that is not on PATH",
                     {"command": "no-such-program-here"}, 15),
                    ("a path that is not there",
                     {"command": os.path.join(base, "nope")}, 15)):
                with self.subTest(label):
                    probe = deep_mod.probe_server(cfg, timeout=timeout)
                    self.assertFalse(probe["ok"], label)
                    self.assertEqual(os.listdir(base), [], label)
            with self.subTest("a signal"):
                with unittest.mock.patch.object(
                        deep_mod, "_converse",
                        side_effect=deep_mod.Interrupted(15)):
                    with self.assertRaises(deep_mod.Interrupted):
                        deep_mod.probe_server(server("cwd_mcp_server.py"))
                self.assertEqual(os.listdir(base), [])

    def test_a_directory_given_is_where_it_starts_and_it_is_kept(self):
        with isolated_machine(chdir=True) as (home, clone), \
                private_tempdir() as base:
            keep = write_text(os.path.join(clone, "keep.txt"), "mine")
            report = report_of(deep_mod.probe_server(
                server("cwd_mcp_server.py"), cwd=clone))
            self.assertTrue(same_dir(report["cwd"], clone), report)
            self.assertEqual(report["entries"], ["keep.txt"])
            with open(keep) as f:
                self.assertEqual(f.read(), "mine")
            self.assertEqual(os.listdir(base), [], "no scratch directory")

    def test_a_directory_given_that_is_not_there_is_a_failed_probe(self):
        with isolated_machine(chdir=True), private_tempdir() as base:
            probe = deep_mod.probe_server(
                server("cwd_mcp_server.py"),
                cwd=os.path.join(base, "gone"))
            self.assertFalse(probe["ok"])
            self.assertIn("launch failed", probe["error"])

    def test_no_scratch_directory_to_make_is_a_failed_probe(self):
        with isolated_machine(chdir=True), private_tempdir():
            with unittest.mock.patch.object(
                    deep_mod.tempfile, "mkdtemp",
                    side_effect=PermissionError(13, "denied")):
                probe = deep_mod.probe_server(server("cwd_mcp_server.py"))
        self.assertFalse(probe["ok"])
        self.assertIn("launch failed", probe["error"])
        self.assertIn("directory", probe["error"])


class TestInsideAClone(unittest.TestCase):
    """The README's "audit a clone": mcp-audit is run in a repository that is
    not yours, and the servers are the ones in your own files."""

    def setUp(self):
        self.enter = isolated_machine(chdir=True)
        self.home, self.clone = self.enter.__enter__()
        self.addCleanup(self.enter.__exit__, None, None, None)
        self.base = self.enter_context_private()

    def enter_context_private(self):
        ctx = private_tempdir()
        base = ctx.__enter__()
        self.addCleanup(ctx.__exit__, None, None, None)
        return base

    def where_it_started(self, name="where"):
        return os.path.join(self.base, name)

    def test_your_own_server_does_not_start_in_the_clone(self):
        plant_clone(self.clone)
        marker = self.where_it_started()
        write_json(os.path.join(self.home, ".claude.json"), {"mcpServers": {
            "mine": server("cwd_mcp_server.py", marker)}})
        code, out, err = run_cli("--deep", "--format", "json")
        self.assertEqual(code, 0, err)
        with open(marker) as f:
            started_in = f.read()
        self.assertFalse(same_dir(started_in, self.clone), started_in)
        self.assertNotIn(self.clone, err.replace(started_in, ""))

    def test_a_server_from_a_file_you_name_does_not_either(self):
        plant_clone(self.clone)
        marker = self.where_it_started()
        path = write_json(os.path.join(self.clone, "named.json"), {
            "mcpServers": {"named": server("cwd_mcp_server.py", marker)}})
        code, out, err = run_cli("--config", path, "--deep",
                                 "--format", "json")
        self.assertEqual(code, 0, err)
        with open(marker) as f:
            self.assertFalse(same_dir(f.read(), self.clone))

    def test_a_project_server_starts_in_the_project_when_you_allow_it(self):
        marker = self.where_it_started()
        write_json(os.path.join(self.clone, ".mcp.json"), {"mcpServers": {
            "proj": server("cwd_mcp_server.py", marker)}})
        code, out, err = run_cli("--deep", "--probe-project",
                                 "--format", "json")
        self.assertEqual(code, 0, err)
        with open(marker) as f:
            self.assertTrue(same_dir(f.read(), self.clone))
        self.assertTrue(os.path.isfile(os.path.join(self.clone, ".mcp.json")))

    def test_the_launch_list_says_where_each_one_starts(self):
        write_json(os.path.join(self.home, ".claude.json"), {"mcpServers": {
            "mine": server("cwd_mcp_server.py")}})
        write_json(os.path.join(self.clone, ".mcp.json"), {"mcpServers": {
            "proj": server("cwd_mcp_server.py")}})
        code, out, err = run_cli("--deep", "--probe-project",
                                 "--format", "json")
        lines = [ln for ln in err.splitlines()]
        header = " ".join(lines)
        self.assertIn("empty temporary directory", header)
        (mine,) = [ln for ln in lines if "'mine'" in ln and "runs:" in ln]
        (proj,) = [ln for ln in lines if "'proj'" in ln and "runs:" in ln]
        self.assertNotIn("current directory", mine)
        self.assertIn("starts in the current directory", proj)

    @NEEDS_SHEBANG
    def test_the_clones_files_do_not_run_through_your_npx(self):
        # The reviewer's repro: `npx -y @acme/mcp-thing` in the user's config,
        # a committed node_modules copy of the package in the clone.
        bindir = os.path.join(self.base, "bin")
        log = os.path.join(self.base, "npx.log")
        make_npx(bindir, "npx")
        evil = make_clone_binary(self.clone, "mcp-thing")
        write_json(os.path.join(self.home, ".claude.json"), {"mcpServers": {
            "thing": {"command": "npx", "args": ["-y", "@acme/mcp-thing"],
                      "env": {"NPX_LOG": log}}}})
        with unittest.mock.patch.dict(os.environ, {"PATH": bindir}):
            code, out, err = run_cli("--deep", "--format", "json")
        self.assertEqual(code, 0, err)
        with open(log) as f:
            (started_in,) = f.read().splitlines()   # npx did start ...
        self.assertFalse(same_dir(started_in, self.clone), started_in)
        self.assertFalse(os.path.exists(evil), "the clone's code ran")

    @NEEDS_SHEBANG
    def test_an_empty_entry_in_path_does_not_mean_the_clone(self):
        # PATH=":/usr/bin" searches the current directory first, for the shell
        # and for shutil.which alike
        bindir = os.path.join(self.base, "bin")
        log = os.path.join(self.base, "npx.log")
        make_npx(bindir, "npx")
        evil = make_clone_binary(self.clone, "npx", at_top=True)
        write_json(os.path.join(self.home, ".claude.json"), {"mcpServers": {
            "thing": {"command": "npx", "args": ["-y", "pkg"],
                      "env": {"NPX_LOG": log}}}})
        with unittest.mock.patch.dict(os.environ,
                                      {"PATH": os.pathsep + bindir}):
            code, out, err = run_cli("--deep", "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.exists(log), "your own npx was not used")
        self.assertFalse(os.path.exists(evil), "the clone's npx ran")

    @NEEDS_SHEBANG
    def test_a_program_is_looked_up_on_path_not_by_shutil_which(self):
        # shutil.which tries the current directory first on Windows (every
        # Python version up to 3.14); the lookup here must not depend on it
        bindir = os.path.join(self.base, "bin")
        log = os.path.join(self.base, "npx.log")
        make_npx(bindir, "npx")
        write_json(os.path.join(self.home, ".claude.json"), {"mcpServers": {
            "thing": {"command": "npx", "args": ["-y", "pkg"],
                      "env": {"NPX_LOG": log}}}})
        with unittest.mock.patch.dict(os.environ, {"PATH": bindir}), \
                unittest.mock.patch.object(
                    deep_mod.shutil, "which",
                    side_effect=AssertionError("shutil.which was used")):
            code, out, err = run_cli("--deep", "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.exists(log))


def make_npx(directory, name):
    """A fake `npx` that records the directory it was started in (to the file
    named in $NPX_LOG), then runs ./node_modules/.bin/<package> if there is
    one, as the real npx does for a dependency that is already installed."""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    write_text(path, "#!%s\n" % sys.executable + (
        "import os, sys\n"
        "with open(os.environ['NPX_LOG'], 'a') as f:\n"
        "    f.write(os.getcwd() + '\\n')\n"
        "package = [a for a in sys.argv[1:] if not a.startswith('-')][0]\n"
        "binary = os.path.join(os.getcwd(), 'node_modules', '.bin',\n"
        "                      package.split('/')[-1])\n"
        "if os.path.exists(binary):\n"
        "    os.execv(binary, [binary])\n"
        "sys.exit(1)\n"))
    os.chmod(path, 0o755)
    return path


def make_clone_binary(clone, name, at_top=False):
    """The clone's own program: it leaves `clone-code-ran.txt` beside itself
    when it runs. Returns the path of that file."""
    directory = clone if at_top else os.path.join(clone, "node_modules", ".bin")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    write_text(path, "#!%s\n" % sys.executable + (
        "import os\n"
        "here = os.path.dirname(os.path.abspath(__file__))\n"
        "open(os.path.join(here, 'clone-code-ran.txt'), 'w').write('x')\n"))
    os.chmod(path, 0o755)
    return os.path.join(directory, "clone-code-ran.txt")


class TestFindProgram(unittest.TestCase):
    """The lookup of a program by its name, with a Windows PATHEXT and a
    current directory that can be simulated anywhere."""

    PATHEXT = ".COM;.EXE;.BAT;.CMD"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.clone = self.make_dir("clone")
        self.bin = self.make_dir("bin")
        self.other = self.make_dir("other")

    def make_dir(self, name):
        path = os.path.join(self.tmp, name)
        os.makedirs(path)
        return path

    @staticmethod
    def touch(directory, name, mode=0o755):
        path = os.path.join(directory, name)
        write_text(path, "")
        os.chmod(path, mode)
        return path

    def find(self, name, *entries, windows=True, avoid=(), pathext=None):
        return deep_mod._find_program(
            name, os.pathsep.join(entries), windows=windows,
            pathext=self.PATHEXT if pathext is None else pathext,
            avoid=avoid)

    def test_a_file_in_the_current_directory_is_not_taken_on_windows(self):
        # what shutil.which does on Windows: the current directory comes first
        self.touch(self.clone, "npx.CMD")
        mine = self.touch(self.bin, "npx.CMD")
        self.assertEqual(self.find("npx", self.clone, self.bin,
                                   avoid=[self.clone]), mine)
        self.assertIsNone(self.find("npx", self.clone, avoid=[self.clone]))

    def test_nothing_is_found_by_the_name_of_a_directory_that_is_avoided(self):
        self.touch(self.clone, "npx.CMD")
        for spelling in (self.clone + os.sep, os.path.join(self.clone, "."),
                         os.path.join(self.clone, "..", "clone")):
            with self.subTest(spelling):
                self.assertIsNone(self.find("npx", spelling,
                                            avoid=[self.clone]))

    def test_an_empty_or_relative_entry_means_the_current_directory(self):
        with isolated_machine(chdir=True) as (home, cwd):
            self.touch(cwd, "npx.CMD")
            os.makedirs(os.path.join(cwd, "rel"))
            self.touch(os.path.join(cwd, "rel"), "npx.CMD")
            for entry in ("", ".", "rel", os.path.join(".", "rel")):
                with self.subTest(entry):
                    self.assertIsNone(self.find("npx", entry))

    def test_the_order_of_pathext_decides(self):
        self.touch(self.bin, "tool.CMD")
        exe = self.touch(self.bin, "tool.EXE")
        self.assertEqual(self.find("tool", self.bin), exe)
        self.assertTrue(self.find("tool", self.bin,
                                  pathext=".CMD;.EXE").endswith("tool.CMD"))

    def test_a_name_that_already_has_a_listed_extension_is_not_given_another(
            self):
        exe = self.touch(self.bin, "tool.EXE")
        self.assertEqual(self.find("tool.EXE", self.bin), exe)
        self.assertIsNone(self.find("tool.EXE.EXE", self.bin))

    def test_a_file_without_an_extension_is_no_program_on_windows(self):
        self.touch(self.bin, "npx")      # the shell script npm puts beside npx.cmd
        self.assertIsNone(self.find("npx", self.bin))

    def test_a_directory_is_no_program(self):
        os.makedirs(os.path.join(self.bin, "npx.CMD"))
        self.assertIsNone(self.find("npx", self.bin))

    def test_the_first_directory_with_the_program_wins(self):
        first = self.touch(self.other, "tool.EXE")
        self.touch(self.bin, "tool.EXE")
        self.assertEqual(self.find("tool", self.other, self.bin), first)

    def test_quotes_around_an_entry_are_dropped_on_windows(self):
        mine = self.touch(self.bin, "tool.EXE")
        self.assertEqual(self.find("tool", '"%s"' % self.bin), mine)

    @unittest.skipUnless(POSIX, "needs the execute permission bit")
    def test_elsewhere_a_file_must_be_executable(self):
        self.touch(self.bin, "tool", mode=0o644)
        self.assertIsNone(self.find("tool", self.bin, windows=False))
        os.chmod(os.path.join(self.bin, "tool"), 0o755)
        self.assertEqual(self.find("tool", self.bin, windows=False),
                         os.path.join(self.bin, "tool"))

    def test_elsewhere_there_is_no_pathext(self):
        self.touch(self.bin, "tool.CMD")
        self.assertIsNone(self.find("tool", self.bin, windows=False))

    def test_the_current_directory_is_not_taken_elsewhere_either(self):
        self.touch(self.clone, "tool")
        self.assertIsNone(self.find("tool", "", self.clone, windows=False,
                                    avoid=[self.clone]))

    def test_no_path_means_nothing_is_found(self):
        self.assertIsNone(self.find("tool", ""))


class TestProgram(unittest.TestCase):
    """How a configured command becomes the file that is started."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.start = os.path.join(self.tmp, "start")
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.start)
        os.makedirs(self.bin)

    def test_a_bare_name_is_looked_up_on_the_path_of_the_server(self):
        path = os.path.join(self.bin, "tool.EXE")
        write_text(path, "")
        env = {"PATH": self.bin, "PATHEXT": ".EXE"}
        self.assertEqual(deep_mod._program("tool", env, self.start,
                                           windows=True), path)
        self.assertIsNone(deep_mod._program("tool", {"PATH": self.tmp},
                                            self.start, windows=True))

    def test_the_path_key_may_be_spelled_as_windows_does(self):
        path = os.path.join(self.bin, "tool.EXE")
        write_text(path, "")
        self.assertEqual(deep_mod._program(
            "tool", {"Path": self.bin}, self.start, windows=True), path)

    def test_a_bare_name_is_not_taken_from_where_the_server_starts(self):
        write_text(os.path.join(self.start, "tool.EXE"), "")
        env = {"PATH": os.pathsep.join(["", self.start]), "PATHEXT": ".EXE"}
        self.assertIsNone(deep_mod._program("tool", env, self.start,
                                            windows=True))

    def test_a_bare_name_is_not_taken_from_the_current_directory_either(self):
        # PATH names the clone mcp-audit was run in, by its full path
        with isolated_machine(chdir=True) as (home, cwd):
            write_text(os.path.join(cwd, "tool.EXE"), "")
            mine = os.path.join(self.bin, "tool.EXE")
            write_text(mine, "")
            env = {"PATH": os.pathsep.join([cwd, self.bin]),
                   "PATHEXT": ".EXE"}
            self.assertEqual(deep_mod._program("tool", env, self.start,
                                               windows=True), mine)

    def test_an_absolute_path_is_used_as_written(self):
        absolute = os.path.join(self.tmp, "elsewhere", "tool")
        self.assertEqual(deep_mod._program(absolute, {}, self.start,
                                           windows=False), absolute)

    def test_a_relative_path_is_relative_to_where_the_server_starts(self):
        got = deep_mod._program(os.path.join("sub", "tool"), {}, self.start,
                                windows=False)
        self.assertEqual(got, os.path.join(self.start, "sub", "tool"))

    def test_a_missing_path_variable_falls_back_to_the_default_path(self):
        with unittest.mock.patch.object(deep_mod.os, "defpath", self.bin):
            write_text(os.path.join(self.bin, "tool"), "")
            os.chmod(os.path.join(self.bin, "tool"), 0o755)
            got = deep_mod._program("tool", {}, self.start, windows=False)
        self.assertEqual(got, os.path.join(self.bin, "tool"))


class TestTheHelpAndTheReadme(unittest.TestCase):
    @staticmethod
    def words(text):
        return " ".join(text.split())

    def test_the_readme_says_where_servers_start(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "README.md"), encoding="utf-8") as f:
            readme = self.words(f.read())
        for needle in ("starts every server it finds in an empty directory",
                       "looked up on `PATH` only", "never in the current "
                       "directory", "--probe-project"):
            self.assertIn(needle, readme)

    def test_the_help_of_deep_says_so(self):
        text = self.words(cli_mod._build_parser().format_help())
        section = text.split("--deep Also", 1)[1].split(
            "--probe-critical With", 1)[0]
        self.assertIn("empty", section)


if __name__ == "__main__":
    unittest.main()
