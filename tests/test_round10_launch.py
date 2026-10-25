"""Round-10 regression tests for the launch checks: amounts that are not
credentials, whole path segments, the container's own command line, and the
temporary-folder shapes the first version missed."""

import os
import sys
import unittest

from mcp_audit import detectors

from _support import FIX


def checks(cfg):
    return sorted((f["check"], f["severity"])
                  for f in detectors.detect_risky_launch("s", cfg))


def ids(cfg):
    return [c for c, _ in checks(cfg)]


def run(*args):
    return {"command": "docker", "args": list(args)}


class TestAmountsAreNotCredentials(unittest.TestCase):
    def test_options_that_hold_a_number_of_tokens(self):
        for args in (["--max-tokens", "100000"], ["--token-limit=100000"],
                     ["--tokens", "250000"], ["--token-ttl", "3600000"],
                     ["--min-tokens", "1000000"], ["--key-count", "1234567"],
                     ["--token-timeout", "30000000"]):
            cfg = {"command": "npx", "args": ["srv@1.0.0"] + args}
            self.assertNotIn("secret-in-args", ids(cfg), args)

    def test_env_style_amounts(self):
        cfg = {"command": "npx", "args": ["srv@1.0.0", "-e",
                                          "MAX_TOKENS=100000"]}
        self.assertNotIn("secret-in-args", ids(cfg))
        cfg = {"command": "npx", "args": ["srv@1.0.0", "TOKEN_LIMIT=100000"]}
        self.assertNotIn("secret-in-args", ids(cfg))

    def test_a_real_token_is_still_found(self):
        for args in (["--token", "abc123def456"], ["--api-key=abc123def456"],
                     ["--tokens", "abc123def456"],
                     ["--password", "12345678"], ["--token", "123456789012"]):
            cfg = {"command": "npx", "args": ["srv@1.0.0"] + args}
            self.assertIn("secret-in-args", ids(cfg), args)


class TestMorePasswordShapes(unittest.TestCase):
    def test_a_password_in_a_url_argument(self):
        cfg = {"command": "node", "args": ["s.js", "postgres://u:pass1234@h/db"]}
        self.assertEqual(checks(cfg), [("secret-in-args", "medium")])

    def test_a_url_with_a_reference_or_no_password_is_fine(self):
        for url in ("postgres://u:${DB_PASSWORD}@h/db", "postgres://u@h/db",
                    "postgres://u:$PW@h/db", "https://example.com/a:b@c",
                    "postgres://u:abc@h/db"):
            cfg = {"command": "node", "args": ["s.js", url]}
            self.assertNotIn("secret-in-args", ids(cfg), url)

    def test_the_password_is_never_printed(self):
        cfg = {"command": "node", "args": ["s.js", "mongodb://u:Zq9xW7vPass@h"]}
        for f in detectors.detect_risky_launch("s", cfg):
            self.assertNotIn("Zq9xW7vPass", f["message"])

    def test_short_password_options_of_known_programs(self):
        for cmd, args in (("sshpass", ["-p", "hunter22x", "ssh", "h"]),
                          ("mysql", ["-phunter22x"]),
                          ("redis-cli", ["-a", "hunter22x"]),
                          ("curl", ["-u", "me:hunter22x", "http://h/"]),
                          ("curl", ["-ume:hunter22x", "http://h/"])):
            self.assertIn("secret-in-args", ids({"command": cmd, "args": args}),
                          (cmd, args))

    def test_short_options_that_are_not_passwords(self):
        for cmd, args in (("psql", ["-p", "5432"]), ("mysql", ["-p"]),
                          ("mysql", ["-p", "mydatabase"]),
                          ("ssh", ["-p", "2222", "host"]),
                          ("docker", ["compose", "-p", "myproject"]),
                          ("curl", ["-u", "me:$PW", "http://h/"]),
                          ("curl", ["-u", "me", "http://h/"])):
            self.assertNotIn("secret-in-args", ids({"command": cmd,
                                                    "args": args}), (cmd, args))

    def test_the_short_password_inside_a_script(self):
        cfg = {"command": "sh", "args": ["-c", "sshpass -p hunter22x ssh h"]}
        self.assertIn("secret-in-args", ids(cfg))


class TestContainerOptionsAreWholeSegmentsBeforeTheImage(unittest.TestCase):
    def test_a_folder_that_only_contains_the_name_is_not_a_secret_dir(self):
        for src in ("/srv/.dockerfiles", "/data/my.configs", "/opt/.sshd",
                    "/home/me/.configs/x", "/x/.awsome", "/x/.kubernetes"):
            cfg = run("run", "-v", src + ":/x", "img")
            self.assertNotIn("container-escape", ids(cfg), src)

    def test_the_real_ones_are_still_high(self):
        for src in ("/home/me/.config", "/home/me/.config/gh", "~/.ssh",
                    "/root/.aws/", "C:\\Users\\me\\.ssh", "/home/me/.docker",
                    "/home/me/.kube/cache", "/home/me/.gnupg"):
            cfg = run("run", "-v", src + ":/x", "img")
            self.assertIn(("container-escape", "high"), checks(cfg), src)

    def test_options_after_the_image_belong_to_the_program(self):
        for tail in (["--privileged"], ["--cap-add", "ALL"],
                     ["--network=host"], ["-v", "/:/host"],
                     ["--pid=host"], ["--device", "/dev/sda"]):
            cfg = run("run", "--rm", "-i", "img", *tail)
            self.assertNotIn("container-escape", ids(cfg), tail)

    def test_options_before_the_image_still_count(self):
        for head in (["--privileged"], ["--cap-add", "ALL"], ["-v", "/:/host"],
                     ["--pid=host"], ["--security-opt", "seccomp=unconfined"],
                     ["-itv", "/etc:/e"], ["-v/etc:/e"]):
            cfg = run("run", "--rm", *head, "img", "serve")
            self.assertIn("container-escape", ids(cfg), head)

    def test_a_value_taking_option_does_not_hide_the_options_after_it(self):
        cfg = run("run", "--name", "box", "-e", "A=1", "-w", "/w",
                  "--privileged", "img")
        self.assertIn(("container-escape", "high"), checks(cfg))

    def test_an_unknown_option_cannot_hide_a_risky_one(self):
        # `--frobnicate yes` may or may not take a value: either way
        # --privileged is before the image
        cfg = run("run", "--frobnicate", "yes", "--privileged", "img")
        self.assertIn(("container-escape", "high"), checks(cfg))
        cfg = run("run", "--frobnicate", "--privileged", "img")
        self.assertIn(("container-escape", "high"), checks(cfg))

    def test_double_dash_ends_the_options(self):
        cfg = run("run", "--", "img", "--privileged")
        self.assertNotIn("container-escape", ids(cfg))

    def test_global_options_before_run_and_other_runtimes(self):
        cfg = run("--context", "x", "run", "--privileged", "img")
        self.assertIn("container-escape", ids(cfg))
        cfg = {"command": "podman", "args": ["run", "--privileged", "img"]}
        self.assertIn("container-escape", ids(cfg))

    def test_inside_a_shell_script(self):
        cfg = {"command": "sh", "args": ["-c", "docker run img --privileged"]}
        self.assertNotIn("container-escape", ids(cfg))
        cfg = {"command": "sh", "args": ["-c", "docker run --privileged img"]}
        self.assertIn("container-escape", ids(cfg))


class TestTemporaryFolders(unittest.TestCase):
    def test_a_data_file_named_bin_is_not_code(self):
        cfg = {"command": "node", "args": ["server.js", "/tmp/data.bin"]}
        self.assertNotIn("temp-binary", ids(cfg))

    def test_a_program_in_a_temp_folder_is_still_found_whatever_its_name(self):
        cfg = {"command": "/tmp/server"}
        self.assertIn("temp-binary", ids(cfg))

    def test_macos_per_user_temp_folders(self):
        for cmd in ("/var/folders/ab/cdef/T/evil.sh",
                    "/private/var/folders/ab/cdef/T/evil",
                    "/private/tmp/evil"):
            self.assertIn("temp-binary", ids({"command": cmd}), cmd)

    def test_a_shell_c_that_runs_a_program_from_tmp(self):
        for script in ("/tmp/evil", "/tmp/evil --flag", "cd / && /tmp/evil",
                       "nohup /var/tmp/evil &"):
            cfg = {"command": "sh", "args": ["-c", script]}
            self.assertIn("temp-binary", ids(cfg), script)

    def test_a_shell_c_that_only_mentions_tmp_is_fine(self):
        cfg = {"command": "sh", "args": ["-c", "echo hi > /tmp/log"]}
        self.assertNotIn("temp-binary", ids(cfg))

    def test_a_package_file_or_file_url_in_a_temp_folder(self):
        for args in (["--from", "/tmp/x.whl", "srv"], ["--from=/tmp/x.whl", "srv"],
                     ["/tmp/x.tar.gz"], ["file:///tmp/x.js"],
                     ["file:///var/tmp/x.py"], ["--import", "file:///tmp/h.mjs"]):
            cfg = {"command": "uvx" if "srv" in args else "npx", "args": args}
            self.assertIn("temp-binary", ids(cfg), args)

    def test_windows_paths_with_forward_slashes(self):
        for cmd in ("C:/Windows/Temp/evil.exe", "c:/users/me/appdata/local/temp/x.exe",
                    "file:///C:/Windows/Temp/x.js"):
            cfg = {"command": "node", "args": [cmd]}
            self.assertIn("temp-binary", ids(cfg), cmd)

    def test_a_file_url_outside_temp_is_fine(self):
        cfg = {"command": "npx", "args": ["file:///home/me/x.js"]}
        self.assertNotIn("temp-binary", ids(cfg))


class TestTheTestsDoNotDependOnWhereThePythonIs(unittest.TestCase):
    def test_the_interpreter_is_never_reported_as_a_temp_binary(self):
        cfg = {"command": sys.executable, "args": [os.path.join(FIX, "x.py")]}
        self.assertNotIn("temp-binary", ids(cfg))

    def test_a_venv_in_a_temp_folder_is_exempt_in_the_test_hook_only(self):
        self.assertTrue(detectors._TEMP_RE.match("/tmp/venv/bin/python"))
        if detectors._TEMP_RE.match(sys.executable):
            self.assertTrue(sys.executable.startswith(
                detectors._TEMP_EXEMPT))
        else:
            self.assertEqual(ids({"command": "/tmp/venv/bin/python"}),
                             ["temp-binary"])


if __name__ == "__main__":
    unittest.main()
