"""Literal credentials in `headers`, and `docker run` options that remove the
container's isolation. Both gaps were found by running ordinary and hostile
configs through the CLI (SOP review 2026-10-31): `docker run --privileged -v
/:/host` and a hard-coded `Authorization: Bearer sk-...` both graded 100/100.
"""

import json
import unittest

from mcp_gradecard import detectors

SECRET = "sk-abcdefghijklmnopqrstuvwxyz0123456789"


def checks(cfg):
    return {f["check"]: f for f in detectors.audit_server("s", cfg, [])}


def docker(*args):
    return {"command": "docker", "args": ["run", "-i", "--rm", *args,
                                          "img/server:1.2.3"]}


class TestSecretHeader(unittest.TestCase):
    def flagged(self, headers):
        return "secret-header" in checks({"url": "https://x.corp.test/mcp",
                                          "headers": headers})

    def test_a_literal_bearer_token_is_flagged(self):
        self.assertTrue(self.flagged({"Authorization": "Bearer " + SECRET}))

    def test_other_credential_headers_are_flagged(self):
        self.assertTrue(self.flagged({"X-API-Key": SECRET}))
        self.assertTrue(self.flagged({"x-auth-token": SECRET}))
        self.assertTrue(self.flagged({"Cookie": "session=" + SECRET}))

    def test_references_are_the_safe_form_and_not_flagged(self):
        for value in ("Bearer ${GITHUB_TOKEN}", "$TOKEN", "%TOKEN%",
                      "Bearer ${input:github_pat}", "Bearer {env:TOKEN}",
                      "Bearer $(cat /run/secret)"):
            with self.subTest(value):
                self.assertFalse(self.flagged({"Authorization": value}))

    def test_ordinary_headers_are_not_flagged(self):
        self.assertFalse(self.flagged({"Content-Type": "application/json",
                                       "X-Request-Id": "abc123",
                                       "Accept": "text/event-stream"}))

    def test_an_empty_or_scheme_only_value_is_not_flagged(self):
        self.assertFalse(self.flagged({"Authorization": ""}))
        self.assertFalse(self.flagged({"Authorization": "Bearer "}))

    def test_odd_shapes_do_not_crash(self):
        for headers in (None, [], "x", {"Authorization": None},
                        {"Authorization": 5}, {5: "x"}):
            with self.subTest(repr(headers)):
                self.assertFalse(self.flagged(headers))

    def test_the_value_is_never_printed(self):
        out = json.dumps(detectors.audit_server(
            "s", {"url": "https://x.corp.test/mcp",
                  "headers": {"Authorization": "Bearer " + SECRET}}, []))
        self.assertNotIn(SECRET, out)
        self.assertIn("Authorization", out)


class TestContainerEscape(unittest.TestCase):
    def escape(self, *args):
        return checks(docker(*args)).get("container-escape")

    def isolation(self, *args):
        return checks(docker(*args)).get("container-isolation")

    def test_privileged_is_high(self):
        f = self.escape("--privileged")
        self.assertEqual(f["severity"], "high")
        self.assertIn("--privileged", f["message"])

    def test_privileged_false_is_not_flagged(self):
        self.assertIsNone(self.escape("--privileged=false"))

    def test_whole_host_mount_is_high_in_every_spelling(self):
        for args in (("-v", "/:/host"), ("-v/:/host",),
                     ("--volume=/:/host:ro",), ("-v", "C:\\:/host"),
                     ("--mount", "type=bind,source=/,target=/host"),
                     ("--mount", "type=bind,src=/,dst=/h")):
            with self.subTest(args):
                self.assertIsNotNone(self.escape(*args))

    def test_the_engine_socket_is_high(self):
        self.assertIsNotNone(self.escape(
            "-v", "/var/run/docker.sock:/var/run/docker.sock"))

    def test_dangerous_capabilities_are_high(self):
        for cap in ("ALL", "SYS_ADMIN", "CAP_SYS_PTRACE"):
            with self.subTest(cap):
                self.assertIsNotNone(self.escape("--cap-add", cap))
        self.assertIsNotNone(self.escape("--cap-add=SYS_ADMIN"))

    def test_ordinary_options_are_not_flagged(self):
        for args in (("-v", "/home/me/project:/work"),
                     ("-v", "C:\\Users\\me\\proj:/work"),
                     ("-v", "data:/data"),
                     ("-e", "GITHUB_PERSONAL_ACCESS_TOKEN"),
                     ("-p", "8080:80"), ("--cap-add", "NET_BIND_SERVICE"),
                     ("--cap-drop", "ALL"), ("--network", "bridge"),
                     ("--mount", "type=volume,source=vol,target=/d")):
            with self.subTest(args):
                found = checks(docker(*args))
                self.assertNotIn("container-escape", found)
                self.assertNotIn("container-isolation", found)

    def test_host_namespaces_and_unconfined_are_medium(self):
        for args in (("--network", "host"), ("--net=host",), ("--pid=host",),
                     ("--security-opt", "seccomp=unconfined")):
            with self.subTest(args):
                f = self.isolation(*args)
                self.assertEqual(f["severity"], "medium")
                self.assertIsNone(self.escape(*args))

    def test_the_servers_own_arguments_after_the_image_are_not_read(self):
        cfg = {"command": "docker", "args": [
            "run", "-i", "--rm", "img/server:1", "--privileged",
            "--network", "host"]}
        found = checks(cfg)
        self.assertNotIn("container-escape", found)
        self.assertNotIn("container-isolation", found)

    def test_podman_and_windows_spellings_are_read(self):
        self.assertIsNotNone(checks(
            {"command": "podman", "args": ["run", "--privileged", "i"]}
        ).get("container-escape"))
        self.assertIsNotNone(checks(
            {"command": "C:\\Program Files\\Docker\\docker.exe",
             "args": ["run", "--privileged", "i"]}).get("container-escape"))
        self.assertIsNotNone(checks(
            {"command": "cmd", "args": ["/c", "docker", "run", "--privileged",
                                        "i"]}).get("container-escape"))

    def test_other_docker_commands_are_not_read(self):
        self.assertNotIn("container-escape", checks(
            {"command": "docker", "args": ["exec", "-i", "--privileged",
                                           "c", "sh"]}))

    def test_odd_shapes_do_not_crash(self):
        for args in ([], ["run"], ["run", "-v"], ["run", "--"],
                     ["run", "-", "x"], ["run", "-v", ""]):
            with self.subTest(args):
                checks({"command": "docker", "args": args})


if __name__ == "__main__":
    unittest.main()
