"""Which package specs float (finding M7).

Only a missing `@` counted as unpinned, so `pkg@latest`, `pkg@next` and
`@^1.2.0` passed as pinned while `uvx pkg==1.2.3` - an exact pin - was
reported as unpinned; `pnpm dlx pkg` read "dlx" as the package, and a package
started through `cmd /c npx` or `bash -lc` was never looked at.
"""

import io
import json
import unittest
import unittest.mock

from mcp_gradecard import detectors

NO_FEED = []


def floating(cfg):
    return detectors.detect_floating_version("x", cfg)


def run(command, *args):
    return {"command": command, "args": list(args)}


class TestNpmSpecs(unittest.TestCase):
    FLOATS = (
        "pkg", "pkg@", "pkg@latest", "pkg@next", "pkg@beta", "pkg@canary",
        "pkg@*", "pkg@x", "pkg@1", "pkg@1.2", "pkg@1.x", "pkg@1.2.x",
        "pkg@^1.2.0", "pkg@~1.2.0", "pkg@>=1.0.0", "pkg@<2", "pkg@>1 <2",
        "pkg@1.0.0 - 2.0.0", "pkg@1.0.0||2.0.0",
        "@scope/pkg", "@scope/pkg@latest", "@scope/pkg@^1.2.0",
        "@scope/pkg@~1", "@scope/pkg@",
    )
    PINNED = (
        "pkg@1.2.3", "pkg@0.0.1", "pkg@10.20.30", "pkg@1.2.3-beta.1",
        "pkg@1.2.3-rc.1+build.5", "pkg@v1.2.3", "pkg@=1.2.3",
        "@scope/pkg@1.2.3", "@scope/pkg@2.0.0-alpha",
        "pkg@sha256:" + "ab" * 32,
    )

    def test_tags_ranges_and_a_missing_version_float(self):
        for spec in self.FLOATS:
            f = floating(run("npx", "-y", spec))
            self.assertEqual([x["severity"] for x in f], ["medium"], spec)
            self.assertEqual([x["check"] for x in f], ["floating-version"],
                             spec)

    def test_an_exact_version_or_digest_is_pinned(self):
        for spec in self.PINNED:
            self.assertEqual(floating(run("npx", "-y", spec)), [], spec)

    def test_the_message_names_the_package_and_what_floats(self):
        (f,) = floating(run("npx", "-y", "@scope/pkg@latest"))
        self.assertIn("@scope/pkg", f["message"])
        self.assertIn("latest", f["message"])
        (f,) = floating(run("npx", "-y", "pkg"))
        self.assertIn("'pkg'", f["message"])
        self.assertIn("unpinned package", f["message"])
        (f,) = floating(run("npx", "-y", "pkg@"))
        self.assertIn("unpinned package", f["message"])
        (f,) = floating(run("npx", "-y", "pkg@^1.2.0"))
        self.assertIn("^1.2.0", f["message"])

    def test_runners_and_subcommands(self):
        for cfg in (run("bunx", "pkg@latest"), run("pnpm", "dlx", "pkg"),
                    run("pnpm", "dlx", "pkg@^1"), run("pnpx", "pkg"),
                    run("npm", "exec", "-y", "pkg"),
                    run("npm", "x", "pkg@next"), run("yarn", "dlx", "pkg"),
                    run("bun", "x", "pkg")):
            self.assertEqual(len(floating(cfg)), 1, cfg)
        for cfg in (run("bunx", "pkg@1.2.3"), run("pnpm", "dlx", "pkg@1.2.3"),
                    run("pnpx", "pkg@1.2.3"),
                    run("npm", "exec", "-y", "pkg@1.2.3"),
                    run("yarn", "dlx", "pkg@1.2.3")):
            self.assertEqual(floating(cfg), [], cfg)

    def test_subcommands_that_run_no_package_are_not_packages(self):
        for cfg in (run("pnpm", "start"), run("pnpm", "exec", "tsc"),
                    run("pnpm", "run", "dev"), run("npm", "run", "x"),
                    run("npm", "start"), run("yarn", "start"),
                    run("pnpm"), run("npx"), run("npx", "-y"),
                    # npx -c runs a shell command string: no package
                    run("npx", "-c", "echo hi"), run("npx", "-c", "mycmd"),
                    run("npx", "-c", "echo hi", "extra"),
                    run("npm", "exec", "-c", "mycmd")):
            self.assertEqual(floating(cfg), [], cfg)
        # ... but pnpm's -c is a flag, not a command string
        self.assertEqual(len(floating(run("pnpm", "dlx", "-c", "pkg"))), 1)

    def test_pnpm_dlx_is_not_a_package_called_dlx(self):
        (f,) = floating(run("pnpm", "dlx", "-y", "real-pkg"))
        self.assertIn("real-pkg", f["message"])
        self.assertNotIn("dlx", f["message"])

    def test_options_with_values_are_not_the_package(self):
        (f,) = floating(run("npx", "--registry", "https://r.example/", "-y",
                            "pkg"))
        self.assertIn("'pkg'", f["message"])
        (f,) = floating(run("npx", "--yes", "--registry=https://r.example/",
                            "pkg"))
        self.assertIn("'pkg'", f["message"])
        self.assertEqual(floating(run("npx", "--registry", "https://r.example/",
                                      "-y", "pkg@1.2.3")), [])

    def test_the_package_option_names_the_package(self):
        (f,) = floating(run("npx", "-p", "pkg@latest", "mycmd"))
        self.assertIn("'pkg'", f["message"])
        self.assertIn("latest", f["message"])
        self.assertEqual(floating(run("npx", "--package=pkg@1.2.3", "mycmd")),
                         [])
        self.assertEqual(len(floating(run("npx", "-p", "a@1.0.0", "-p", "b",
                                          "cmd"))), 1)

    def test_what_follows_the_package_belongs_to_the_server(self):
        self.assertEqual(floating(run("npx", "-y", "pkg@1.2.3", "--yes",
                                      "other", "-p", "x")), [])
        self.assertEqual(floating(run("npx", "-y", "pkg@1.2.3", "--",
                                      "other")), [])

    def test_git_urls_paths_and_tarballs_are_not_judged(self):
        for spec in ("./local-server", "../x", "/abs/server.js",
                     "C:\\srv\\server.js", "file:../x", "github:user/repo",
                     "user/repo", "git+ssh://git@host/u/r.git"):
            self.assertEqual(floating(run("npx", "-y", spec)), [], spec)


class TestPythonSpecs(unittest.TestCase):
    FLOATS = ("pkg", "pkg@latest", "pkg>=1.0", "pkg~=1.2", "pkg==1.*",
              "pkg<2", "pkg>=1,<2", "pkg!=1.0", "pkg[extra]", "pkg[extra]>=1")
    PINNED = ("pkg==1.2.3", "pkg@1.2.3", "pkg[extra]==1.2.3", "pkg===1.2.3",
              "pkg==2024.1.1", "pkg==1.2.3rc1", "pkg==1.2.3.post1",
              "pkg>=1,==1.2.3", "pkg == 1.2.3",
              "pkg==1.2.3; python_version >= '3.9'")

    def test_ranges_tags_and_a_missing_version_float(self):
        for spec in self.FLOATS:
            f = floating(run("uvx", spec))
            self.assertEqual([x["check"] for x in f], ["floating-version"],
                             spec)

    def test_exact_pins_are_pinned_whatever_the_syntax(self):
        for spec in self.PINNED:
            self.assertEqual(floating(run("uvx", spec)), [], spec)

    def test_from_and_with_name_the_packages(self):
        self.assertEqual(floating(run("uvx", "--from", "pkg==1.2.3", "cmd")),
                         [])
        self.assertEqual(len(floating(run("uvx", "--from", "pkg", "cmd"))), 1)
        self.assertEqual(len(floating(run("uvx", "--from", "pkg>=1", "cmd"))),
                         1)
        (f,) = floating(run("uvx", "--with", "extra", "pkg==1.2.3"))
        self.assertIn("extra", f["message"])
        self.assertEqual(floating(run("uvx", "--python", "3.12", "pkg==1.2.3")),
                         [])

    def test_other_launchers(self):
        self.assertEqual(len(floating(run("uv", "tool", "run", "pkg"))), 1)
        self.assertEqual(floating(run("uv", "tool", "run", "pkg==1.2.3")), [])
        self.assertEqual(len(floating(run("pipx", "run", "pkg"))), 1)
        self.assertEqual(floating(run("pipx", "run", "pkg==1.2.3")), [])
        for cfg in (run("uv", "sync"), run("uv", "run", "x.py"),
                    run("pipx", "list")):
            self.assertEqual(floating(cfg), [], cfg)

    def test_urls_and_paths_are_not_judged(self):
        for spec in ("./pkg", "git+https://example.com/u/r", "pkg @ file:///x"):
            self.assertEqual(floating(run("uvx", spec)), [], spec)


class TestThroughWrappers(unittest.TestCase):
    def test_a_floating_package_behind_a_wrapper_is_still_floating(self):
        for cfg in (
                run("cmd", "/c", "npx", "-y", "pkg@latest"),
                run("cmd.exe", "/d", "/s", "/c", "npx -y pkg"),
                run("bash", "-lc", "npx -y pkg@^1"),
                run("sh", "-c", "cd /srv && exec npx -y pkg"),
                run("env", "FOO=1", "npx", "-y", "pkg"),
                run("sudo", "-u", "svc", "npx", "-y", "pkg"),
                run("pwsh", "-Command", "uvx pkg"),
                run("/usr/bin/env", "bash", "-c", "npx -y pkg")):
            self.assertEqual(len(floating(cfg)), 1, cfg)

    def test_a_pinned_package_behind_a_wrapper_is_fine(self):
        for cfg in (
                run("cmd", "/c", "npx", "-y", "pkg@1.2.3"),
                run("bash", "-lc", "npx -y pkg@1.2.3"),
                run("env", "FOO=1", "npx", "-y", "pkg@1.2.3")):
            self.assertEqual(floating(cfg), [], cfg)

    def test_two_packages_in_one_script_are_both_judged(self):
        cfg = run("bash", "-c", "npx -y a@1.0.0 && npx -y b")
        (f,) = floating(cfg)
        self.assertIn("'b'", f["message"])
        # the same package twice is one finding
        self.assertEqual(len(floating(run("bash", "-c",
                                          "npx -y b; npx -y b"))), 1)

    def test_a_script_too_complex_to_read_does_not_crash_the_check(self):
        script = "echo " + "$(" * 20 + "x" + ")" * 20
        self.assertEqual(floating(run("bash", "-c", script)), [])


class TestAdvisoriesAndOsvSeeExactVersions(unittest.TestCase):
    ADV = [{"package": "some-pkg", "cve": "CVE-1", "title": "t",
            "severity": "high", "fixed_in": "2.0.0"}]

    def known(self, cfg):
        return detectors.detect_known_bad("x", cfg, self.ADV)

    def test_uvx_exact_pins_are_matched_by_package_and_version(self):
        self.assertEqual(len(self.known(run("uvx", "some-pkg==1.0.0"))), 1)
        self.assertEqual(self.known(run("uvx", "some-pkg==2.1.0")), [])
        self.assertEqual(self.known(run("uvx", "some-pkg@2.1.0")), [])

    def test_a_range_cannot_prove_the_fix_so_the_advisory_stands(self):
        self.assertEqual(len(self.known(run("npx", "-y", "some-pkg@^2.0.0"))), 1)
        self.assertEqual(len(self.known(run("npx", "-y", "some-pkg@latest"))), 1)

    def test_a_wrapped_package_is_matched(self):
        self.assertEqual(len(self.known(
            run("bash", "-lc", "npx -y some-pkg@1.0.0"))), 1)

    def osv_requests(self, cfg):
        sent = []

        class Ctx(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with unittest.mock.patch.object(
                detectors.urllib.request, "urlopen",
                side_effect=lambda req, timeout=None: (
                    sent.append(json.loads(req.data.decode()))
                    or Ctx(b'{"vulns": []}'))):
            detectors.detect_osv("x", cfg)
        return sent

    def test_osv_is_asked_only_about_exact_versions(self):
        self.assertEqual(self.osv_requests(run("npx", "-y", "pkg@1.2.3")),
                         [{"package": {"name": "pkg", "ecosystem": "npm"},
                           "version": "1.2.3"}])
        self.assertEqual(self.osv_requests(run("uvx", "pkg==1.2.3")),
                         [{"package": {"name": "pkg", "ecosystem": "PyPI"},
                           "version": "1.2.3"}])
        # a "v" or "=" in front is not part of the release
        self.assertEqual(self.osv_requests(run("npx", "-y", "pkg@v1.2.3")),
                         [{"package": {"name": "pkg", "ecosystem": "npm"},
                           "version": "1.2.3"}])
        for cfg in (run("npx", "-y", "pkg@^1.2.0"), run("npx", "-y", "pkg"),
                    run("npx", "-y", "pkg@latest"), run("uvx", "pkg>=1"),
                    run("uvx", "pkg"),
                    run("npx", "-y", "pkg@sha256:" + "ab" * 32)):
            self.assertEqual(self.osv_requests(cfg), [], cfg)


if __name__ == "__main__":
    unittest.main()
