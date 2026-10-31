r"""The hosts a URL can be read as pointing to (mcp_gradecard.urls).

The allowlist decision is made on these, so the table below pins, for each
spelling, every host a parser could connect to: Python's urlsplit (RFC 3986)
and the WHATWG parsers (Node's `new URL`, browsers) disagree on some of them,
for instance on `https://evil.example\@api.github.com/c`.
"""

import unittest

from mcp_gradecard import urls

TAB, LF = "\t", "\n"
KELVIN = chr(0x212A)
U_UMLAUT = chr(0xFC)

# (url, scheme, hosts either parser could connect to, parsers disagree?)
TABLE = [
    ("https://api.github.com/x", "https", ["api.github.com"], False),
    ("HTTPS://API.GitHub.com:443/x?a=b#c", "https", ["api.github.com"], False),
    ("https://user:pw@api.github.com/x", "https", ["api.github.com"], False),
    ("http://localhost.:3000", "http", ["localhost"], False),
    ("http://localhost../x", "http", ["localhost."], False),
    # the panel's URL: urlsplit says api.github.com, Node says evil.example
    ("https://evil.example\\@api.github.com/c", "https",
     ["api.github.com", "evil.example"], True),
    ("https://api.github.com\\@evil.example/c", "https",
     ["api.github.com", "evil.example"], True),
    ("https://api.github.com\\.evil.example/x", "https",
     ["api.github.com", "api.github.com\\.evil.example"], True),
    # a backslash after the path starts changes nothing
    ("https://api.github.com/a\\b", "https", ["api.github.com"], False),
    ("https://api.github.com?x=a\\b", "https", ["api.github.com"], False),
    # tabs and line feeds are deleted by every parser that matters
    ("http://localhost" + TAB + ".evil.example/", "http",
     ["localhost.evil.example"], False),
    ("ht" + LF + "tps://api.github.com", "https", ["api.github.com"], False),
    ("  https://api.github.com/x  ", "https", ["api.github.com"], False),
    # userinfo
    ("https://api.github.com@evil.example/", "https", ["evil.example"], False),
    ("https://a@b@evil.example/", "https", ["evil.example"], False),
    ("https://evil.example/@api.github.com", "https", ["evil.example"], False),
    ("https://evil.example?@api.github.com", "https", ["evil.example"], False),
    ("https://evil.example#@api.github.com", "https", ["evil.example"], False),
    # slashes: a special scheme skips any run of them, urlsplit sees no host
    ("http:///evil.example/x", "http", ["evil.example"], False),
    ("http:\\\\evil.example/x", "http", ["evil.example"], False),
    ("http:////evil.example", "http", ["evil.example"], False),
    ("https:\\/\\/evil.example\\/x", "https", ["evil.example"], False),
    # IPv6 and IPv4
    ("http://[::1]:5000/", "http", ["::1"], False),
    ("http://[0:0:0:0:0:0:0:1]/", "http", ["::1"], False),
    ("http://[::FFFF:127.0.0.1]/", "http", ["::ffff:127.0.0.1"], False),
    ("http://[::ffff:7f00:1]/", "http", ["::ffff:127.0.0.1"], False),
    ("http://127.0.0.1:8080", "http", ["127.0.0.1"], False),
    ("http://0x7f.1/", "http", ["0x7f.1"], False),
    ("http://2130706433/", "http", ["2130706433"], False),
    # ports are not part of a host
    ("http://localhost:${PORT}/mcp", "http", ["localhost"], False),
    ("http://evil.example:80:443/", "http", ["evil.example"], False),
    # percent escapes: a parser decodes them, so the text does not say
    ("http://%6c%6f%63%61%6c%68%6f%73%74/", "http",
     ["%6c%6f%63%61%6c%68%6f%73%74"], True),
    # a space or a quote inside the authority: userinfo, or part of the name
    ("https://localhost y@evil.example/sse", "https", ["evil.example"], False),
    ("https://localhost'y@evil.example/", "https", ["evil.example"], False),
    ("https://localhost'.evil.example/", "https", ["localhost'.evil.example"],
     False),
    ("https://api.github.com is the API", "https", ["api.github.com"], False),
    ("http:/evil.example/x", "http", ["evil.example"], False),
    # other schemes are read the RFC way only
    ("postgres://u:pw@db.example:5432/app", "postgres", ["db.example"], False),
    ("unix://localhost\\@evil.example", "unix",
     ["evil.example"], False),
]

NO_READING = ["", "abc", "localhost:3000", "localhost:3000/mcp", "${URL}",
              "/relative/path", "mailto:someone@example.com"]

UNPARSEABLE = [
    "http://[x", "http://[x]/", "http://[::1]evil/", "http://[::1%25eth0]/",
    "http://a[b/", "http://a]b/", "http://[::1/x", "http://", "http:///",
    "http://?x", "http://@/x", "http://./x", "file:///etc/x",
    "https://" + chr(0xE9) * 70 + ".example/x",
    "https://" + "a" * 3000 + ".example/x",
]

NOT_EXACT = {
    "https://localhost'.evil.example/": "localhost'.evil.example",
    "https://localhost>.evil.example/": "localhost>.evil.example",
    'https://"evil.example/': '"evil.example',
    "http://%6c%6f%63%61%6c%68%6f%73%74/": "%6c%6f%63%61%6c%68%6f%73%74",
    "https://api.slac" + KELVIN + ".com/": "api.slack.com",
    "https://m" + U_UMLAUT + "nchen.example/": "xn--mnchen-3ya.example",
}


class TestReadings(unittest.TestCase):
    def test_table(self):
        for url, scheme, hosts, ambiguous in TABLE:
            u = urls.parse(url)
            self.assertEqual(u.scheme, scheme, repr(url))
            self.assertEqual(sorted(r.host for r in u.readings),
                             sorted(hosts), repr(url))
            self.assertEqual(u.ambiguous, ambiguous, repr(url))

    def test_text_that_is_not_a_url_has_no_readings(self):
        for text in NO_READING:
            self.assertEqual(urls.parse(text).readings, (), repr(text))

    def test_broken_urls_raise(self):
        for url in UNPARSEABLE:
            with self.assertRaises(urls.UnparseableUrl, msg=repr(url)):
                urls.parse(url)

    def test_hosts_the_text_does_not_pin_down_are_not_exact(self):
        for url, host in NOT_EXACT.items():
            (r,) = urls.parse(url).readings
            self.assertFalse(r.exact, repr(url))
            self.assertEqual(r.host, host, repr(url))
        for url, _, _, _ in TABLE:
            if "%" in url or any(c in url for c in "'\"<>"):
                continue
            for r in urls.parse(url).readings:
                self.assertTrue(r.exact, repr(url))

    def test_what_is_printed_has_no_userinfo_path_query_or_bad_port(self):
        u = urls.parse("https://user:S3CR3T@evil.example:8443/p/q?k=S3CR3T#f")
        (r,) = u.readings
        self.assertEqual((r.shown, r.tail), ("evil.example:8443", "/..."))
        u = urls.parse("https://evil.example:S3CR3T/")
        self.assertEqual(u.readings[0].shown, "evil.example")
        self.assertEqual(urls.parse("http://[::1]:5000").readings[0].shown,
                         "[::1]:5000")
        self.assertEqual(urls.parse("http://h.example").readings[0].tail, "")
        self.assertEqual(urls.parse("http://h.example/").readings[0].tail, "/")

    def test_a_very_long_host_is_cut_when_printed(self):
        (r,) = urls.parse("https://" + "a" * 500 + ".example/p").readings
        self.assertLess(len(r.shown), 200)

    def test_looks_like_host(self):
        for url in ("http://evil.example/", "http://[::1]/",
                    "http://%6c%6f/"):
            self.assertTrue(urls.looks_like_host(urls.parse(url).readings[0]),
                            url)
        for url in ("http://intranet/", "http://ghp_TOKENTOKEN/"):
            self.assertFalse(urls.looks_like_host(urls.parse(url).readings[0]),
                             url)


class TestLinearTime(unittest.TestCase):
    def test_a_huge_url_is_not_quadratic(self):
        import time
        for url in ("https://" + "a@" * 200_000 + "evil.example/x",
                    "https://" + "\\" * 400_000 + "x",
                    "https:" + "/" * 400_000 + "x",
                    "https://" + "[" * 400_000,
                    "https://" + "a." * 200_000):
            start = time.monotonic()
            try:
                urls.parse(url)
            except urls.UnparseableUrl:
                pass
            self.assertLess(time.monotonic() - start, 2.0, url[:20])


if __name__ == "__main__":
    unittest.main()
