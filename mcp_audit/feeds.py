"""Read a feed (--ioc-feed, --advisory-feed) from a local file or an https
URL. There is no hosted service behind this: the URL is one you chose, and a
feed you fetch is exactly as fresh as whoever publishes it - nothing here
checks its age. A feed that cannot be read is an error, never "no entries"."""

from __future__ import annotations

import urllib.parse
import urllib.request

TIMEOUT = 15


class FeedSourceError(RuntimeError):
    """The source cannot be read (text is safe to print)."""


def is_url(source: str) -> bool:
    return source.lower().startswith(("http://", "https://"))


def read_source(source: str, limit: int, label: str) -> bytes:
    """The bytes of `source` (at most `limit`), a path or an https URL."""
    if is_url(source):
        parts = urllib.parse.urlsplit(source)
        if parts.scheme.lower() != "https" or not parts.hostname:
            raise FeedSourceError(
                f"{label} {shown(source)}: only https URLs are fetched (a "
                "feed over plain http can be changed on the way)")
        try:
            with urllib.request.urlopen(source, timeout=TIMEOUT) as resp:
                raw = resp.read(limit + 1)
        except (OSError, ValueError) as e:
            raise FeedSourceError(
                f"{label} {shown(source)} cannot be fetched "
                f"({type(e).__name__})") from None
    else:
        try:
            with open(source, "rb") as f:
                raw = f.read(limit + 1)
        except OSError as e:
            raise FeedSourceError(
                f"{label} {source} cannot be read "
                f"({type(e).__name__})") from None
    if len(raw) > limit:
        raise FeedSourceError(f"{label} {shown(source)} is too large")
    return raw


def shown(source: str) -> str:
    """A URL without credentials or a query (either may be a token)."""
    if not is_url(source):
        return source
    p = urllib.parse.urlsplit(source)
    host = p.hostname or ""
    return f"{p.scheme}://{host}{p.path}"
