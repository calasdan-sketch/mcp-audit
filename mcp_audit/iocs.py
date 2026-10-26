"""Indicators of compromise: servers, hosts, files and repositories that a
public report ties to a supply-chain campaign (iocs.json, shipped in the
wheel). A match is a finding; the feed is data, so adding an indicator is
editing a file, and `--ioc-feed FILE_OR_URL` adds your own.

The feed holds only what a report lists. An empty or short feed is normal; a
missing one is an error (a scanner that lost its feed would call a known
campaign clean), as with the advisory feed."""

from __future__ import annotations

import json
import re
from importlib import resources

from . import feeds

FEED_NAME = "iocs.json"
TYPES = ("host", "path", "server-name", "github-repo", "github-account",
         "package")
STATUSES = ("active", "historical")
MAX_FEED_BYTES = 8 * 1024 * 1024
_SEVERITY = {
    ("host", "active"): "critical", ("host", "historical"): "high",
    ("path", "active"): "critical", ("path", "historical"): "high",
    ("github-repo", "active"): "critical",
    ("github-repo", "historical"): "high",
    ("github-account", "active"): "high",
    ("github-account", "historical"): "medium",
    ("server-name", "active"): "medium",
    ("server-name", "historical"): "low",
    ("package", "active"): "critical", ("package", "historical"): "high",
}


class IocFeedError(RuntimeError):
    """A feed that is missing, unreadable or malformed. Never swallowed into
    "no indicators"."""


def _check(feed, where: str) -> list:
    if not isinstance(feed, dict) or feed.get("version") != 1 \
            or not isinstance(feed.get("campaigns"), list):
        raise IocFeedError(f"{where} is not an indicator feed (expected "
                           '{"version": 1, "campaigns": [...]})')
    for c in feed["campaigns"]:
        if not isinstance(c, dict) or not all(
                isinstance(c.get(k), str) and c[k]
                for k in ("id", "title")) or not isinstance(
                    c.get("indicators"), list):
            raise IocFeedError(f"{where}: a campaign needs 'id', 'title' and "
                               "'indicators'")
        for i in c["indicators"]:
            if not isinstance(i, dict) or i.get("type") not in TYPES \
                    or not isinstance(i.get("value"), str) or not i["value"] \
                    or i.get("status", "active") not in STATUSES:
                raise IocFeedError(
                    f"{where}: campaign '{c['id']}' has an indicator that "
                    "needs a 'type' (" + ", ".join(TYPES) + ") and a "
                    "'value'")
    return feed["campaigns"]


def load_feed(extra_paths=()) -> list:
    """The shipped campaigns plus those in each of `extra_paths`."""
    try:
        text = resources.files(__package__).joinpath(FEED_NAME).read_text(
            encoding="utf-8")
        campaigns = list(_check(json.loads(text), FEED_NAME))
    except IocFeedError:
        raise
    except Exception as e:
        raise IocFeedError(f"the indicator feed {FEED_NAME} cannot be read "
                           f"({type(e).__name__}); this install is "
                           "broken") from None
    for path in extra_paths:
        try:
            raw = feeds.read_source(path, MAX_FEED_BYTES, "--ioc-feed")
            campaigns += _check(json.loads(raw.decode("utf-8-sig")),
                                f"--ioc-feed {feeds.shown(path)}")
        except IocFeedError:
            raise
        except feeds.FeedSourceError as e:
            raise IocFeedError(str(e)) from None
        except (ValueError, RecursionError) as e:
            raise IocFeedError(f"--ioc-feed {feeds.shown(path)} cannot be "
                               f"read ({type(e).__name__})") from None
    return campaigns


_cache: "list | None" = None


def default_feed() -> list:
    global _cache
    if _cache is None:
        _cache = load_feed()
    return _cache


def _units(cfg: dict) -> "list[str]":
    """Every string of a server entry an indicator can be in: the URL, the
    command, the arguments and the values of the environment. (Env values
    are matched, never printed.)"""
    out = []
    for key in ("url", "serverUrl", "command"):
        if isinstance(cfg.get(key), str):
            out.append(cfg[key])
    for a in cfg.get("args") or []:
        out.append(str(a))
    env = cfg.get("env")
    if isinstance(env, dict):
        out += [str(v) for v in env.values()]
    return out


def _pattern(kind: str, value: str):
    v = re.escape(value)
    if kind == "host":
        return re.compile(r"(?<![A-Za-z0-9\-])" + v
                          + r"(?![A-Za-z0-9\-])(?!\.[A-Za-z0-9])",
                          re.IGNORECASE)
    if kind == "github-repo":
        return re.compile(r"github(?:\.com)?[/:]" + v
                          + r"(?![A-Za-z0-9_.\-])", re.IGNORECASE)
    if kind == "github-account":
        return re.compile(r"github(?:\.com)?[/:]" + v
                          + r"(?![A-Za-z0-9_.\-])", re.IGNORECASE)
    return None


def match(name: str, cfg: dict, campaigns: list) -> "list[tuple]":
    """[(campaign, indicator)] for every indicator the entry matches."""
    units = _units(cfg)
    flat = [u.replace("\\", "/").lower() for u in units]
    pkgs = {u.lower() for u in units}
    hits = []
    for c in campaigns:
        for ind in c["indicators"]:
            kind, value = ind["type"], ind["value"]
            if kind == "server-name":
                hit = name.lower() == value.lower()
            elif kind == "path":
                needle = value.replace("\\", "/").lower()
                hit = any(needle in u for u in flat)
            elif kind == "package":
                hit = value.lower() in pkgs or any(
                    u.startswith(value.lower() + "@") for u in pkgs)
            else:
                rx = _pattern(kind, value)
                hit = any(rx.search(u) for u in units)
            if hit:
                hits.append((c, ind))
    return hits


def findings(name: str, cfg: dict, campaigns: list) -> "list[dict]":
    out = []
    seen = set()
    for c, ind in match(name, cfg, campaigns):
        status = ind.get("status", "active")
        sev = _SEVERITY[(ind["type"], status)]
        key = (c["id"], ind["type"], ind["value"])
        if key in seen:
            continue
        seen.add(key)
        label = c.get("source_label") or c["title"]
        note = f" ({ind['note']})" if ind.get("note") else ""
        what = {"host": "talks to", "path": "runs or reads",
                "server-name": "is named", "github-repo": "comes from",
                "github-account": "comes from an account used by",
                "package": "uses the package"}[ind["type"]]
        if ind["type"] == "server-name":
            advice = ("a name alone proves nothing: check where this server "
                      "comes from")
        else:
            advice = ("remove it, rotate every credential it could read and "
                      "check the machine")
        if status == "historical":
            advice = "an earlier indicator of that campaign; " + advice
        out.append({"severity": sev, "check": "known-ioc",
                    "message": f"this server {what} '{ind['value']}'{note}, "
                               f"an indicator of the {c['title']} campaign "
                               f"({label}) - {advice}"})
    return out
