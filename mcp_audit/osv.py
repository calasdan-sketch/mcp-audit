"""OSV lookups for --online: one /v1/querybatch request per 1000 pinned
packages instead of one request per package, a capped read of the answer and
a 24-hour file cache.

Only the ecosystem, the package name and the exact version leave the
machine. A failed lookup is reported (never read as "no vulnerabilities")
and never cached."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
import time
import urllib.request

BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_BATCH = 1000                    # OSV's limit per request
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
CACHE_SECONDS = 24 * 60 * 60
MAX_CACHE_BYTES = 8 * 1024 * 1024

Key = "tuple[str, str, str]"        # (ecosystem, name, version)


def cache_path() -> "str | None":
    """Where the cache lives: $MCP_AUDIT_CACHE_DIR, else the user's cache
    directory. None when none can be found."""
    base = os.environ.get("MCP_AUDIT_CACHE_DIR")
    if not base:
        if sys.platform == "win32":
            root = os.environ.get("LOCALAPPDATA")
        else:
            root = os.environ.get("XDG_CACHE_HOME") or (
                os.path.join(os.path.expanduser("~"), ".cache")
                if os.path.expanduser("~") != "~" else None)
        if not root:
            return None
        base = os.path.join(root, "mcp-audit")
    return os.path.join(base, "osv-cache.json")


def _skey(key) -> str:
    return "\x1f".join(key)


def _load_cache(path: "str | None") -> dict:
    if not path:
        return {}
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_CACHE_BYTES + 1)
        if len(raw) > MAX_CACHE_BYTES:
            return {}
        data = json.loads(raw.decode("utf-8"))
        entries = data.get("entries") if isinstance(data, dict) else None
        return entries if isinstance(entries, dict) else {}
    except (OSError, ValueError, RecursionError):
        return {}


def _save_cache(path: "str | None", entries: dict) -> None:
    if not path:
        return
    tmp = None
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".osv-", dir=os.path.dirname(path))
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"version": 1, "entries": entries}, f)
        os.replace(tmp, path)
        tmp = None
    except OSError:
        pass    # a cache that cannot be written only costs a lookup
    finally:
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


def _post(queries: list, timeout: float) -> list:
    body = json.dumps({"queries": [
        {"package": {"name": n, "ecosystem": e}, "version": v}
        for e, n, v in queries]}).encode()
    req = urllib.request.Request(
        BATCH_URL, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("the answer is larger than "
                         f"{MAX_RESPONSE_BYTES // (1024 * 1024)} MB")
    results = json.loads(raw.decode("utf-8")).get("results")
    if not isinstance(results, list) or len(results) != len(queries):
        raise ValueError("the answer does not match the question")
    out = []
    for r in results:
        vulns = r.get("vulns") if isinstance(r, dict) else None
        out.append(sorted({str(v["id"]) for v in vulns or []
                           if isinstance(v, dict) and v.get("id")}))
    return out


def lookup(keys, timeout: float = 10, cache: "str | None" = None,
           now=time.time) -> dict:
    """{key: ("ok", [vulnerability ids]) | ("error", text)} for each
    (ecosystem, name, version) in `keys`. `cache`: the cache file, or None
    for no cache."""
    keys = list(dict.fromkeys(keys))
    entries = _load_cache(cache)
    t = now()
    out: dict = {}
    todo = []
    for k in keys:
        e = entries.get(_skey(k))
        if (isinstance(e, dict) and isinstance(e.get("t"), (int, float))
                and isinstance(e.get("ids"), list)
                and 0 <= t - e["t"] < CACHE_SECONDS):
            out[k] = ("ok", [str(i) for i in e["ids"]])
        else:
            todo.append(k)
    fresh = False
    for i in range(0, len(todo), MAX_BATCH):
        chunk = todo[i:i + MAX_BATCH]
        try:
            answers = _post(chunk, timeout)
        except (OSError, ValueError, RecursionError, AttributeError,
                KeyError) as e:
            for k in chunk:
                out[k] = ("error", str(e) or type(e).__name__)
            continue
        for k, ids in zip(chunk, answers):
            out[k] = ("ok", ids)
            entries[_skey(k)] = {"t": t, "ids": ids}
            fresh = True
    if fresh:
        # drop what has expired, so the file does not grow for ever
        entries = {k: e for k, e in entries.items()
                   if isinstance(e, dict)
                   and isinstance(e.get("t"), (int, float))
                   and 0 <= t - e["t"] < CACHE_SECONDS}
        _save_cache(cache, entries)
    return out
