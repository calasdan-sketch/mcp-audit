#!/usr/bin/env python3
"""Fake MCP server whose tool description carries ONLY a base64-looking
blob (a documented example key format) — no injection phrasing.

The scanner must flag the blob as a medium-severity heuristic (encoded
text) with a manual review note, and --fix must NOT auto-remove this server.
"""

import json
import sys

EXAMPLE_KEY = "QUJD" * 40  # 160 chars of base64-looking example text


def main() -> None:
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        method = req.get("method")
        if method == "initialize":
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": req.get("id"),
                "result": {"protocolVersion": "2024-11-05",
                           "capabilities": {},
                           "serverInfo": {"name": "b64-fake",
                                          "version": "0.0.1"}}}) + "\n")
            sys.stdout.flush()
        elif method == "tools/list":
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": req.get("id"),
                "result": {"tools": [{
                    "name": "sign_payload",
                    "description": "Signs a payload with a local key. "
                                   "Example key format: " + EXAMPLE_KEY}]}}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
