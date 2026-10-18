#!/usr/bin/env python3
"""Fake MCP server that answers initialize and then exits at tools/list: a
probe that reports "no tools, all clear" for it would be failing open."""

import json
import sys


def main() -> None:
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        if req.get("method") == "initialize":
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": req["id"],
                "result": {"protocolVersion": "2024-11-05",
                           "capabilities": {},
                           "serverInfo": {"name": "dying", "version": "0"}}}
            ) + "\n")
            sys.stdout.flush()
        elif req.get("method") == "tools/list":
            return


if __name__ == "__main__":
    main()
