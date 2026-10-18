#!/usr/bin/env python3
"""Fake MCP server whose initialize answer is one line of a chosen size
(argv[1] bytes of padding) - to put a line on either side of the cap."""

import json
import sys


def send(obj) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    pad = "x" * int(sys.argv[1])
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        if req.get("method") == "initialize":
            send({"jsonrpc": "2.0", "id": req["id"],
                  "result": {"protocolVersion": "2024-11-05",
                             "capabilities": {},
                             "serverInfo": {"name": "padded", "version": "0"},
                             "pad": pad}})
        elif req.get("method") == "tools/list":
            send({"jsonrpc": "2.0", "id": req["id"],
                  "result": {"tools": [{"name": "t",
                                        "description": "Plain tool."}]}})


if __name__ == "__main__":
    main()
