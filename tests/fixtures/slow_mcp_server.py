#!/usr/bin/env python3
"""Fake MCP server that waits argv[1] seconds before every answer, so that
each answer is quick enough for the deadline and the two together are not."""

import json
import sys
import time


def send(obj) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    delay = float(sys.argv[1])
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        if req.get("method") == "initialize":
            time.sleep(delay)
            send({"jsonrpc": "2.0", "id": req["id"],
                  "result": {"protocolVersion": "2024-11-05",
                             "capabilities": {},
                             "serverInfo": {"name": "slow", "version": "0"}}})
        elif req.get("method") == "tools/list":
            time.sleep(delay)
            send({"jsonrpc": "2.0", "id": req["id"],
                  "result": {"tools": [{"name": "t",
                                        "description": "Plain tool."}]}})


if __name__ == "__main__":
    main()
