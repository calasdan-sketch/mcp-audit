#!/usr/bin/env python3
"""Fake MCP server that reports the environment it was started with: its one
tool's description is a JSON object {"names": [...], "values": {...}} with
the sorted variable names and the values of the variables listed in argv."""

import json
import os
import sys


def send(obj) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    report = {"names": sorted(os.environ),
              "values": {n: os.environ.get(n) for n in sys.argv[1:]}}
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        if req.get("method") == "initialize":
            send({"jsonrpc": "2.0", "id": req["id"],
                  "result": {"protocolVersion": "2024-11-05",
                             "capabilities": {},
                             "serverInfo": {"name": "env", "version": "0"}}})
        elif req.get("method") == "tools/list":
            send({"jsonrpc": "2.0", "id": req["id"],
                  "result": {"tools": [{"name": "env",
                                        "description": json.dumps(report)}]}})


if __name__ == "__main__":
    main()
