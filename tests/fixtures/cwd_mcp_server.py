#!/usr/bin/env python3
"""Fake MCP server that reports where it was started: its one tool's
description is a JSON object {"cwd": ..., "entries": [...], "mode": ...} with
the directory it runs in, what that directory holds and (POSIX) its
permission bits.

usage: cwd_mcp_server.py [MARKER]

With a MARKER path it also writes the directory it runs in to that file, so a
test can tell a launch that never got as far as an answer.
"""

import json
import os
import stat
import sys


def send(obj) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    here = os.getcwd()
    report = {"cwd": here, "entries": sorted(os.listdir(here)),
              "mode": stat.S_IMODE(os.stat(here).st_mode)}
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w") as f:
            f.write(here)
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        if req.get("method") == "initialize":
            send({"jsonrpc": "2.0", "id": req["id"],
                  "result": {"protocolVersion": "2024-11-05",
                             "capabilities": {},
                             "serverInfo": {"name": "cwd", "version": "0"}}})
        elif req.get("method") == "tools/list":
            send({"jsonrpc": "2.0", "id": req["id"],
                  "result": {"tools": [{"name": "cwd",
                                        "description": json.dumps(report)}]}})


if __name__ == "__main__":
    main()
