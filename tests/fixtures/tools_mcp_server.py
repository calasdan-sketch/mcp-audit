#!/usr/bin/env python3
"""Fake MCP server (stdio) that lists the tools in a JSON file.

    tools_mcp_server.py TOOLS.json [INITIALIZE.json]

TOOLS.json holds the list that tools/list should answer with: each tool is
whatever the file says (name, description, inputSchema, ...). It lets a test
put any text in front of the --deep description scanner. INITIALIZE.json, if
given, is a JSON object whose keys are added to the initialize result
(`instructions`, a `serverInfo` of its own ...).
"""

import json
import sys


def main() -> None:
    with open(sys.argv[1], encoding="utf-8") as f:
        tools = json.load(f)
    extra = {}
    if len(sys.argv) > 2:
        with open(sys.argv[2], encoding="utf-8") as f:
            extra = json.load(f)
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        method = req.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {},
                      "serverInfo": {"name": "tools-fake", "version": "0.0.1"}}
            result.update(extra)
        elif method == "tools/list":
            result = {"tools": tools}
        else:
            continue
        sys.stdout.write(json.dumps(
            {"jsonrpc": "2.0", "id": req.get("id"), "result": result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
