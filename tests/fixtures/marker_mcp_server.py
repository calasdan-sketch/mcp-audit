#!/usr/bin/env python3
"""Not an MCP server: proves it was launched by creating MARKER, then exits.

usage: marker_mcp_server.py MARKER [more args are ignored]
"""

import sys

if __name__ == "__main__":
    with open(sys.argv[1], "w") as f:
        f.write("launched")
