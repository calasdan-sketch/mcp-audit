#!/usr/bin/env python3
"""Fake MCP server that never stops writing.

usage: flood_mcp_server.py MODE   (MODE: "longline" or "lines")

"longline" writes bytes with no newline at all, so a reader that waits for
the end of the line keeps everything in memory; "lines" writes an endless
stream of short log lines. It gives up after 20 seconds (or when its output
pipe is closed) so a failing test cannot leave it running.
"""

import sys
import time

CHUNK_LONG = b"x" * 65536
CHUNK_LINES = b"log line that is not json\n" * 2000


def main() -> None:
    chunk = CHUNK_LONG if sys.argv[1] == "longline" else CHUNK_LINES
    out = sys.stdout.buffer
    deadline = time.time() + 20
    try:
        while time.time() < deadline:
            out.write(chunk)
            out.flush()
    except (BrokenPipeError, OSError):
        pass


if __name__ == "__main__":
    main()
