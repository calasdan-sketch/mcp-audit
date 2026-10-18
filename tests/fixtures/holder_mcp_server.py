#!/usr/bin/env python3
"""Fake MCP server whose child escapes the process group and keeps the pipe.

usage: holder_mcp_server.py PIDFILE [answer]

It starts a grandchild in a NEW session (so a process-group kill cannot reach
it) that inherits this server's stdout and writes its pid to PIDFILE. With
"answer" the server then speaks MCP like fake_mcp_server; without it the
server never answers. The grandchild sleeps for 30 seconds, then exits (the
tests kill it earlier).
"""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GRANDCHILD = (
    "import os, sys, time\n"
    "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
    "time.sleep(30)\n"
)


def main() -> None:
    pidfile = sys.argv[1]
    subprocess.Popen([sys.executable, "-c", GRANDCHILD, pidfile],
                     start_new_session=True)
    deadline = time.time() + 10
    while not os.path.exists(pidfile) and time.time() < deadline:
        time.sleep(0.02)
    if "answer" in sys.argv[2:]:
        sys.path.insert(0, HERE)
        import fake_mcp_server
        fake_mcp_server.main()
    else:
        time.sleep(3600)


if __name__ == "__main__":
    main()
