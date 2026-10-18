#!/usr/bin/env python3
"""Fake MCP server that starts a child in its OWN process group (the usual
case: npx starting node). The child writes its pid to PIDFILE and sleeps.

usage: family_mcp_server.py PIDFILE [silent]

With "silent" the server never answers (to prove the tree is also killed at
the deadline); otherwise it speaks MCP like fake_mcp_server.
"""

import os
import subprocess
import sys
import time

CHILD = (
    "import os, sys, time\n"
    "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
    "time.sleep(60)\n"
)


def main() -> None:
    pidfile = sys.argv[1]
    subprocess.Popen([sys.executable, "-c", CHILD, pidfile],
                     stdout=subprocess.DEVNULL)
    deadline = time.time() + 10
    while not os.path.exists(pidfile) and time.time() < deadline:
        time.sleep(0.02)
    if "silent" in sys.argv[2:]:
        time.sleep(3600)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import fake_mcp_server
    fake_mcp_server.main()


if __name__ == "__main__":
    main()
