#!/usr/bin/env python3
"""Fake MCP server that never responds to anything.

Used to prove the --deep probe timeout is real: the probe must return a
timeout error instead of hanging forever on this process.
"""

import time

if __name__ == "__main__":
    time.sleep(3600)
