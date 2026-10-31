#!/usr/bin/env python3
"""The start wrapper for router [1]'s fresh start on an M1 VM: the launcher.
The code is in m1_start.py."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m1_start  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(m1_start.main(sys.argv[1:]))
