#!/usr/bin/env python3
"""D-ROOTS for an M1 VM: the launcher. The code is in m1_roots.py."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m1_roots  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(m1_roots.main(sys.argv[1:], launcher=os.path.abspath(__file__)))
