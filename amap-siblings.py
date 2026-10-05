#!/usr/bin/env python3
"""Launcher. The code is in `siblings.py` (an importable module); this file
keeps the command-line name. Hyphen means "run me", underscore means
"import me"."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from siblings import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
