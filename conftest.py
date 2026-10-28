"""Pytest support: expose both project root and tests/ on sys.path.

The canonical test runner is `python -m unittest discover -s tests -v` (see
README), which places tests/ on sys.path so `e2e_support` is importable and
the project root provides `scanner`. This conftest gives `pytest` the same
view without modifying the test modules.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TESTS = ROOT / "tests"

for entry in (str(TESTS), str(ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)
