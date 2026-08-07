"""
Makes the project root importable from test files.

Tests live in tests/, but the modules they test (app.py, detector.py,
validation.py) sit at the repository root. pytest adds the directory holding
this file to sys.path, so `from validation import ...` resolves from inside
tests/ without needing a package layout or an installed distribution.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
