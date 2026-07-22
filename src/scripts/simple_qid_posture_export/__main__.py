"""Enable ``python -m scripts.simple_qid_posture_export``."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
