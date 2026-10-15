"""Entry point: python analyzer.py <email.eml> [more.eml ...] [--json | --summary]"""

import sys

from phish_analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
