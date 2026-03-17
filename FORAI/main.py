#!/usr/bin/env python3
"""
FORAI - Forensic AI Analysis Tool
Main entry point.

Usage:
    python main.py analyze CASE001 --plaso-file timeline.plaso
    python main.py question CASE001 Q7
    python main.py interactive CASE001
    python main.py list-questions

(c) 2025 Shane D. Shook - All Rights Reserved
"""

import sys
from forai.cli import main

if __name__ == "__main__":
    sys.exit(main())
