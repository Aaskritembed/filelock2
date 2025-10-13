#!/usr/bin/env python3
"""
filelocker.py — CLI tool for secure secret sharing
  Commands:
    init <folder_path>  - create encrypted archive and distribute shares
    unlock              - reconstruct from shares (interactive), decrypt, then rotate & redistribute
"""

from cli import main

if __name__ == "__main__":
    main()
