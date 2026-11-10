"""Explicit, offline initialization of persistent admission state; never enables recovery."""
from __future__ import annotations

import argparse
import os
import sqlite3
from contextlib import closing
from pathlib import Path

SCHEMA = """
CREATE TABLE seen (event TEXT PRIMARY KEY);
CREATE TABLE attempts (connection TEXT PRIMARY KEY, at REAL);
CREATE TABLE arrivals (at REAL);
CREATE TABLE inflight (id INTEGER PRIMARY KEY, until REAL);
CREATE TABLE breaker (id INTEGER PRIMARY KEY, until REAL);
PRAGMA user_version=1;
"""


def initialize_state(directory: Path) -> None:
    """Require a provisioned directory and refuse to overwrite any existing state."""
    path = directory / "recovery.sqlite3"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    # Leave partial state on failure: a subsequent run must not silently reset it.
    with closing(sqlite3.connect(path)) as db:
        db.executescript(SCHEMA)
        db.commit()
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    if not args.directory.is_absolute():
        parser.error("state directory must be absolute and pre-provisioned")
    initialize_state(args.directory)


if __name__ == "__main__":
    main()
