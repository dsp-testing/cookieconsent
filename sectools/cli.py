"""Command-line interface for sectools.

Usage::

    python -m sectools <subcommand> [options]

Subcommands:

    fetch-codeql   Fetch CodeQL SARIF from GitHub Code Scanning API
    serialize      Parse SARIF or security-review Markdown → normalized.json + findings.sarif
    dedup          Merge & deduplicate N normalized.json files
    scan           Full pipeline orchestration (fetch + serialize + dedup)
"""

import argparse
import sys

from sectools import __version__
from sectools import fetch_codeql, serialize, dedup, scan


def main(argv=None):
    """Entry point for the sectools CLI."""
    parser = argparse.ArgumentParser(
        prog="sectools",
        description="Shell tooling for the security-findings pipeline",
        epilog="Run 'sectools <command> --help' for subcommand details.",
    )
    parser.add_argument(
        "--version", action="version", version=f"sectools {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", title="commands")

    # Register all subcommands
    fetch_codeql.add_subparser(subparsers)
    serialize.add_subparser(subparsers)
    dedup.add_subparser(subparsers)
    scan.add_subparser(subparsers)

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        raise SystemExit(0)

    # Each subcommand sets args.func
    args.func(args)


if __name__ == "__main__":
    main()
