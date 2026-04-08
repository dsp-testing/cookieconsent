"""Fetch CodeQL SARIF from the GitHub Code Scanning API.

Implements the ``fetch-codeql`` subcommand for the sectools CLI.
Requires the ``gh`` CLI (https://cli.github.com) to be installed and
authenticated with a token that has the ``security_events`` scope.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def detect_repo() -> Optional[str]:
    """Auto-detect *owner/repo* from the git remote via ``gh repo view``."""
    try:
        result = subprocess.run(
            ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print(
            "Error: gh CLI not found. Install from https://cli.github.com",
            file=sys.stderr,
        )
        return None

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "auth" in stderr.lower() or "login" in stderr.lower():
            print(
                "Error: gh CLI not authenticated. Run 'gh auth login'",
                file=sys.stderr,
            )
        else:
            print(f"Error: Could not detect repository: {stderr}", file=sys.stderr)
        return None

    repo = result.stdout.strip()
    if not repo or "/" not in repo:
        print("Error: Could not detect repository from git remote.", file=sys.stderr)
        return None
    return repo


def _gh_run(args: list[str]) -> Optional[subprocess.CompletedProcess]:
    """Run a ``gh`` command, handling common error cases.

    Returns the :class:`~subprocess.CompletedProcess` on success, or
    *None* when the command cannot be executed.
    """
    try:
        return subprocess.run(args, capture_output=True, text=True)
    except FileNotFoundError:
        print(
            "Error: gh CLI not found. Install from https://cli.github.com",
            file=sys.stderr,
        )
        return None


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def fetch_codeql(
    repo: Optional[str] = None,
    output_dir: Optional[str] = None,
    analysis_id: Optional[str] = None,
) -> Optional[Path]:
    """Fetch CodeQL SARIF from the GitHub Code Scanning API.

    Args:
        repo: ``owner/repo`` string.  Auto-detected from git remote if
            *None*.
        output_dir: Directory to write ``codeql-raw.sarif``.  Defaults to
            the current working directory.
        analysis_id: Specific analysis ID.  Uses the most recent analysis
            if *None*.

    Returns:
        :class:`~pathlib.Path` to the written SARIF file, or *None* on
        failure.
    """

    # -- Resolve repo ---------------------------------------------------------
    if repo is None:
        repo = detect_repo()
        if repo is None:
            return None

    # -- Resolve analysis ID --------------------------------------------------
    if analysis_id is None:
        result = _gh_run(
            ["gh", "api", f"/repos/{repo}/code-scanning/analyses", "--jq", ".[0].id"]
        )
        if result is None:
            return None
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if "auth" in stderr.lower() or "login" in stderr.lower():
                print(
                    "Error: gh CLI not authenticated. Run 'gh auth login'",
                    file=sys.stderr,
                )
            elif "not found" in stderr.lower() or "no data" in stderr.lower():
                print(
                    f"Error: No Code Scanning analyses found for {repo}. "
                    "Is CodeQL enabled?",
                    file=sys.stderr,
                )
            else:
                print(f"Error: {stderr}", file=sys.stderr)
            return None

        analysis_id = result.stdout.strip()
        if not analysis_id:
            print(
                f"Error: No Code Scanning analyses found for {repo}. "
                "Is CodeQL enabled?",
                file=sys.stderr,
            )
            return None

    # -- Fetch SARIF ----------------------------------------------------------
    result = _gh_run(
        [
            "gh",
            "api",
            f"/repos/{repo}/code-scanning/analyses/{analysis_id}",
            "-H",
            "Accept: application/sarif+json",
        ]
    )
    if result is None:
        return None
    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "auth" in stderr.lower() or "login" in stderr.lower():
            print(
                "Error: gh CLI not authenticated. Run 'gh auth login'",
                file=sys.stderr,
            )
        else:
            print(f"Error: {stderr}", file=sys.stderr)
        return None

    sarif_text = result.stdout

    # -- Validate SARIF -------------------------------------------------------
    try:
        sarif = json.loads(sarif_text)
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Error: Response is not valid JSON: {exc}", file=sys.stderr)
        return None

    if not isinstance(sarif, dict):
        print("Error: SARIF response is not a JSON object.", file=sys.stderr)
        return None
    if "version" not in sarif or "runs" not in sarif:
        print(
            "Error: Response does not look like valid SARIF "
            "(missing 'version' or 'runs' keys).",
            file=sys.stderr,
        )
        return None

    # -- Write to disk --------------------------------------------------------
    out = Path(output_dir) if output_dir else Path.cwd()
    out.mkdir(parents=True, exist_ok=True)
    sarif_path = out / "codeql-raw.sarif"

    sarif_path.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")

    print(f"✅ CodeQL SARIF fetched → {sarif_path} (analysis ID: {analysis_id})")
    return sarif_path


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

def _run(args) -> int:
    """CLI handler for ``fetch-codeql``."""
    result = fetch_codeql(
        repo=args.repo,
        output_dir=args.output,
        analysis_id=args.analysis_id,
    )
    return 0 if result else 1


def add_subparser(subparsers) -> None:
    """Add the ``fetch-codeql`` subcommand to the CLI argument parser."""
    parser = subparsers.add_parser(
        "fetch-codeql",
        help="Fetch CodeQL SARIF from GitHub Code Scanning API",
        description=(
            "Fetches the most recent CodeQL analysis as SARIF from the GitHub "
            "Code Scanning API. Requires the gh CLI to be installed and "
            "authenticated."
        ),
    )
    parser.add_argument(
        "--repo",
        help="Repository (owner/repo). Auto-detected from git remote if omitted.",
    )
    parser.add_argument(
        "--output",
        default=".",
        help="Output directory (default: current directory)",
    )
    parser.add_argument(
        "--analysis-id",
        help="Specific analysis ID (default: most recent)",
    )
    parser.set_defaults(func=_run)
