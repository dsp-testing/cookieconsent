"""Full scan pipeline orchestrator — fetch, serialize, dedup in one command.

Chains the ``fetch-codeql``, ``serialize``, and ``dedup`` subcommands into a
single workflow, writing a ``run-metadata.json`` sidecar with timing, repo
info, and finding counts.

Pure stdlib; Python 3.8+.
"""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

from sectools import fetch_codeql, schemas
from sectools import serialize as serialize_mod
from sectools import dedup as dedup_mod


def scan(sources="codeql-only", llm_report=None, strategy="moderate",
         output_dir=None, repo=None):
    """Run the full scan pipeline.

    Args:
        sources: ``"codeql-only"``, ``"llm-only"``, or ``"all"``.
        llm_report: Path to a security-review Markdown report (required for
            ``llm-only``, optional for ``all``).
        strategy: Dedup strategy — ``"strict"``, ``"moderate"``, or
            ``"fuzzy"``.
        output_dir: Output directory.  Auto-generated if *None*.
        repo: ``owner/repo`` string.  Auto-detected if *None*.

    Returns:
        Path to the output directory, or *None* on failure.
    """
    start_time = time.time()

    # Create output directory
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = output_dir or f"scan-{ts}"
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    codeql_norm = None
    llm_norm = None

    # Step 1: CodeQL (if sources is "codeql-only" or "all")
    if sources in ("codeql-only", "all"):
        print("═" * 60)
        print("Phase 1: Fetching CodeQL SARIF")
        print("═" * 60)
        codeql_sarif_dir = os.path.join(out_dir, "codeql-raw")
        sarif_path = fetch_codeql.fetch_codeql(
            repo=repo, output_dir=codeql_sarif_dir,
        )
        if sarif_path is None:
            print("⚠️  CodeQL fetch failed")
            if sources == "codeql-only":
                return None  # fatal for codeql-only
        else:
            print("\n" + "═" * 60)
            print("Phase 2: Serializing CodeQL findings")
            print("═" * 60)
            codeql_out = os.path.join(out_dir, "findings-codeql")
            codeql_norm = serialize_mod.serialize(
                str(sarif_path), output_dir=codeql_out,
            )

    # Step 2: LLM report (if sources is "llm-only" or "all")
    if sources in ("llm-only", "all"):
        if llm_report:
            print("\n" + "═" * 60)
            print("Phase 3: Serializing LLM security review")
            print("═" * 60)
            llm_out = os.path.join(out_dir, "findings-security-review")
            llm_norm = serialize_mod.serialize(llm_report, output_dir=llm_out)
        elif sources == "all":
            # Try to find existing security-review findings
            existing = [
                str(p) for p in dedup_mod.discover_inputs(".")
                if "security-review" in str(p)
            ]
            if existing:
                print(f"\n📋 Found existing security-review findings: {existing[0]}")
                llm_norm = str(Path(existing[0]).parent)
            else:
                print("\n⚠️  No --llm-report provided and no existing "
                      "security-review findings found.")
                print("   To include LLM findings, either:")
                print("   1. Run: copilot-cli security-review > report.md")
                print("   2. Then: python -m sectools scan --sources all "
                      "--llm-report report.md")
        elif sources == "llm-only":
            print("❌ --sources llm-only requires --llm-report PATH")
            return None

    # Step 3: Dedup (only when we have findings from multiple sources)
    norm_files = []
    if codeql_norm:
        codeql_norm_path = os.path.join(codeql_norm, "normalized.json")
        if os.path.isfile(codeql_norm_path):
            norm_files.append(codeql_norm_path)
    if llm_norm:
        if os.path.isfile(llm_norm):
            norm_files.append(llm_norm)
        else:
            candidate = os.path.join(llm_norm, "normalized.json")
            if os.path.isfile(candidate):
                norm_files.append(candidate)

    dedup_dir = None
    if len(norm_files) >= 2:
        print("\n" + "═" * 60)
        print(f"Phase 4: Deduplicating ({strategy} strategy)")
        print("═" * 60)
        dedup_out = os.path.join(out_dir, "deduplicated")
        dedup_dir = dedup_mod.deduplicate(
            norm_files, strategy=strategy, output_dir=dedup_out,
        )
    elif len(norm_files) == 1:
        print("\n📋 Only one source — skipping deduplication")

    # Step 4: Write metadata
    elapsed = time.time() - start_time
    _write_metadata(out_dir, sources, strategy, norm_files, dedup_dir,
                    elapsed, repo)

    print("\n" + "═" * 60)
    print(f"✅ Scan complete → {out_dir}/")
    print("═" * 60)
    return out_dir


def _write_metadata(out_dir, sources, strategy, norm_files, dedup_dir,
                    elapsed_seconds, repo=None):
    """Write run-metadata.json sidecar."""
    detected_repo = repo
    branch = None
    commit = None
    try:
        if not detected_repo:
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                url = result.stdout.strip()
                m = re.search(r"[:/]([^/]+/[^/.]+?)(?:\.git)?$", url)
                if m:
                    detected_repo = m.group(1)

        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            branch = result.stdout.strip()

        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            commit = result.stdout.strip()
    except Exception:
        pass

    # Count findings from each source
    source_counts = {}
    for nf in norm_files:
        try:
            with open(nf) as f:
                doc = json.load(f)
            source_counts[doc.get("tool_name", "unknown")] = doc.get(
                "finding_count", 0,
            )
        except Exception:
            pass

    # Count dedup output
    dedup_count = None
    if dedup_dir:
        dedup_json = os.path.join(dedup_dir, "deduplicated.json")
        try:
            with open(dedup_json) as f:
                doc = json.load(f)
            dedup_count = doc.get("finding_count", 0)
        except Exception:
            pass

    now = datetime.now(timezone.utc)
    metadata = {
        "schema_version": "1.0",
        "run_id": now.strftime("%Y%m%d-%H%M%S"),
        "repository": detected_repo,
        "branch": branch,
        "commit": commit,
        "started_at": (now - timedelta(seconds=elapsed_seconds)).isoformat(),
        "completed_at": now.isoformat(),
        "elapsed_seconds": round(elapsed_seconds, 2),
        "sources": sources,
        "dedup_strategy": strategy,
        "tools": {
            "sectools": "0.1.0",
            "python": sys.version.split()[0],
        },
        "finding_counts": {
            "per_source": source_counts,
            "after_dedup": dedup_count,
        },
    }

    meta_path = os.path.join(out_dir, "run-metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"\n📋 Wrote {meta_path}")


def add_subparser(subparsers):
    """Add the ``scan`` subcommand to the CLI argument parser."""
    p = subparsers.add_parser(
        "scan",
        help="Full scan pipeline: fetch + serialize + dedup",
        description="Orchestrate a full security scan pipeline. Fetches CodeQL "
                    "results, serializes findings from multiple sources, and "
                    "deduplicates them.",
    )
    p.add_argument(
        "--sources",
        choices=["all", "codeql-only", "llm-only"],
        default="codeql-only",
        help="Which sources to include (default: codeql-only)",
    )
    p.add_argument("--llm-report", help="Path to security-review Markdown report")
    p.add_argument(
        "--strategy",
        choices=["strict", "moderate", "fuzzy"],
        default="moderate",
        help="Dedup strategy (default: moderate)",
    )
    p.add_argument("--output", help="Output directory (default: auto-generated)")
    p.add_argument(
        "--repo",
        help="Repository (OWNER/REPO). Auto-detected if omitted.",
    )
    p.set_defaults(func=_run)


def _run(args):
    """CLI entry point for the scan subcommand."""
    result = scan(
        sources=args.sources,
        llm_report=args.llm_report,
        strategy=args.strategy,
        output_dir=args.output,
        repo=args.repo,
    )
    raise SystemExit(0 if result else 1)
