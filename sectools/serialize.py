"""Serialize subcommand — parse SARIF or security-review Markdown into normalized outputs.

Reads a SARIF file or security-review Markdown report, normalizes the findings,
and writes normalized.json + findings.sarif to a timestamped output directory.

Pure stdlib; no third-party dependencies.  Python 3.8+.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sectools import parsers, schemas, sarif_emitter, validator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_summary(findings):
    """Return a formatted severity breakdown string.

    Example: ``CRITICAL 1  HIGH 2  MEDIUM 1  LOW 1  INFO 0``
    """
    counts = {s: 0 for s in schemas.SEVERITIES}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        if sev in counts:
            counts[sev] += 1
    return "  ".join(f"{s} {counts[s]}" for s in schemas.SEVERITIES)


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------


def serialize(input_file, output_dir=None):
    """Serialize a SARIF or security-review Markdown file into normalized.json + findings.sarif.

    Args:
        input_file: Path to the input file (SARIF or Markdown).
        output_dir: Output directory. If None, auto-creates timestamped dir.

    Returns:
        Path to the output directory, or None on failure.
    """
    input_file = str(input_file)

    # 1. Detect input type
    input_type = parsers.detect_input_type(input_file)

    # 2. Read input
    try:
        with open(input_file, "r", encoding="utf-8") as fh:
            raw_text = fh.read()
    except OSError as exc:
        print(f"Error reading {input_file}: {exc}")
        return None

    # 3. Parse based on type
    if input_type == "sarif":
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            print(f"Error: invalid JSON in {input_file}: {exc}")
            return None
        findings, tool_name, tool_slug = parsers.parse_sarif(data)
        source_type = "sarif"

    elif input_type == "security-review":
        findings = parsers.parse_security_review_md(raw_text)
        tool_name = "security-review skill"
        tool_slug = "security-review"
        source_type = "security-review"

    else:
        print(f"Error: cannot detect input type for {input_file} (expected SARIF or security-review Markdown)")
        return None

    # 4. Create output directory
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = output_dir or f"findings-{tool_slug}-{ts}"
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    # 5. Write normalized.json
    norm_path = os.path.join(out_dir, "normalized.json")
    envelope = {
        "schema_version": schemas.SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_type": source_type,
        "source_hint": str(input_file),
        "tool_name": tool_name,
        "finding_count": len(findings),
        "findings": findings,
    }
    with open(norm_path, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh, indent=2, ensure_ascii=False)

    # 6. Write findings.sarif
    sarif_path = os.path.join(out_dir, "findings.sarif")
    sarif_emitter.write_sarif(findings, tool_name, sarif_path)

    # 7. Validate both files
    norm_ok = validator.validate_and_report(norm_path, "normalized")
    if not norm_ok:
        try:
            os.remove(norm_path)
        except OSError:
            pass
        print("Error: normalized.json failed validation — deleted broken file.")
        return None

    sarif_ok = validator.validate_and_report(sarif_path, "sarif")
    if not sarif_ok:
        try:
            os.remove(sarif_path)
        except OSError:
            pass
        print("Error: findings.sarif failed validation — deleted broken file.")
        return None

    # 8. Print summary
    n = len(findings)
    print(f"\n✅ Findings serialized → {out_dir}/")
    print()
    print(f"  normalized.json   {n} findings   [validated]")
    print(f"  findings.sarif    {n} results    [validated]")
    print()
    print(f"  Severity:  {_severity_summary(findings)}")
    print(f"  Source:    {source_type} ({tool_name})")

    return out_dir


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def _run(args):
    """Entry point called by argparse."""
    result = serialize(args.input, output_dir=args.output)
    raise SystemExit(0 if result else 1)


def add_subparser(subparsers):
    """Register the ``serialize`` subcommand with an argparse subparsers object."""
    p = subparsers.add_parser(
        "serialize",
        help="Parse SARIF or security-review Markdown into normalized.json + findings.sarif",
        description="Reads a SARIF file or security-review Markdown report, normalizes "
                    "the findings, and writes normalized.json + findings.sarif to a "
                    "timestamped output directory.",
    )
    p.add_argument("input", help="Path to SARIF file or security-review Markdown report")
    p.add_argument("--output", help="Output directory (default: auto-generated timestamped dir)")
    p.set_defaults(func=_run)
