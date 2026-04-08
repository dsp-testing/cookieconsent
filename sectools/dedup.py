"""Deduplicate findings from multiple normalized.json files.

Implements three strategies (strict, moderate, fuzzy) for matching findings
across sources, uses union-find for transitive grouping, and merges duplicate
clusters following the merge rules in dedup-strategies.md.

Writes ``deduplicated.json`` + ``deduplicated.sarif`` to an output directory.
Pure stdlib; Python 3.8+.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sectools import schemas
from sectools.sarif_emitter import write_sarif
from sectools.validator import validate_and_report, validate_normalized


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------


def discover_inputs(base_dir="."):
    """Find all findings-*/normalized.json and scan-*/*/normalized.json files.

    Skips files that are already deduplicated (source_type == "merged").
    Returns list of Path objects.
    """
    base = Path(base_dir)
    patterns = [
        "findings-*/normalized.json",
        "scan-*/*/normalized.json",
    ]
    skip_patterns = [
        "dedup-*/deduplicated.json",
    ]

    skip_paths = set()
    for sp in skip_patterns:
        skip_paths.update(base.glob(sp))

    results = []
    for pattern in patterns:
        for p in sorted(base.glob(pattern)):
            if p in skip_paths:
                continue
            # Also skip if the file itself is a merged output
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
                if doc.get("source_type") == "merged":
                    continue
            except Exception:
                continue
            results.append(p)
    return results


# ---------------------------------------------------------------------------
# Duplicate detection functions
# ---------------------------------------------------------------------------


def is_duplicate_strict(a, b):
    """Strict: same file + same category + lines within 5."""
    if a["source"] == b["source"]:
        return False
    if a["file"] is None or b["file"] is None:
        return False
    if a["file"] != b["file"]:
        return False
    if a["category"] != b["category"]:
        return False
    if a["line"] is None or b["line"] is None:
        return False
    return abs(a["line"] - b["line"]) <= 5


def is_duplicate_moderate(a, b):
    """Moderate: same file + same category."""
    if a["source"] == b["source"]:
        return False
    if a["file"] is None or b["file"] is None:
        return False
    if a["file"] != b["file"]:
        return False
    return a["category"] == b["category"]


def jaccard_similarity(text_a, text_b):
    """Token-level Jaccard similarity on lowercased, whitespace-split tokens."""
    tokens_a = set(text_a.lower().split())
    tokens_b = set(text_b.lower().split())
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)


def is_duplicate_fuzzy(a, b):
    """Fuzzy: same category + Jaccard similarity >= 0.7 on descriptions."""
    if a["source"] == b["source"]:
        return False
    if a["category"] != b["category"]:
        return False
    return jaccard_similarity(a["description"], b["description"]) >= 0.7


_STRATEGY_FN = {
    "strict": is_duplicate_strict,
    "moderate": is_duplicate_moderate,
    "fuzzy": is_duplicate_fuzzy,
}


# ---------------------------------------------------------------------------
# Union-Find grouping
# ---------------------------------------------------------------------------


def _find(parent, x):
    """Find root with path compression."""
    while parent.get(x, x) != x:
        parent[x] = parent.get(parent[x], parent[x])
        x = parent[x]
    return x


def _union(parent, a, b):
    """Union two elements."""
    ra, rb = _find(parent, a), _find(parent, b)
    if ra != rb:
        parent[ra] = rb


def build_groups(all_findings, is_duplicate_fn):
    """Group findings into duplicate clusters using union-find.

    Returns dict: {root_index: [indices]}
    """
    parent = {}
    for i in range(len(all_findings)):
        for j in range(i + 1, len(all_findings)):
            if is_duplicate_fn(all_findings[i], all_findings[j]):
                _union(parent, i, j)

    groups = {}
    for i in range(len(all_findings)):
        root = _find(parent, i)
        groups.setdefault(root, []).append(i)
    return groups


# ---------------------------------------------------------------------------
# Merge rules
# ---------------------------------------------------------------------------


def merge_group(findings_in_group):
    """Merge a group of duplicate findings into one.

    Rules (from dedup-strategies.md):
    - severity: highest (CRITICAL > HIGH > MEDIUM > LOW > INFO)
    - confidence: highest
    - description: longest
    - code_snippet: longest non-null
    - file/line: from highest-severity finding
    - cwe: first non-null in severity order
    - source: alphabetically joined with "+"
    - id: "M-NNN" (set by caller)
    - duplicate_sources: [{tool, original_id}] for each input finding
    """
    # Sort by severity (highest first), using SEVERITY_ORDER (lower index = higher)
    sorted_findings = sorted(
        findings_in_group,
        key=lambda f: schemas.SEVERITY_ORDER.get(f["severity"], 99),
    )

    best = sorted_findings[0]  # highest severity

    # severity: highest
    severity = best["severity"]

    # confidence: highest across group
    confidence = sorted_findings[0]["confidence"]
    for f in sorted_findings[1:]:
        confidence = schemas.higher_confidence(confidence, f["confidence"])

    # file/line: from highest-severity finding
    file_val = best["file"]
    line_val = best["line"]

    # description: longest
    description = max(
        (f["description"] for f in sorted_findings), key=len
    )

    # code_snippet: longest non-null
    snippets = [f["code_snippet"] for f in sorted_findings if f.get("code_snippet")]
    code_snippet = max(snippets, key=len) if snippets else None

    # cwe: first non-null in severity order
    cwe = None
    for f in sorted_findings:
        if f.get("cwe") is not None:
            cwe = f["cwe"]
            break

    # source: alphabetically sorted unique sources joined with "+"
    sources = sorted(set(f["source"] for f in sorted_findings))
    source = "+".join(sources)

    # category: same across group
    category = best["category"]

    # duplicate_sources
    duplicate_sources = [
        {"tool": f["source"], "original_id": f["id"]}
        for f in sorted_findings
    ]

    return {
        "id": None,  # set by caller
        "source": source,
        "category": category,
        "severity": severity,
        "file": file_val,
        "line": line_val,
        "description": description,
        "cwe": cwe,
        "confidence": confidence,
        "code_snippet": code_snippet,
        "duplicate_sources": duplicate_sources,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def deduplicate(input_files, strategy="moderate", output_dir=None):
    """Deduplicate findings from multiple normalized.json files.

    Args:
        input_files: List of paths to normalized.json files.
        strategy: "strict", "moderate", or "fuzzy".
        output_dir: Output directory. Auto-generated if None.

    Returns:
        Path to output directory, or None on failure.
    """
    if strategy not in _STRATEGY_FN:
        print(f"❌ Unknown strategy: {strategy!r}")
        return None

    if not input_files:
        print("❌ No input files provided.")
        return None

    # 1. Load and validate all input files
    all_findings = []
    input_sources = []
    load_errors = False

    for fpath in input_files:
        fpath = str(fpath)
        try:
            with open(fpath, "r", encoding="utf-8") as fp:
                doc = json.load(fp)
        except Exception as exc:
            print(f"❌ Failed to load {fpath}: {exc}")
            load_errors = True
            continue

        errors = validate_normalized(doc)
        if errors:
            print(f"❌ Validation errors in {fpath}:")
            for e in errors:
                print(f"   - {e}")
            load_errors = True
            continue

        tool_name = doc.get("tool_name", "unknown")
        findings = doc.get("findings", [])
        count = len(findings)

        input_sources.append({
            "file": fpath,
            "tool": tool_name,
            "count": count,
        })

        for f in findings:
            all_findings.append(f)

    if load_errors and not all_findings:
        return None

    input_total = len(all_findings)
    print(f"📥 Loaded {input_total} findings from {len(input_sources)} source(s)")

    # 2. Select strategy function
    is_dup_fn = _STRATEGY_FN[strategy]

    # 3. Build duplicate groups
    groups = build_groups(all_findings, is_dup_fn)

    # 4. Merge groups and build output
    output_findings = []
    merged_counter = 0

    # Process groups in deterministic order (sorted by root index)
    for root in sorted(groups.keys()):
        indices = groups[root]
        group_findings = [all_findings[i] for i in indices]

        if len(group_findings) == 1:
            # Singleton: keep original fields, prefix id with source
            f = dict(group_findings[0])
            f["id"] = f"{f['source']}:{f['id']}"
            output_findings.append(f)
        else:
            # Merged: apply merge rules
            merged_counter += 1
            merged = merge_group(group_findings)
            merged["id"] = f"M-{merged_counter:03d}"
            output_findings.append(merged)

    duplicates_removed = input_total - len(output_findings)
    print(
        f"🔍 Strategy: {strategy} | "
        f"Duplicates removed: {duplicates_removed} | "
        f"Output: {len(output_findings)} findings"
    )

    # 5. Build output directory
    if output_dir is None:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = f"dedup-{ts}"

    os.makedirs(output_dir, exist_ok=True)

    # 6. Build deduplicated.json envelope
    envelope = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_type": "merged",
        "source_hint": f"deduplicated from {len(input_sources)} sources",
        "tool_name": "findings-deduplicator",
        "finding_count": len(output_findings),
        "findings": output_findings,
        "deduplication": {
            "strategy": strategy,
            "input_sources": input_sources,
            "input_total": input_total,
            "duplicates_removed": duplicates_removed,
            "output_total": len(output_findings),
        },
    }

    # 7. Write deduplicated.json
    json_path = os.path.join(output_dir, "deduplicated.json")
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(envelope, fp, indent=2, ensure_ascii=False)
    print(f"📄 Wrote {json_path}")

    # 8. Write deduplicated.sarif
    sarif_path = os.path.join(output_dir, "deduplicated.sarif")
    write_sarif(output_findings, "findings-deduplicator", sarif_path)
    print(f"📄 Wrote {sarif_path}")

    # 9. Validate outputs
    print()
    json_ok = validate_and_report(json_path, "dedup")
    sarif_ok = validate_and_report(sarif_path, "sarif")

    if json_ok and sarif_ok:
        print(f"\n✅ Deduplication complete → {output_dir}/")
    else:
        print(f"\n⚠️  Output written to {output_dir}/ but validation had errors")

    return output_dir


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def _run(args):
    """CLI entry point for the dedup subcommand."""
    files = args.files
    if not files:
        files = [str(p) for p in discover_inputs(".")]
        if not files:
            print("❌ No normalized.json files found. Provide paths or run from repo root.")
            return 1

    result = deduplicate(files, strategy=args.strategy, output_dir=args.output)
    return 0 if result else 1


def add_subparser(subparsers):
    """Add the ``dedup`` subcommand to the CLI argument parser."""
    parser = subparsers.add_parser(
        "dedup",
        help="Merge and deduplicate findings from multiple normalized.json files",
    )
    parser.add_argument(
        "files", nargs="*", help="normalized.json files (auto-discovered if omitted)"
    )
    parser.add_argument(
        "--strategy",
        choices=["strict", "moderate", "fuzzy"],
        default="moderate",
        help="Deduplication strategy (default: moderate)",
    )
    parser.add_argument(
        "--output", help="Output directory (default: auto-generated)"
    )
    parser.set_defaults(func=_run)
