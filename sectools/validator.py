"""Pure-Python validators for sectools output files.

Validates normalized.json, deduplicated.json, and findings.sarif documents
against the schema defined in sectools.schemas. No third-party dependencies —
stdlib only (Python 3.8+).
"""

import json
import re
from pathlib import Path

from sectools.schemas import (
    CONFIDENCES,
    DEDUP_STRATEGIES,
    ENVELOPE_KEYS,
    FINDING_OPTIONAL_KEYS,
    FINDING_REQUIRED_KEYS,
    SEVERITIES,
    SOURCE_TYPES,
)

_CWE_RE = re.compile(r"^CWE-\d+$")
_ALL_FINDING_KEYS = FINDING_REQUIRED_KEYS | FINDING_OPTIONAL_KEYS


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_finding(idx, f):
    """Validate a single finding dict. Returns list of error strings."""
    errors = []
    prefix = f"findings[{idx}]"

    if not isinstance(f, dict):
        return [f"{prefix}: expected dict, got {type(f).__name__}"]

    # Required keys
    missing = FINDING_REQUIRED_KEYS - f.keys()
    if missing:
        errors.append(f"{prefix}: missing required keys {sorted(missing)}")

    # Unexpected keys
    extra = f.keys() - _ALL_FINDING_KEYS
    if extra:
        errors.append(f"{prefix}: unexpected keys {sorted(extra)}")

    # severity
    if "severity" in f and f["severity"] not in SEVERITIES:
        errors.append(
            f"{prefix}: severity {f['severity']!r} not in {SEVERITIES}"
        )

    # confidence
    if "confidence" in f and f["confidence"] not in CONFIDENCES:
        errors.append(
            f"{prefix}: confidence {f['confidence']!r} not in {CONFIDENCES}"
        )

    # file
    if "file" in f:
        if f["file"] is not None and not isinstance(f["file"], str):
            errors.append(f"{prefix}: file must be str or None")

    # line
    if "line" in f:
        if f["line"] is not None and not isinstance(f["line"], int):
            errors.append(f"{prefix}: line must be int or None")
        if "file" in f and f["file"] is None and f.get("line") is not None:
            errors.append(f"{prefix}: line must be None when file is None")

    # description
    if "description" in f:
        if not isinstance(f["description"], str) or not f["description"]:
            errors.append(f"{prefix}: description must be non-empty string")

    # cwe
    if "cwe" in f:
        cwe = f["cwe"]
        if cwe is not None:
            if not isinstance(cwe, str) or not _CWE_RE.match(cwe):
                errors.append(
                    f"{prefix}: cwe must be None or match CWE-\\d+"
                )

    # code_snippet
    if "code_snippet" in f:
        cs = f["code_snippet"]
        if cs is not None and not isinstance(cs, str):
            errors.append(f"{prefix}: code_snippet must be str or None")

    return errors


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_normalized(doc):
    """Validate a normalized.json document.

    Args:
        doc: Parsed JSON document (dict).

    Returns:
        List of error strings (empty means valid).
    """
    errors = []

    # Envelope keys
    missing = ENVELOPE_KEYS - doc.keys()
    if missing:
        errors.append(f"Missing envelope keys: {sorted(missing)}")

    # schema_version
    if doc.get("schema_version") != "1.0":
        errors.append(
            f"schema_version must be '1.0', got {doc.get('schema_version')!r}"
        )

    # source_type
    st = doc.get("source_type")
    if st not in SOURCE_TYPES:
        errors.append(f"source_type {st!r} not in {sorted(SOURCE_TYPES)}")

    # findings must be list
    findings = doc.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be a list")
        return errors  # can't continue per-finding checks

    # finding_count
    fc = doc.get("finding_count")
    if fc != len(findings):
        errors.append(
            f"finding_count ({fc}) != len(findings) ({len(findings)})"
        )

    # parsing_notes rules
    has_notes = "parsing_notes" in doc
    if st == "freeform" and not has_notes:
        errors.append("parsing_notes is required when source_type is 'freeform'")
    if st != "freeform" and has_notes:
        errors.append("parsing_notes only allowed when source_type is 'freeform'")

    # Per-finding checks
    seen_ids = set()
    for idx, f in enumerate(findings):
        errors.extend(_check_finding(idx, f))
        fid = f.get("id") if isinstance(f, dict) else None
        if fid is not None:
            if fid in seen_ids:
                errors.append(f"Duplicate finding id: {fid!r}")
            seen_ids.add(fid)

    return errors


def validate_dedup(doc):
    """Validate a deduplicated.json document.

    Runs base normalized checks first, then applies dedup-specific rules.

    Args:
        doc: Parsed JSON document (dict).

    Returns:
        List of error strings (empty means valid).
    """
    # Run base checks but override the source_type constraint afterwards
    errors = validate_normalized(doc)

    st = doc.get("source_type")

    # Override: source_type must be "merged" (drop base error if it exists)
    base_st_prefix = "source_type "
    errors = [e for e in errors if not e.startswith(base_st_prefix)]
    if st != "merged":
        errors.append(f"source_type must be 'merged' for dedup, got {st!r}")

    # parsing_notes must NOT be present (drop base "required" error for freeform)
    errors = [e for e in errors if "parsing_notes" not in e]
    if "parsing_notes" in doc:
        errors.append("parsing_notes must not be present in dedup output")

    # deduplication block
    dedup = doc.get("deduplication")
    if dedup is None:
        errors.append("Missing 'deduplication' key")
        return errors

    if not isinstance(dedup, dict):
        errors.append("'deduplication' must be a dict")
        return errors

    # strategy
    strat = dedup.get("strategy")
    if strat not in DEDUP_STRATEGIES:
        errors.append(
            f"deduplication.strategy {strat!r} not in {DEDUP_STRATEGIES}"
        )

    # input_sources
    sources = dedup.get("input_sources")
    if not isinstance(sources, list) or len(sources) == 0:
        errors.append("deduplication.input_sources must be a non-empty list")
    else:
        for i, src in enumerate(sources):
            if not isinstance(src, dict):
                errors.append(f"deduplication.input_sources[{i}]: expected dict")
                continue
            if not isinstance(src.get("file"), str):
                errors.append(f"deduplication.input_sources[{i}]: file must be str")
            if not isinstance(src.get("tool"), str):
                errors.append(f"deduplication.input_sources[{i}]: tool must be str")
            if not isinstance(src.get("count"), int):
                errors.append(f"deduplication.input_sources[{i}]: count must be int")

    # input_total
    input_total = dedup.get("input_total")
    if not isinstance(input_total, int):
        errors.append("deduplication.input_total must be int")
    elif isinstance(sources, list) and all(
        isinstance(s, dict) and isinstance(s.get("count"), int) for s in sources
    ):
        expected = sum(s["count"] for s in sources)
        if input_total != expected:
            errors.append(
                f"deduplication.input_total ({input_total}) != sum of source counts ({expected})"
            )

    # duplicates_removed
    dup_removed = dedup.get("duplicates_removed")
    if not isinstance(dup_removed, int):
        errors.append("deduplication.duplicates_removed must be int")

    # output_total
    output_total = dedup.get("output_total")
    if not isinstance(output_total, int):
        errors.append("deduplication.output_total must be int")
    else:
        fc = doc.get("finding_count")
        if isinstance(fc, int) and output_total != fc:
            errors.append(
                f"deduplication.output_total ({output_total}) != finding_count ({fc})"
            )

    # Math check
    if (
        isinstance(input_total, int)
        and isinstance(dup_removed, int)
        and isinstance(output_total, int)
    ):
        if input_total - dup_removed != output_total:
            errors.append(
                f"Math check failed: input_total ({input_total}) - "
                f"duplicates_removed ({dup_removed}) != output_total ({output_total})"
            )

    # Merged finding cross-checks
    findings = doc.get("findings")
    if isinstance(findings, list):
        for idx, f in enumerate(findings):
            if not isinstance(f, dict):
                continue
            src = f.get("source", "")
            has_dup_sources = "duplicate_sources" in f
            is_merged = isinstance(src, str) and "+" in src

            if is_merged and not has_dup_sources:
                errors.append(
                    f"findings[{idx}]: merged source contains '+' but "
                    f"duplicate_sources is missing"
                )
            if has_dup_sources and not is_merged:
                errors.append(
                    f"findings[{idx}]: duplicate_sources present but "
                    f"source does not contain '+'"
                )

            if has_dup_sources:
                ds = f["duplicate_sources"]
                if not isinstance(ds, list) or len(ds) == 0:
                    errors.append(
                        f"findings[{idx}]: duplicate_sources must be non-empty list"
                    )
                elif isinstance(ds, list):
                    for j, entry in enumerate(ds):
                        if not isinstance(entry, dict):
                            errors.append(
                                f"findings[{idx}].duplicate_sources[{j}]: expected dict"
                            )
                            continue
                        if not isinstance(entry.get("tool"), str):
                            errors.append(
                                f"findings[{idx}].duplicate_sources[{j}]: "
                                f"tool must be str"
                            )
                        if not isinstance(entry.get("original_id"), str):
                            errors.append(
                                f"findings[{idx}].duplicate_sources[{j}]: "
                                f"original_id must be str"
                            )

    return errors


def validate_sarif(doc):
    """Validate a SARIF 2.1.0 document structurally.

    Args:
        doc: Parsed JSON document (dict).

    Returns:
        List of error strings (empty means valid).
    """
    errors = []

    if doc.get("version") != "2.1.0":
        errors.append(
            f"version must be '2.1.0', got {doc.get('version')!r}"
        )

    if "$schema" not in doc:
        errors.append("Missing '$schema' key")

    runs = doc.get("runs")
    if not isinstance(runs, list) or len(runs) == 0:
        errors.append("'runs' must be a non-empty list")
        return errors

    for ri, run in enumerate(runs):
        prefix = f"runs[{ri}]"

        # tool.driver.name
        tool = run.get("tool") if isinstance(run, dict) else None
        driver = tool.get("driver") if isinstance(tool, dict) else None
        name = driver.get("name") if isinstance(driver, dict) else None
        if not isinstance(name, str) or not name:
            errors.append(f"{prefix}: tool.driver.name must be a non-empty string")

        results = run.get("results") if isinstance(run, dict) else None
        if not isinstance(results, list):
            errors.append(f"{prefix}: results must be a list")
            continue

        for rj, result in enumerate(results):
            rprefix = f"{prefix}.results[{rj}]"

            # message.text
            msg = result.get("message") if isinstance(result, dict) else None
            if not isinstance(msg, dict) or not isinstance(msg.get("text"), str):
                errors.append(f"{rprefix}: message must be dict with 'text' string key")

            # level
            level = result.get("level") if isinstance(result, dict) else None
            if level is not None and level not in ("none", "note", "warning", "error"):
                errors.append(
                    f"{rprefix}: level {level!r} not in "
                    f"('none', 'note', 'warning', 'error')"
                )

            # locations
            locations = result.get("locations", []) if isinstance(result, dict) else []
            if isinstance(locations, list):
                for li, loc in enumerate(locations):
                    if not isinstance(loc, dict):
                        continue
                    phys = loc.get("physicalLocation")
                    if isinstance(phys, dict):
                        region = phys.get("region")
                        if isinstance(region, dict) and "startLine" in region:
                            sl = region["startLine"]
                            if not isinstance(sl, int) or sl < 1:
                                errors.append(
                                    f"{rprefix}.locations[{li}]: "
                                    f"startLine must be int >= 1, got {sl!r}"
                                )

                        al = phys.get("artifactLocation")
                        if isinstance(al, dict):
                            uri = al.get("uri")
                            if isinstance(uri, str) and uri.startswith("./"):
                                errors.append(
                                    f"{rprefix}.locations[{li}]: "
                                    f"artifactLocation.uri should not start with './'"
                                )

    return errors


# ---------------------------------------------------------------------------
# File-level convenience functions
# ---------------------------------------------------------------------------

_VALIDATORS = {
    "normalized": validate_normalized,
    "dedup": validate_dedup,
    "sarif": validate_sarif,
}


def validate_file(file_path, file_type="normalized"):
    """Validate a JSON file.

    Args:
        file_path: Path to JSON file.
        file_type: "normalized", "dedup", or "sarif"

    Returns:
        List of error strings (empty = valid).
    """
    try:
        text = Path(file_path).read_text(encoding="utf-8")
        doc = json.loads(text)
    except Exception as exc:
        return [f"Invalid JSON: {exc}"]

    validator = _VALIDATORS.get(file_type)
    if validator is None:
        return [f"Unknown file_type {file_type!r}; expected one of {sorted(_VALIDATORS)}"]

    return validator(doc)


def validate_and_report(file_path, file_type="normalized"):
    """Validate and print results to stdout.

    Returns True if valid, False if errors found.
    """
    errors = validate_file(file_path, file_type)
    name = Path(file_path).name

    if errors:
        print(f"❌ {name}: {len(errors)} violation(s)")
        for e in errors:
            print(f"   - {e}")
        return False

    # Get finding count for summary
    try:
        doc = json.loads(Path(file_path).read_text(encoding="utf-8"))
        count = doc.get("finding_count", "?")
        print(f"✅ {name}: valid ({count} findings)")
    except Exception:
        print(f"✅ {name}: valid")

    return True
