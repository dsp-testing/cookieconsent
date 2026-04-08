# Output Validation

Run **all four checks** in Step 8. The skill MUST NOT report success if any check fails.

---

## Check 1 — `jq` Syntax

Fastest possible sanity check. Catches truncation, unescaped quotes, trailing commas.

```bash
jq empty "$OUTDIR/deduplicated.json" && echo "✅ deduplicated.json: valid JSON" || { echo "❌ INVALID JSON"; exit 1; }
jq empty "$OUTDIR/deduplicated.sarif"  && echo "✅ deduplicated.sarif: valid JSON"  || { echo "❌ INVALID JSON"; exit 1; }
```

If either fails: the file was written incorrectly. **Delete it**, regenerate (Step 6 or
7), and re-run this check. Most common cause: JSON was hand-written instead of using
`json.dump`.

---

## Check 2 — Base Normalized Schema

Validates `deduplicated.json` against the base 10 finding fields, envelope keys, and enum
values. Adapted from the findings-serializer schema check with two key differences:
`source_type` must be `"merged"` (not `security-review`/`sarif`/`freeform`), and
`parsing_notes` must NOT be present. The optional `duplicate_sources` key is allowed on
findings.

```bash
python3 - "$OUTDIR/deduplicated.json" <<'PY'
import json, sys

ENVELOPE_KEYS = {"schema_version", "generated_at", "source_type", "source_hint",
                 "tool_name", "finding_count", "findings", "deduplication"}
FINDING_KEYS_REQUIRED = {"id", "source", "category", "severity", "file", "line",
                         "description", "cwe", "confidence", "code_snippet"}
FINDING_KEYS_OPTIONAL = {"duplicate_sources"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}
STRATEGIES = {"strict", "moderate", "fuzzy"}

errors = []
path = sys.argv[1]

with open(path, encoding="utf-8") as f:
    doc = json.load(f)

# Envelope
missing = ENVELOPE_KEYS - set(doc.keys())
if missing:
    errors.append(f"envelope missing keys: {sorted(missing)}")
if doc.get("schema_version") != "1.0":
    errors.append(f"schema_version must be '1.0', got {doc.get('schema_version')!r}")
if doc.get("source_type") != "merged":
    errors.append(f"source_type must be 'merged', got {doc.get('source_type')!r}")
if "parsing_notes" in doc:
    errors.append("parsing_notes must not be present in deduplicated output")
if not isinstance(doc.get("findings"), list):
    errors.append("findings must be an array")
elif doc.get("finding_count") != len(doc["findings"]):
    errors.append(f"finding_count={doc.get('finding_count')} but len(findings)={len(doc['findings'])}")

# Findings
for i, finding in enumerate(doc.get("findings", [])):
    prefix = f"findings[{i}]"
    if not isinstance(finding, dict):
        errors.append(f"{prefix} is not an object")
        continue
    missing = FINDING_KEYS_REQUIRED - set(finding.keys())
    if missing:
        errors.append(f"{prefix} missing required keys: {sorted(missing)}")
    extra = set(finding.keys()) - FINDING_KEYS_REQUIRED - FINDING_KEYS_OPTIONAL
    if extra:
        errors.append(f"{prefix} has unexpected keys: {sorted(extra)}")
    if finding.get("severity") not in SEVERITIES:
        errors.append(f"{prefix}.severity={finding.get('severity')!r} not in {sorted(SEVERITIES)}")
    if finding.get("confidence") not in CONFIDENCES:
        errors.append(f"{prefix}.confidence={finding.get('confidence')!r} not in {sorted(CONFIDENCES)}")
    if finding.get("file") is not None and not isinstance(finding["file"], str):
        errors.append(f"{prefix}.file must be string or null")
    if finding.get("line") is not None and not isinstance(finding["line"], int):
        errors.append(f"{prefix}.line must be int or null")
    if not isinstance(finding.get("description"), str) or not finding["description"].strip():
        errors.append(f"{prefix}.description must be a non-empty string")
    cwe = finding.get("cwe")
    if cwe is not None and not (isinstance(cwe, str) and cwe.startswith("CWE-") and cwe[4:].isdigit()):
        errors.append(f"{prefix}.cwe={cwe!r} must be 'CWE-<number>' or null")
    # duplicate_sources validation
    ds = finding.get("duplicate_sources")
    if ds is not None:
        if not isinstance(ds, list) or not ds:
            errors.append(f"{prefix}.duplicate_sources must be a non-empty list or absent")
        else:
            for di, d in enumerate(ds):
                if not isinstance(d, dict):
                    errors.append(f"{prefix}.duplicate_sources[{di}] must be an object")
                elif not isinstance(d.get("tool"), str) or not isinstance(d.get("original_id"), str):
                    errors.append(f"{prefix}.duplicate_sources[{di}] must have string 'tool' and 'original_id'")

# ID uniqueness
ids = [f.get("id") for f in doc.get("findings", [])]
if len(ids) != len(set(ids)):
    dupes = sorted({x for x in ids if ids.count(x) > 1})
    errors.append(f"duplicate finding ids: {dupes}")

if errors:
    print(f"❌ deduplicated.json: {len(errors)} schema violation(s)")
    for e in errors:
        print(f"   - {e}")
    sys.exit(1)
print(f"✅ deduplicated.json: schema valid ({len(doc['findings'])} findings)")
PY
```

---

## Check 3 — Deduplication Metadata

Validates the `deduplication` envelope section and cross-checks merged findings against
their `duplicate_sources` annotations.

```bash
python3 - "$OUTDIR/deduplicated.json" <<'PY'
import json, sys

errors = []
path = sys.argv[1]

with open(path, encoding="utf-8") as f:
    doc = json.load(f)

dedup = doc.get("deduplication")
if not isinstance(dedup, dict):
    errors.append("deduplication key must be an object")
else:
    if dedup.get("strategy") not in {"strict", "moderate", "fuzzy"}:
        errors.append(f"deduplication.strategy must be strict/moderate/fuzzy, got {dedup.get('strategy')!r}")
    sources = dedup.get("input_sources")
    if not isinstance(sources, list) or not sources:
        errors.append("deduplication.input_sources must be a non-empty array")
    else:
        computed_total = 0
        for si, s in enumerate(sources):
            if not isinstance(s.get("file"), str):
                errors.append(f"deduplication.input_sources[{si}].file must be a string")
            if not isinstance(s.get("tool"), str):
                errors.append(f"deduplication.input_sources[{si}].tool must be a string")
            if not isinstance(s.get("count"), int):
                errors.append(f"deduplication.input_sources[{si}].count must be an int")
            else:
                computed_total += s["count"]
        if dedup.get("input_total") != computed_total:
            errors.append(f"deduplication.input_total={dedup.get('input_total')} but sum of source counts={computed_total}")
    if not isinstance(dedup.get("duplicates_removed"), int):
        errors.append("deduplication.duplicates_removed must be an int")
    if not isinstance(dedup.get("output_total"), int):
        errors.append("deduplication.output_total must be an int")
    elif dedup.get("output_total") != doc.get("finding_count"):
        errors.append(f"deduplication.output_total={dedup.get('output_total')} != finding_count={doc.get('finding_count')}")
    if isinstance(dedup.get("input_total"), int) and isinstance(dedup.get("duplicates_removed"), int) and isinstance(dedup.get("output_total"), int):
        if dedup["input_total"] - dedup["duplicates_removed"] != dedup["output_total"]:
            errors.append(f"input_total({dedup['input_total']}) - duplicates_removed({dedup['duplicates_removed']}) != output_total({dedup['output_total']})")

# Cross-check: merged findings must have duplicate_sources, singletons must not
for i, f in enumerate(doc.get("findings", [])):
    has_ds = "duplicate_sources" in f
    is_merged = "+" in f.get("source", "")
    if is_merged and not has_ds:
        errors.append(f"findings[{i}] source contains '+' (merged) but has no duplicate_sources")
    if has_ds and not is_merged:
        errors.append(f"findings[{i}] has duplicate_sources but source '{f.get('source')}' doesn't indicate merge")

if errors:
    print(f"❌ deduplication metadata: {len(errors)} violation(s)")
    for e in errors:
        print(f"   - {e}")
    sys.exit(1)
print("✅ deduplication metadata: valid")
PY
```

---

## Check 4 — SARIF Schema

Validates `deduplicated.sarif` against the cached SARIF 2.1.0 JSON Schema. Tries
`jsonschema` first; falls back to structural assertions if unavailable.

```bash
python3 - "$OUTDIR/deduplicated.sarif" "$(dirname "$0")/sarif-2.1.0-schema.json" <<'PY' 2>&1 || \
python3 - "$OUTDIR/deduplicated.sarif" ".github/skills/findings-serializer/references/sarif-2.1.0-schema.json" <<'PY'
import json, sys

sarif_path = sys.argv[1]
schema_path = sys.argv[2]

with open(sarif_path, encoding="utf-8") as f:
    doc = json.load(f)

# --- Try full jsonschema validation ---
try:
    import jsonschema
    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)
    validator = jsonschema.Draft7Validator(schema)
    errs = sorted(validator.iter_errors(doc), key=lambda e: e.path)
    if errs:
        print(f"❌ deduplicated.sarif: {len(errs)} SARIF schema violation(s)")
        for e in errs[:10]:
            loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
            print(f"   - {loc}: {e.message}")
        if len(errs) > 10:
            print(f"   ... and {len(errs) - 10} more")
        sys.exit(1)
    print(f"✅ deduplicated.sarif: SARIF 2.1.0 schema valid (jsonschema)")
    sys.exit(0)
except ImportError:
    pass  # fall through to structural check

# --- Fallback: structural assertions (jsonschema not installed) ---
errors = []
if doc.get("version") != "2.1.0":
    errors.append(f"version must be '2.1.0', got {doc.get('version')!r}")
if "$schema" not in doc:
    errors.append("$schema key missing")
runs = doc.get("runs")
if not isinstance(runs, list) or not runs:
    errors.append("runs must be a non-empty array")
else:
    for ri, run in enumerate(runs):
        driver = run.get("tool", {}).get("driver", {})
        if not driver.get("name"):
            errors.append(f"runs[{ri}].tool.driver.name is required")
        results = run.get("results", [])
        if not isinstance(results, list):
            errors.append(f"runs[{ri}].results must be an array")
            continue
        for i, r in enumerate(results):
            msg = r.get("message")
            if not isinstance(msg, dict) or not isinstance(msg.get("text"), str):
                errors.append(f"runs[{ri}].results[{i}].message.text required")
            level = r.get("level")
            if level is not None and level not in {"none", "note", "warning", "error"}:
                errors.append(f"runs[{ri}].results[{i}].level={level!r} invalid")
            for li, loc in enumerate(r.get("locations", [])):
                region = loc.get("physicalLocation", {}).get("region", {})
                sl = region.get("startLine")
                if sl is not None and (not isinstance(sl, int) or sl < 1):
                    errors.append(f"runs[{ri}].results[{i}].locations[{li}] startLine must be int >= 1")

if errors:
    print(f"❌ deduplicated.sarif: {len(errors)} structural violation(s)")
    for e in errors:
        print(f"   - {e}")
    sys.exit(1)
print(f"✅ deduplicated.sarif: structural check passed (jsonschema not installed — install with: pip3 install --user jsonschema)")
PY
```

---

## Retry Logic

```
for attempt in 1 2 3:
    write file (Step 6 or 7)
    run all four checks above
    if all pass → break (success)
    else:
        capture validator error
        delete the broken file
        fix the data structure based on the error
if attempt 3 still fails:
    report failure to user with the validator error — DO NOT claim success
```

Common fixable errors and their fixes:

| Validator error | Fix |
|---|---|
| `source_type='security-review'` | Must be `'merged'` for dedup output |
| `deduplication key must be an object` | Add the deduplication envelope section |
| `input_total - duplicates_removed != output_total` | Recompute counts from actual data |
| `findings[N] source contains '+' but has no duplicate_sources` | Add duplicate_sources to all merged findings |
| `findings[N] has duplicate_sources but source doesn't indicate merge` | Source should be `"tool1+tool2"` for merged |
| `parsing_notes must not be present` | Remove parsing_notes from envelope |
| `severity='Critical' not in [...]` | Upper-case all enum values before serializing |
| `finding_count=5 but len(findings)=4` | Recompute `finding_count = len(findings)` — never hardcode |
| `findings[N] missing required keys: ['code_snippet']` | Add `"code_snippet": null` for findings without code |
| `cwe='89' must be 'CWE-<number>'` | Prefix with `"CWE-"` |
| `runs[0].results[N].message.text required` | Wrap message in `{"text": ...}` — SARIF messages are objects |
| `startLine must be int >= 1` | Convert 0-indexed lines to 1-indexed; coerce strings to int |
| `jq: parse error` | File was hand-written. Rewrite using `json.dump`. |
