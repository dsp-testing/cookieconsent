# Output Validation

Run **all three checks** in Step 6. The skill MUST NOT report success if any check fails.

---

## Check 1 — `jq` Syntax

Fastest possible sanity check. Catches truncation, unescaped quotes, trailing commas.

```bash
jq empty "$OUTDIR/normalized.json" && echo "✅ normalized.json: valid JSON syntax" || { echo "❌ normalized.json: INVALID JSON"; exit 1; }
jq empty "$OUTDIR/findings.sarif"  && echo "✅ findings.sarif: valid JSON syntax"  || { echo "❌ findings.sarif: INVALID JSON";  exit 1; }
```

If either fails: the file was written incorrectly. **Delete it**, regenerate (Step 4 or
5), and re-run this check. Most common cause: JSON was hand-written instead of using
`json.dump`.

---

## Check 2 — Normalized Schema

Validates `normalized.json` against the schema in `normalized-schema.md`. Pure stdlib —
no pip installs required.

```bash
python3 - "$OUTDIR/normalized.json" <<'PY'
import json, sys

ENVELOPE_KEYS = {"schema_version", "generated_at", "source_type", "source_hint",
                 "tool_name", "finding_count", "findings"}
FINDING_KEYS  = {"id", "source", "category", "severity", "file", "line",
                 "description", "cwe", "confidence", "code_snippet"}
SEVERITIES    = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
CONFIDENCES   = {"HIGH", "MEDIUM", "LOW"}
SOURCE_TYPES  = {"security-review", "sarif", "freeform"}

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
if doc.get("source_type") not in SOURCE_TYPES:
    errors.append(f"source_type must be one of {sorted(SOURCE_TYPES)}, got {doc.get('source_type')!r}")
if not isinstance(doc.get("findings"), list):
    errors.append("findings must be an array")
elif doc.get("finding_count") != len(doc["findings"]):
    errors.append(f"finding_count={doc.get('finding_count')} but len(findings)={len(doc['findings'])}")

# parsing_notes only allowed for freeform
if "parsing_notes" in doc and doc.get("source_type") != "freeform":
    errors.append("parsing_notes present but source_type is not 'freeform'")
if doc.get("source_type") == "freeform" and "parsing_notes" not in doc:
    errors.append("source_type is 'freeform' but parsing_notes is missing")

# Findings
for i, finding in enumerate(doc.get("findings", [])):
    prefix = f"findings[{i}]"
    if not isinstance(finding, dict):
        errors.append(f"{prefix} is not an object")
        continue
    missing = FINDING_KEYS - set(finding.keys())
    if missing:
        errors.append(f"{prefix} missing keys: {sorted(missing)}")
    extra = set(finding.keys()) - FINDING_KEYS
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
    if finding.get("file") is None and finding.get("line") is not None:
        errors.append(f"{prefix}.line is set but file is null")
    if not isinstance(finding.get("description"), str) or not finding["description"].strip():
        errors.append(f"{prefix}.description must be a non-empty string")
    cwe = finding.get("cwe")
    if cwe is not None and not (isinstance(cwe, str) and cwe.startswith("CWE-") and cwe[4:].isdigit()):
        errors.append(f"{prefix}.cwe={cwe!r} must be 'CWE-<number>' or null")

# Check id uniqueness
ids = [f.get("id") for f in doc.get("findings", [])]
if len(ids) != len(set(ids)):
    dupes = sorted({x for x in ids if ids.count(x) > 1})
    errors.append(f"duplicate finding ids: {dupes}")

if errors:
    print(f"❌ normalized.json: {len(errors)} schema violation(s)")
    for e in errors:
        print(f"   - {e}")
    sys.exit(1)
print(f"✅ normalized.json: schema valid ({len(doc['findings'])} findings)")
PY
```

---

## Check 3 — SARIF Schema

Validates `findings.sarif` against the cached SARIF 2.1.0 JSON Schema. Tries `jsonschema`
first; falls back to structural assertions if unavailable.

```bash
python3 - "$OUTDIR/findings.sarif" "$(dirname "$0")/sarif-2.1.0-schema.json" <<'PY' 2>&1 || \
python3 - "$OUTDIR/findings.sarif" ".github/skills/findings-serializer/references/sarif-2.1.0-schema.json" <<'PY'
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
        print(f"❌ findings.sarif: {len(errs)} SARIF schema violation(s)")
        for e in errs[:10]:
            loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
            print(f"   - {loc}: {e.message}")
        if len(errs) > 10:
            print(f"   ... and {len(errs) - 10} more")
        sys.exit(1)
    print(f"✅ findings.sarif: SARIF 2.1.0 schema valid (jsonschema)")
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
    print(f"❌ findings.sarif: {len(errors)} structural violation(s)")
    for e in errors:
        print(f"   - {e}")
    sys.exit(1)
print(f"✅ findings.sarif: structural check passed (jsonschema not installed — install with: pip3 install --user jsonschema)")
PY
```

---

## Retry Logic

```
for attempt in 1 2 3:
    write file (Step 4 or 5)
    run all three checks above
    if all pass → break (success)
    else:
        capture validator error
        delete the broken file
        fix the data structure based on the error message
        (e.g. "findings[2].severity='Critical'" → upper-case it to 'CRITICAL')
if attempt 3 still fails:
    report failure to user with the validator error — DO NOT claim success
```

Common fixable errors and their fixes:

| Validator error | Fix |
|---|---|
| `severity='Critical' not in [...]` | Upper-case all enum values before serializing |
| `finding_count=5 but len(findings)=4` | Recompute `finding_count = len(findings)` — never hardcode |
| `findings[N] missing keys: ['code_snippet']` | Add `"code_snippet": None` for findings without code |
| `cwe='89' must be 'CWE-<number>'` | Prefix with `"CWE-"` |
| `parsing_notes present but source_type is not 'freeform'` | Remove `parsing_notes` from envelope, or fix `source_type` |
| `runs[0].results[N].message.text required` | Wrap message in `{"text": ...}` — SARIF messages are objects |
| `startLine must be int >= 1` | Convert 0-indexed lines to 1-indexed; coerce strings to int |
| `jq: parse error` | File was hand-written. Rewrite using `json.dump`. |
