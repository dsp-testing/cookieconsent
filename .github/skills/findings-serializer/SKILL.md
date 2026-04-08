---
name: findings-serializer
description: 'Transformer skill that converts security findings from heterogeneous sources into machine-comparable JSON. Ingests security-review Markdown reports, SARIF files (CodeQL, Semgrep, Snyk, etc.), or free-form LLM security output, and emits two validated artifacts: a normalized JSON file (matching the security-comparison schema) and a valid SARIF 2.1.0 file. Can automatically fetch CodeQL SARIF from the GitHub Code Scanning analyses endpoint when no input file is provided. Use this skill when asked to "serialize findings to JSON", "convert security report to SARIF", "normalize findings", "make findings comparable", "transform security output", "export findings as JSON", or after running security-review when the user wants structured output. Both outputs are written to a timestamped folder and self-validated before the skill reports success.'
---

# Findings Serializer

A transformer skill that takes security findings in **any** of three input shapes and
emits **two** machine-comparable artifacts. Use it as the bridge between human-readable
security reports and tooling that needs structured data (diffing, dashboards, CI gates,
the `security-comparison` skill).

## When to Use This Skill

Use this skill when the request involves:

- Serializing or exporting security findings to JSON
- Converting a `security-review` report to SARIF or structured JSON
- Normalizing SARIF from CodeQL/Semgrep/Snyk into a simpler schema
- Making findings from two different tools comparable
- Extracting structured findings from a free-form LLM security write-up
- Any phrasing like "turn this into JSON", "give me SARIF", "normalize these findings",
  "make this machine-readable", or `/findings-serializer <path-or-paste>`

## Inputs Supported

| Modality | Detection | Parsing approach |
|----------|-----------|------------------|
| **security-review Markdown** | `🔐 SECURITY REVIEW REPORT` banner OR `━━━` finding-card delimiters | LLM extracts each card's fields per `references/normalized-schema.md` §A |
| **SARIF file** | `.sarif`/`.json` file with `"$schema"` containing `sarif` OR `"version":"2.1.0"` + `"runs"` key | `jq` extraction per `references/sarif-emit.md` §SARIF Input Extraction |
| **Free-form LLM text** | Anything not matching the above | Best-effort LLM extraction per `references/normalized-schema.md` §C; defaults applied for missing fields |

> **CodeQL / Code Scanning:** To get CodeQL results into this skill, fetch them as raw
> SARIF via the analyses endpoint (richer data than the alerts API — includes `rank` and
> `snippet`). The skill can also do this automatically — see Step 1.

## Outputs

Written to `findings-<tool>-YYYYMMDD-HHMMSS/` in the repository root (e.g.
`findings-codeql-20260408-174211/`, `findings-security-review-20260408-174211/`):

| File | Purpose |
|------|---------|
| `normalized.json` | Canonical comparison format — extends `security-comparison` Step 4 schema with `confidence` + `code_snippet`. Directly consumable by the `security-comparison` skill. |
| `findings.sarif` | Valid SARIF 2.1.0 — uploadable to GitHub Code Scanning, viewable in any SARIF viewer. |

Both files are validated before the skill reports success. **The skill MUST NOT report
success if either file fails validation.**

## Execution Workflow

Follow these steps **in order** every time:

### Step 1 — Determine Input Modality

1. If the user provided a **file path**, read it and detect:
   - SARIF: `jq -e '.version == "2.1.0" and has("runs")' <file>` exits 0 → **SARIF**
   - Markdown with `🔐 SECURITY REVIEW REPORT` or `━━━` → **security-review**
   - Otherwise → **free-form**
2. If the user **pasted text** in chat, detect by content (same heuristics).
3. If genuinely ambiguous, ask the user which modality to assume.
4. **SARIF auto-fetch fallback** — if the user did not provide any input file or text
   (e.g. they just invoked the skill with no arguments, or asked to "serialize CodeQL
   findings"), attempt to fetch SARIF from the current repository's Code Scanning:
   ```bash
   # Infer owner/repo from git remote
   REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
   # Get the most recent analysis ID
   ANALYSIS_ID=$(gh api "/repos/${REPO}/code-scanning/analyses" --jq '.[0].id')
   if [ -n "$ANALYSIS_ID" ]; then
     gh api "/repos/${REPO}/code-scanning/analyses/${ANALYSIS_ID}" \
       -H "Accept: application/sarif+json" > codeql.sarif
     echo "Fetched SARIF → codeql.sarif (analysis $ANALYSIS_ID)"
   else
     echo "No Code Scanning analyses found for $REPO" >&2
     exit 1
   fi
   ```
   If the fetch succeeds, proceed with `codeql.sarif` as a **SARIF** input.
   If `gh` is not authenticated, no analyses exist, or the repo has no Code Scanning
   enabled, inform the user and stop — do not fall through to free-form.

Record the detected `source_type` (`security-review` / `sarif` / `freeform`) and a
`source_hint` (file path or `"pasted text"`).

Also derive a **`tool_slug`** for the output folder name — this is the same lower-case
slug used for each finding's `source` field (see `references/normalized-schema.md`):

| Modality | `tool_slug` |
|---|---|
| security-review Markdown | `security-review` |
| SARIF auto-fetch (Step 1.4) | `codeql` |
| SARIF file | `jq -r '.runs[0].tool.driver.name // "sarif"' <file>`, lower-cased + slugified (e.g. `CodeQL` → `codeql`, `Semgrep OSS` → `semgrep-oss`) |
| Free-form | `freeform` |

### Step 2 — Create Output Folder

```bash
TOOL_SLUG="..."   # from Step 1 — e.g. codeql, security-review, semgrep, freeform
# Slugify defensively (filesystem-safe): lowercase, non-alnum → '-', squeeze, trim
TOOL_SLUG=$(printf '%s' "$TOOL_SLUG" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-*//; s/-*$//')
[ -z "$TOOL_SLUG" ] && TOOL_SLUG="unknown"

TS=$(date -u +%Y%m%d-%H%M%S)
OUTDIR="findings-${TOOL_SLUG}-${TS}"
mkdir -p "$OUTDIR"
echo "$OUTDIR"
```

Use this `$OUTDIR` for all subsequent writes.

### Step 3 — Parse Input → Finding List

Read `references/normalized-schema.md` for the **exact** field-by-field mapping for the
detected modality. Build an in-memory list where every finding has **all 10 required
fields** populated (using `null` or documented defaults where the source doesn't provide
a value).

**Category normalization:** Use `../security-comparison/references/category-mapping.md`
to map CodeQL rule IDs (and vulnerability-type strings) to canonical category names.
Fall back to `"Other"` only when no mapping applies.

**Severity normalization:** Use the tables in `../security-comparison/SKILL.md`
§Severity Normalization. All severities MUST land on one of:
`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`.

For **free-form** input, also build a `parsing_notes` list describing what could not be
confidently extracted (e.g. `"3 findings had no file location — set to null"`).

### Step 4 — Write `normalized.json`

**⛔ NEVER hand-write JSON as a string.** Code snippets contain quotes, backslashes, and
newlines that will break naive serialization. Always serialize programmatically.

Write a small Python script inline that:
1. Defines the finding list as Python dicts/lists (the LLM populates the literal data)
2. Wraps it in the envelope per `references/normalized-schema.md` §Envelope
3. Calls `json.dump(envelope, f, indent=2, ensure_ascii=False)`

```bash
python3 - "$OUTDIR/normalized.json" <<'PY'
import json, sys, datetime

findings = [
    # ... LLM populates each dict here, one per finding ...
]

envelope = {
    "schema_version": "1.0",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "source_type": "...",      # security-review | sarif | freeform
    "source_hint": "...",
    "tool_name": "...",
    "finding_count": len(findings),
    "findings": findings,
    # "parsing_notes": [...]   # include ONLY for freeform
}

with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(envelope, f, indent=2, ensure_ascii=False)
print(f"wrote {len(findings)} findings → {sys.argv[1]}")
PY
```

### Step 5 — Write `findings.sarif`

Read `references/sarif-emit.md` for the SARIF 2.1.0 template and the severity→level map.
Use the **same** Python `json.dump` discipline. Build:

- One `runs[0].tool.driver.rules[]` entry per **distinct category** in the finding list
- One `runs[0].results[]` entry per finding
- Map normalized severity → SARIF `level` per the table in `sarif-emit.md`
- Stash `confidence`, `original_severity`, `source` in each result's `properties` bag
  (SARIF doesn't have native fields for these)

### Step 6 — Validate Both Files

Read `references/validation.md` and run **all three** checks:

1. **`jq` syntax** — `jq empty <file>` on both files. Exit 0 required.
2. **Normalized schema** — Python script asserting envelope keys, finding count, all 10
   required fields per finding, valid enum values for `severity` and `confidence`.
3. **SARIF schema** — Python `jsonschema` validation against the cached
   `references/sarif-2.1.0-schema.json`. Falls back to structural assertions if
   `jsonschema` is unavailable.

**On any validation failure:**
1. Print the validator's error
2. Delete the broken file
3. Fix the data and regenerate (max 2 retries)
4. If still failing, report failure to the user with the validation error — do NOT
   claim success

### Step 7 — Report

Print a concise summary:

```
✅ Findings serialized → findings-<tool>-YYYYMMDD-HHMMSS/

  normalized.json   <N> findings   [validated]
  findings.sarif    <N> results    [validated]

  Severity:  CRITICAL <n>  HIGH <n>  MEDIUM <n>  LOW <n>  INFO <n>
  Source:    <source_type> (<tool_name>)
```

For free-form input, also print the `parsing_notes` list so the user knows what was
guessed or defaulted.

## Reference Files

| File | Use when | Content |
|------|----------|---------|
| `references/normalized-schema.md` | Step 3, Step 4 | Envelope + finding schema; per-input field mappings (sec-review §A, SARIF §B, freeform §C) |
| `references/sarif-emit.md` | Step 5, Step 3 (SARIF input) | SARIF 2.1.0 template; severity→level map; `jq` extraction snippets for SARIF input parsing |
| `references/validation.md` | Step 6 | Copy-paste-ready `jq` + Python validation scripts; retry logic |
| `references/sarif-2.1.0-schema.json` | Step 6 | Cached SARIF JSON Schema for offline validation |
| `../security-comparison/references/category-mapping.md` | Step 3 | CodeQL rule ID → canonical category; reverse mapping for vulnerability-type strings |
| `../security-comparison/SKILL.md` §Severity Normalization | Step 3 | CodeQL `security_severity_level` and `severity` → CRITICAL/HIGH/MEDIUM/LOW/INFO |
