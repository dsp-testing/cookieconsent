---
name: findings-deduplicator
description: 'Merges and deduplicates security findings from multiple normalized.json files (produced by findings-serializer) into a single unified finding set. Supports three configurable deduplication strategies: strict (file + line proximity + category), moderate (file + category), and fuzzy (category + description similarity). Outputs deduplicated.json and deduplicated.sarif in the same format as findings-serializer with added dedup metadata. Use this skill when asked to "deduplicate findings", "merge security results", "combine findings from multiple tools", "remove duplicate findings", or "unify security scan results".'
---

# Findings Deduplicator

A transformer skill that merges multiple `normalized.json` files — each produced by the
`findings-serializer` skill from a different tool — into a **single deduplicated finding
set**. Use it after serializing results from two or more scanners (e.g. CodeQL +
security-review) to eliminate duplicates and get one authoritative list.

## When to Use This Skill

Use this skill when the request involves:

- Deduplicating or merging security findings from multiple sources
- Combining `normalized.json` files from different tools into one set
- Removing duplicate findings across CodeQL, Semgrep, security-review, etc.
- Unifying security scan results into a single report
- Any phrasing like "deduplicate findings", "merge security results", "combine findings
  from multiple tools", "remove duplicate findings", "unify security scan results",
  or `/findings-deduplicator`

## Inputs Supported

| Input | Detection | Notes |
|-------|-----------|-------|
| **Explicit file paths** | User provides one or more paths to `normalized.json` files | Validated individually |
| **Auto-discovered files** | `findings-*/normalized.json` and `scan-*/*/normalized.json` in repo root | Skips any `deduplicated.json` files for idempotency |

Each input must pass: `jq -e '.schema_version == "1.0" and has("findings")' <file>`

> **Minimum inputs:** At least **2** valid `normalized.json` files are required. If fewer
> than 2 are found, inform the user and stop — there is nothing to deduplicate.

## Outputs

Written to `dedup-YYYYMMDD-HHMMSS/` in the repository root:

| File | Purpose |
|------|---------|
| `deduplicated.json` | Extended `normalized.json` envelope with dedup metadata — merged findings with `duplicate_sources` annotations on merged entries. Directly consumable by downstream skills. |
| `deduplicated.sarif` | Valid SARIF 2.1.0 built from the merged finding list — uploadable to GitHub Code Scanning. |

Both files are validated before the skill reports success. **The skill MUST NOT report
success if either file fails validation.**

## Deduplication Strategies

Three strategies are supported. The user can specify one explicitly; if not, **moderate**
is the default.

| Strategy | Two findings are "the same" when… |
|----------|-----------------------------------|
| `strict` | Same `file` (non-null) AND same `category` AND `abs(line_a - line_b) <= 5` |
| `moderate` | Same `file` (non-null) AND same `category` |
| `fuzzy` | Same `category` AND description_similarity ≥ 0.7 (Jaccard on whitespace-split tokens) |

> **Important:** Findings with `file: null` are **never** considered duplicates of each
> other — they are too ambiguous to match reliably.

Read `references/dedup-strategies.md` for the full algorithm with worked examples.

## Execution Workflow

Follow these steps **in order** every time:

### Step 1 — Discover Inputs

1. If the user provided **explicit file paths**, use those.
2. Otherwise, **auto-discover**: find all `findings-*/normalized.json` and
   `scan-*/*/normalized.json` files in the repo root.
3. If `deduplicated.json` files are found among the discovered files, **skip them**
   (idempotency — don't re-deduplicate already-deduplicated output).
4. **Validate** each input:
   ```bash
   jq -e '.schema_version == "1.0" and has("findings")' <file>
   ```
   Discard any file that does not pass.
5. If fewer than **2** valid inputs remain, inform the user and **stop** — there is
   nothing to deduplicate.
6. **Load** all findings into memory, tagging each with its source file path so that
   provenance is tracked through every subsequent step.

### Step 2 — Select Deduplication Strategy

1. If the user specified a strategy (`strict`, `moderate`, or `fuzzy`), use it.
2. Otherwise, default to **`moderate`**.
3. Read `references/dedup-strategies.md` for the full algorithm definition and edge cases.

### Step 3 — Build Duplicate Groups

1. **Sort** all findings by `(category, file, line)` — this clusters potential duplicates
   together and makes pairwise comparison efficient.
2. For each pair of findings from **different** sources, test the selected strategy's
   match criteria (see the strategy table above).
3. **Group** matching findings into duplicate clusters using union-find / connected
   components — if A matches B and B matches C, all three are in one group.
4. Findings that don't match anything remain **singletons** (groups of size 1).

### Step 4 — Merge Duplicate Groups

For each group with **more than 1 finding**, produce a single merged finding using these
merge rules:

| Field | Merge rule |
|-------|-----------|
| `id` | New ID: `"M-001"`, `"M-002"`, etc. (M for merged); singletons keep original ID prefixed with source |
| `source` | Concatenate sources alphabetically: `"codeql+security-review"` |
| `category` | Same across group (it's a match criterion) |
| `severity` | Highest: CRITICAL > HIGH > MEDIUM > LOW > INFO |
| `file` | Same across group (for strict/moderate); for fuzzy, pick the most specific (non-null) |
| `line` | From the highest-severity finding in the group |
| `description` | From the finding with the **longest** description |
| `cwe` | First non-null CWE in the group |
| `confidence` | Highest: HIGH > MEDIUM > LOW |
| `code_snippet` | The longest non-null snippet |
| `duplicate_sources` | Array of `{"tool": "...", "original_id": "..."}` for each finding in the group |

**Singletons** (non-duplicated findings) keep all original fields unchanged. They do
**NOT** get a `duplicate_sources` field.

Read `references/merge-schema.md` for the full extended schema.

### Step 5 — Create Output Folder

```bash
TS=$(date -u +%Y%m%d-%H%M%S)
OUTDIR="dedup-${TS}"
mkdir -p "$OUTDIR"
echo "$OUTDIR"
```

Use this `$OUTDIR` for all subsequent writes.

### Step 6 — Write `deduplicated.json`

**⛔ NEVER hand-write JSON as a string.** Code snippets contain quotes, backslashes, and
newlines that will break naive serialization. Always serialize programmatically.

Write a Python script inline that:
1. Defines the merged finding list as Python dicts/lists
2. Wraps it in the extended envelope per `references/merge-schema.md`
3. Calls `json.dump(envelope, f, indent=2, ensure_ascii=False)`

```bash
python3 - "$OUTDIR/deduplicated.json" <<'PY'
import json, sys, datetime

findings = [
    # ... LLM populates each dict here, one per merged/singleton finding ...
]

envelope = {
    "schema_version": "1.0",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "source_type": "merged",
    "source_hint": "deduplicated from N sources",
    "tool_name": "findings-deduplicator",
    "finding_count": len(findings),
    "findings": findings,
    "deduplication": {
        "strategy": "moderate",
        "input_sources": [
            {"file": "findings-security-review-TS/normalized.json", "tool": "security-review", "count": 7},
            {"file": "findings-codeql-TS/normalized.json", "tool": "codeql", "count": 5}
        ],
        "input_total": 12,
        "duplicates_removed": 3,
        "output_total": 9
    }
}

with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(envelope, f, indent=2, ensure_ascii=False)
print(f"wrote {len(findings)} findings → {sys.argv[1]}")
PY
```

### Step 7 — Write `deduplicated.sarif`

Same approach as `findings-serializer` Step 5 — read
`../findings-serializer/references/sarif-emit.md` for the SARIF 2.1.0 template and the
severity→level map. Use the **same** Python `json.dump` discipline. Build:

- One `runs[0].tool.driver.rules[]` entry per **distinct category** in the merged finding
  list
- One `runs[0].results[]` entry per merged/singleton finding
- Map normalized severity → SARIF `level` per the table in `sarif-emit.md`
- Stash `confidence`, `original_severity`, `source`, and `duplicate_sources` (when
  present) in each result's `properties` bag

### Step 8 — Validate Both Files

Read `references/validation.md` and run **all three** checks:

1. **`jq` syntax** — `jq empty <file>` on both files. Exit 0 required.
2. **Normalized schema** — Python script asserting envelope keys (including the
   `deduplication` block), finding count, all 10 required fields per finding, valid enum
   values for `severity` and `confidence`. See `references/merge-schema.md` for the
   extended schema.
3. **SARIF schema** — Python `jsonschema` validation against the cached
   `../findings-serializer/references/sarif-2.1.0-schema.json`. Falls back to structural
   assertions if `jsonschema` is unavailable.

**On any validation failure:**
1. Print the validator's error
2. Delete the broken file
3. Fix the data and regenerate (max 2 retries)
4. If still failing, report failure to the user with the validation error — do NOT
   claim success

### Step 9 — Report

Print a concise summary:

```
✅ Findings deduplicated → dedup-YYYYMMDD-HHMMSS/

  Inputs:
    findings-security-review-TS/normalized.json   7 findings  (security-review)
    findings-codeql-TS/normalized.json             5 findings  (codeql)

  Strategy: moderate (same file + same category)

  Results:
    Input total:       12 findings
    Duplicates found:   3
    Output total:        9 unique findings

  deduplicated.json   9 findings   [validated]
  deduplicated.sarif  9 results    [validated]

  Severity:  CRITICAL <n>  HIGH <n>  MEDIUM <n>  LOW <n>  INFO <n>
```

## Reference Files

| File | Use when | Content |
|------|----------|---------|
| `references/dedup-strategies.md` | Step 2, Step 3 | Full algorithm for each strategy with worked examples |
| `references/merge-schema.md` | Step 4, Step 6 | Extended `normalized.json` schema for merged findings; `deduplication` block spec |
| `references/validation.md` | Step 8 | Validation checks (reuses + extends `findings-serializer`'s checks) |
| `../findings-serializer/references/sarif-emit.md` | Step 7 | SARIF 2.1.0 template; severity→level map |
| `../findings-serializer/references/sarif-2.1.0-schema.json` | Step 8 | Cached SARIF JSON Schema for offline validation |
| `../security-comparison/references/category-mapping.md` | Step 3 | Category normalization reference for consistent matching |
