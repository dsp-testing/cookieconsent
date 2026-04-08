# Merged Findings Schema

## Overview

The `deduplicated.json` file extends the `findings-serializer` normalized schema (v1.0) with deduplication metadata. Existing consumers of `normalized.json` can ignore the extra fields — all original fields are preserved and valid.

## Envelope

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-04-08T19:05:30+00:00",
  "source_type": "merged",
  "source_hint": "deduplicated from 2 sources",
  "tool_name": "findings-deduplicator",
  "finding_count": 9,
  "findings": [ /* see Merged Finding Object below */ ],
  "deduplication": {
    "strategy": "moderate",
    "input_sources": [
      {
        "file": "scan-20260408-190000/llm/normalized.json",
        "tool": "security-review",
        "count": 7
      },
      {
        "file": "scan-20260408-190000/codeql/normalized.json",
        "tool": "codeql",
        "count": 5
      }
    ],
    "input_total": 12,
    "duplicates_removed": 3,
    "output_total": 9
  }
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | string | ✅ | Always `"1.0"` |
| `generated_at` | string | ✅ | ISO-8601 UTC |
| `source_type` | string | ✅ | Always `"merged"` for deduplicated output |
| `source_hint` | string | ✅ | `"deduplicated from N sources"` |
| `tool_name` | string | ✅ | Always `"findings-deduplicator"` |
| `finding_count` | int | ✅ | Must equal `len(findings)` |
| `findings` | array | ✅ | Array of Merged Finding Objects |
| `deduplication` | object | ✅ | Deduplication metadata (see below) |

> **Note:** `parsing_notes` is NOT present (that's only for freeform input in the serializer).

## Deduplication Object

| Field | Type | Required | Notes |
|---|---|---|---|
| `strategy` | enum | ✅ | `"strict"`, `"moderate"`, or `"fuzzy"` |
| `input_sources` | array | ✅ | One entry per input file |
| `input_sources[].file` | string | ✅ | Path to the input `normalized.json` |
| `input_sources[].tool` | string | ✅ | Tool name from the input's envelope |
| `input_sources[].count` | int | ✅ | Finding count from the input |
| `input_total` | int | ✅ | Sum of all input counts |
| `duplicates_removed` | int | ✅ | `input_total - output_total` |
| `output_total` | int | ✅ | Must equal `finding_count` in envelope |

## Merged Finding Object

The base 10 fields are identical to the findings-serializer schema. One optional field is added for merged (non-singleton) findings:

```json
{
  "id": "M-001",
  "source": "codeql+security-review",
  "category": "SQL Injection",
  "severity": "CRITICAL",
  "file": "src/routes/users.js",
  "line": 47,
  "description": "An attacker can manipulate the id parameter to execute arbitrary SQL via string interpolation in the query builder.",
  "cwe": "CWE-89",
  "confidence": "HIGH",
  "code_snippet": "const query = `SELECT * FROM users WHERE id = ${req.params.id}`;",
  "duplicate_sources": [
    {"tool": "codeql", "original_id": "js/sql-injection-0"},
    {"tool": "security-review", "original_id": "F-003"}
  ]
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | ✅ | Merged: `"M-001"`, `"M-002"`, ... Singleton: `"<source>:<original_id>"` (e.g., `"codeql:js/xss-2"`) |
| `source` | string | ✅ | Merged: sources joined with `+` in alphabetical order (e.g., `"codeql+security-review"`). Singleton: original source unchanged. |
| `category` | string | ✅ | Canonical category (same as input) |
| `severity` | enum | ✅ | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`. For merged: highest across group. |
| `file` | string \| null | ✅ | From highest-severity finding in the group |
| `line` | int \| null | ✅ | From highest-severity finding in the group |
| `description` | string | ✅ | Longest description in the group |
| `cwe` | string \| null | ✅ | First non-null in severity order. Format: `"CWE-<number>"` |
| `confidence` | enum | ✅ | `HIGH` / `MEDIUM` / `LOW`. For merged: highest across group. |
| `code_snippet` | string \| null | ✅ | Longest non-null snippet in the group |
| `duplicate_sources` | array \| absent | ❌ (optional) | Present ONLY on merged findings. Array of `{tool, original_id}` objects. Omit entirely for singletons. |

## Compatibility Notes

- **Forward-compatible with `normalized.json`:** The `security-comparison` skill and any consumer of `normalized.json` can consume `deduplicated.json` — the base 10 finding fields are always present and valid. The `deduplication` envelope key and `duplicate_sources` finding key are additive.
- **`source_type: "merged"`:** This is a new value not in the original enum (`security-review`, `sarif`, `freeform`). Consumers that strictly validate `source_type` should be updated to accept `"merged"`.
- **Empty dedup:** If 0 duplicates are found, the output is effectively a concatenation of inputs. `duplicates_removed` = 0, and no findings have `duplicate_sources`.

## Example: No Duplicates Found

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-04-08T19:05:30+00:00",
  "source_type": "merged",
  "source_hint": "deduplicated from 2 sources",
  "tool_name": "findings-deduplicator",
  "finding_count": 12,
  "findings": [
    {"id": "codeql:js/sql-injection-0", "source": "codeql", "...": ""},
    {"id": "security-review:F-001", "source": "security-review", "...": ""},
    "..."
  ],
  "deduplication": {
    "strategy": "moderate",
    "input_sources": ["..."],
    "input_total": 12,
    "duplicates_removed": 0,
    "output_total": 12
  }
}
```
