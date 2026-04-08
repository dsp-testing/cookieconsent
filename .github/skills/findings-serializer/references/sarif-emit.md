# SARIF 2.1.0 Emission

Reference for **Step 5** (writing `findings.sarif`) and the `jq` extraction snippets used
in **Step 3** when the *input* is SARIF.

---

## Severity → SARIF `level` Map

SARIF `level` has only four valid values. Map normalized severity as follows:

| Normalized `severity` | SARIF `level` | Rationale |
|---|---|---|
| `CRITICAL` | `"error"` | SARIF has no level above error — preserve original in `properties.original_severity` |
| `HIGH` | `"error"` | |
| `MEDIUM` | `"warning"` | |
| `LOW` | `"note"` | |
| `INFO` | `"note"` | |

The original five-level severity is **always** preserved in `result.properties.original_severity`
so round-tripping back through this skill is lossless.

---

## Minimal Valid SARIF 2.1.0 Template

Build this structure in Python and serialize with `json.dump`. Every `[...]` placeholder
is filled from the in-memory finding list.

```python
import json, sys

# In-memory finding list from Step 3 (already normalized)
findings = [...]
tool_name = "..."   # from envelope.tool_name
source = "..."      # from envelope.source_type / finding.source

LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# Build rules: one per distinct category
seen_categories = []
rules = []
for f in findings:
    if f["category"] not in seen_categories:
        seen_categories.append(f["category"])
        rule = {
            "id": f["category"].replace(" ", "-").lower(),  # e.g. "sql-injection"
            "name": f["category"],
            "shortDescription": {"text": f["category"]},
        }
        if f["cwe"]:
            rule["properties"] = {"cwe": f["cwe"]}
        rules.append(rule)

# Build results: one per finding
results = []
for f in findings:
    result = {
        "ruleId": f["category"].replace(" ", "-").lower(),
        "level": LEVEL_MAP[f["severity"]],
        "message": {"text": f["description"]},
        "properties": {
            "confidence": f["confidence"],
            "original_severity": f["severity"],
            "source": f["source"],
            "normalized_id": f["id"],
        },
    }
    if f["cwe"]:
        result["properties"]["cwe"] = f["cwe"]
    if f["file"]:
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": f["file"]},
            }
        }
        if f["line"] is not None:
            loc["physicalLocation"]["region"] = {"startLine": f["line"]}
            if f["code_snippet"]:
                loc["physicalLocation"]["region"]["snippet"] = {"text": f["code_snippet"]}
        result["locations"] = [loc]
    results.append(result)

sarif = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/findings-serializer",
                    "rules": rules,
                }
            },
            "results": results,
        }
    ],
}

with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(sarif, f, indent=2, ensure_ascii=False)
print(f"wrote {len(results)} results → {sys.argv[1]}")
```

**SARIF schema gotchas** that will fail validation if violated:
- `version` MUST be the string `"2.1.0"` — not a number
- `runs` MUST be an array (even with one run)
- `tool.driver.name` is required
- Each `result.message` MUST be an object with a `text` key — not a bare string
- `region.startLine` MUST be ≥ 1 (1-indexed)
- `artifactLocation.uri` should NOT have a leading `./`
- `locations` is optional — omit the key entirely if `file` is `null` (don't set `locations: []` or `locations: null`)

---

## SARIF Input Extraction (`jq` snippets for Step 3)

When the **input** is a SARIF file, use these `jq` snippets to pull raw fields, then
apply the mappings from `normalized-schema.md` §B in Python.

### Detect SARIF
```bash
jq -e '.version == "2.1.0" and has("runs")' input.sarif >/dev/null 2>&1 && echo "SARIF"
```

### Tool name
```bash
jq -r '.runs[0].tool.driver.name // "unknown"' input.sarif
```

### All results as flat JSON lines (one per line — easy to consume in Python)
```bash
jq -c '
  .runs[0] as $run
  | $run.tool.driver.rules // [] | map({(.id): .}) | add // {} as $rules
  | $run.results[]
  | {
      ruleId: (.ruleId // "unknown"),
      level: (.level // "none"),
      security_severity: (.properties."security-severity" // null),
      message: .message.text,
      file: (.locations[0].physicalLocation.artifactLocation.uri // null),
      line: (.locations[0].physicalLocation.region.startLine // null),
      snippet: (
        .locations[0].physicalLocation.region.snippet.text
        // .locations[0].physicalLocation.contextRegion.snippet.text
        // null
      ),
      rank: (.rank // null),
      tags: (.properties.tags // ($rules[.ruleId].properties.tags // [])),
      rule_short_desc: ($rules[.ruleId].shortDescription.text // null)
    }
' input.sarif
```

Each output line is a JSON object — read with `json.loads()` in Python, then apply:
- `category` ← look up `ruleId` in `category-mapping.md`, fall back to `rule_short_desc`
- `cwe` ← first `tags[]` matching `^external/cwe/cwe-(\d+)`
- `severity` ← per the priority chain in `normalized-schema.md` §B
- `confidence` ← from `rank` per the thresholds in `normalized-schema.md` §B
