"""Emit valid SARIF 2.1.0 JSON from normalized security findings.

Converts a list of normalized finding dicts (as defined in sectools.schemas)
into the SARIF 2.1.0 interchange format.  Pure stdlib; no third-party deps.
"""

import json

from sectools import schemas


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def category_to_rule_id(category):
    """Convert a canonical category name to a SARIF rule ID.

    Example: "SQL Injection" -> "sql-injection"
    """
    return category.replace(" ", "-").lower()


# ---------------------------------------------------------------------------
# Core emitter
# ---------------------------------------------------------------------------


def emit_sarif(findings, tool_name):
    """Convert normalized findings to a SARIF 2.1.0 dict.

    Args:
        findings: List of normalized finding dicts.
        tool_name: Tool name for the SARIF driver (e.g., "CodeQL",
            "findings-deduplicator").

    Returns:
        A dict representing valid SARIF 2.1.0 JSON.
    """
    # -- Build rules (one per distinct category) ----------------------------
    seen_categories = {}  # category -> rule dict
    for f in findings:
        cat = f["category"]
        if cat in seen_categories:
            continue
        rule = {
            "id": category_to_rule_id(cat),
            "name": cat,
            "shortDescription": {"text": cat},
        }
        cwe = f.get("cwe")
        if cwe:
            rule["properties"] = {"cwe": cwe}
        seen_categories[cat] = rule

    rules = list(seen_categories.values())

    # -- Build results (one per finding) ------------------------------------
    results = []
    for f in findings:
        result = {
            "ruleId": category_to_rule_id(f["category"]),
            "level": schemas.SARIF_LEVEL_MAP[f["severity"]],
            "message": {"text": f["description"]},
            "properties": {
                "confidence": f["confidence"],
                "original_severity": f["severity"],
                "source": f["source"],
                "normalized_id": f["id"],
            },
        }

        cwe = f.get("cwe")
        if cwe:
            result["properties"]["cwe"] = cwe

        # Locations — only when file is non-null
        file_path = f.get("file")
        if file_path is not None:
            # Strip leading "./" per SARIF convention
            uri = file_path.lstrip("./") if file_path.startswith("./") else file_path
            physical = {"artifactLocation": {"uri": uri}}

            line = f.get("line")
            snippet = f.get("code_snippet")
            if line is not None and line >= 1:
                region = {"startLine": line}
                if snippet is not None:
                    region["snippet"] = {"text": snippet}
                physical["region"] = region

            result["locations"] = [{"physicalLocation": physical}]

        # Dedup metadata (optional, present in deduplicator output)
        dup_sources = f.get("duplicate_sources")
        if dup_sources is not None:
            result["properties"]["duplicate_sources"] = dup_sources

        results.append(result)

    # -- Assemble SARIF envelope --------------------------------------------
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/sectools",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


# ---------------------------------------------------------------------------
# File writer convenience
# ---------------------------------------------------------------------------


def write_sarif(findings, tool_name, output_path):
    """Build SARIF and write to file.

    Args:
        findings: List of normalized finding dicts.
        tool_name: Tool name for SARIF driver.
        output_path: Path to write the SARIF file.

    Returns:
        Number of results written.
    """
    sarif = emit_sarif(findings, tool_name)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)
    return len(findings)
