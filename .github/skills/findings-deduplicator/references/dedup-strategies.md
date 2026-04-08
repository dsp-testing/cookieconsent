# Deduplication Strategies

## Overview

Three strategies for deciding when two findings from different sources represent the same vulnerability. The user chooses one at invocation time; default is `moderate`.

All strategies share these **preconditions** before a pair is even tested:
- The two findings must come from DIFFERENT sources (same-source findings are never deduplicated)
- At least one of `file` must be non-null (two null-file findings are never matched)

## Strategy: `strict`

**Criteria:** Same `file` (case-sensitive, exact match, both non-null) AND same `category` (exact match) AND `abs(line_a - line_b) <= 5`

**When to use:** When you want maximum precision — only removes findings that are clearly the same issue at the same code location. Best for when line numbers are reliable (e.g., both sources point at the exact code).

**Algorithm (pseudocode):**
```python
def is_duplicate_strict(a, b):
    if a["source"] == b["source"]:
        return False
    if a["file"] is None or b["file"] is None:
        return False
    if a["file"] != b["file"]:
        return False
    if a["category"] != b["category"]:
        return False
    if a["line"] is None or b["line"] is None:
        return False  # can't compare proximity without lines
    return abs(a["line"] - b["line"]) <= 5
```

**Worked example:**

Finding A (CodeQL): `file: "src/api.js", line: 42, category: "SQL Injection"`
Finding B (security-review): `file: "src/api.js", line: 44, category: "SQL Injection"`
→ `abs(42 - 44) = 2 ≤ 5` → **DUPLICATE** ✅

Finding C (CodeQL): `file: "src/api.js", line: 42, category: "SQL Injection"`
Finding D (security-review): `file: "src/api.js", line: 55, category: "SQL Injection"`
→ `abs(42 - 55) = 13 > 5` → **NOT duplicate** ❌ (these are likely different SQL injection sites)

## Strategy: `moderate` (Default)

**Criteria:** Same `file` (case-sensitive, exact match, both non-null) AND same `category` (exact match)

**When to use:** Good balance of precision and recall. Tools often report slightly different line numbers for the same vulnerability (e.g., CodeQL points at the query execution, the LLM points at where user input enters). This strategy catches those while still requiring file-level specificity.

**Algorithm (pseudocode):**
```python
def is_duplicate_moderate(a, b):
    if a["source"] == b["source"]:
        return False
    if a["file"] is None or b["file"] is None:
        return False
    if a["file"] != b["file"]:
        return False
    return a["category"] == b["category"]
```

**Worked example:**

Finding A (CodeQL): `file: "src/api.js", line: 42, category: "SQL Injection"`
Finding B (security-review): `file: "src/api.js", line: 120, category: "SQL Injection"`
→ Same file + same category → **DUPLICATE** ✅
(Even though lines are far apart — under moderate strategy, they're considered the same issue in the same file)

Finding A (CodeQL): `file: "src/api.js", category: "SQL Injection"`
Finding C (security-review): `file: "src/utils.js", category: "SQL Injection"`
→ Different files → **NOT duplicate** ❌

**⚠️ Caveat:** If a file genuinely has two distinct SQL injection vulnerabilities at different locations, moderate will merge them into one. Use `strict` if this is a concern.

## Strategy: `fuzzy`

**Criteria:** Same `category` (exact match) AND `jaccard_similarity(description_tokens_a, description_tokens_b) >= 0.7`

**When to use:** When findings might reference the same vulnerability but in different files (e.g., a shared utility function called from multiple places, or a cross-file data flow where tools disagree on which file to flag). Also useful for free-form/LLM findings that may not have precise file locations.

**Jaccard similarity calculation:**
```python
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
    if a["source"] == b["source"]:
        return False
    if a["category"] != b["category"]:
        return False
    return jaccard_similarity(a["description"], b["description"]) >= 0.7
```

**Worked example:**

Finding A: `category: "XSS", description: "User input is rendered without escaping in the profile page via innerHTML, allowing script injection."`
Finding B: `category: "XSS", description: "The profile page renders user input via innerHTML without escaping, enabling script injection attacks."`
→ tokens_a = {"user", "input", "is", "rendered", "without", "escaping", "in", "the", "profile", "page", "via", "innerhtml,", "allowing", "script", "injection."}
→ tokens_b = {"the", "profile", "page", "renders", "user", "input", "via", "innerhtml", "without", "escaping,", "enabling", "script", "injection", "attacks."}
→ High overlap → **DUPLICATE** ✅

**⚠️ Caveat:** Fuzzy matching can produce false positives if two genuinely different vulnerabilities in the same category have similar descriptions. Review merged findings carefully.

## Grouping: Union-Find

When more than 2 sources are involved, duplicates form transitive groups. Use union-find (disjoint set) to group:

```python
parent = {}

def find(x):
    while parent.get(x, x) != x:
        parent[x] = parent.get(parent[x], parent[x])
        x = parent[x]
    return x

def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb:
        parent[ra] = rb

# For each pair of findings from different sources:
for i, a in enumerate(all_findings):
    for j, b in enumerate(all_findings):
        if j <= i:
            continue
        if a["source"] == b["source"]:
            continue
        if is_duplicate(a, b):  # using selected strategy
            union(i, j)

# Collect groups
groups = {}
for i in range(len(all_findings)):
    root = find(i)
    groups.setdefault(root, []).append(i)
```

## Merge Rules

When a group has >1 finding, merge into a single finding:

| Field | Rule | Rationale |
|-------|------|-----------|
| `id` | `"M-001"`, `"M-002"`, ... | New IDs for merged findings; sequential across output |
| `source` | Concatenate alphabetically: `"codeql+security-review"` | Shows provenance |
| `category` | Same across group (match criterion) | — |
| `severity` | Highest: CRITICAL > HIGH > MEDIUM > LOW > INFO | Conservative: don't downgrade |
| `file` | From highest-severity finding; if tied, first non-null | Most relevant location |
| `line` | From the highest-severity finding in the group | Consistent with file choice |
| `description` | Longest description in the group | Most context |
| `cwe` | First non-null in severity order | Prefer higher-confidence source |
| `confidence` | Highest: HIGH > MEDIUM > LOW | Two tools agreeing = more confident |
| `code_snippet` | Longest non-null snippet | Most context |
| `duplicate_sources` | `[{"tool": "codeql", "original_id": "js/sql-injection-0"}, {"tool": "security-review", "original_id": "F-003"}]` | Audit trail |

**Singletons** (findings not matched to any duplicate) keep all original fields unchanged. They do NOT get a `duplicate_sources` field. Their `id` is prefixed with their source: `"codeql:js/sql-injection-5"` or `"security-review:F-007"`.
