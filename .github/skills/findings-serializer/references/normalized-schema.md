# Normalized Findings Schema

The canonical comparison format emitted as `normalized.json`. This schema **extends**
the `security-comparison` skill's Step 4 schema with two fields (`confidence`,
`code_snippet`) so the comparison skill can consume it directly while downstream tooling
gets richer context.

---

## Envelope

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-04-08T17:42:11.003912+00:00",
  "source_type": "security-review",
  "source_hint": "pasted text",
  "tool_name": "security-review skill",
  "finding_count": 7,
  "findings": [ /* see Finding Object below */ ],
  "parsing_notes": [ /* freeform input only — omit otherwise */ ]
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | string | ✅ | Always `"1.0"` for this skill version |
| `generated_at` | string | ✅ | ISO-8601 UTC, from `datetime.now(timezone.utc).isoformat()` |
| `source_type` | enum | ✅ | `"security-review"` \| `"sarif"` \| `"freeform"` |
| `source_hint` | string | ✅ | File path, or `"pasted text"`, or short description |
| `tool_name` | string | ✅ | Original tool. SARIF: `runs[0].tool.driver.name`. Sec-review: `"security-review skill"`. Freeform: best guess or `"unknown"` |
| `finding_count` | int | ✅ | MUST equal `len(findings)`. Validator checks this. |
| `findings` | array | ✅ | Array of Finding Objects. May be empty (`[]`). |
| `parsing_notes` | array of strings | freeform only | Each string describes one extraction gap. Omit entirely for sec-review and SARIF inputs. |

---

## Finding Object

All 10 fields are **required** on every finding. Use `null` for genuinely-absent data —
never omit a key.

```json
{
  "id": "F-001",
  "source": "security-review",
  "category": "SQL Injection",
  "severity": "CRITICAL",
  "file": "src/routes/users.js",
  "line": 47,
  "description": "An attacker can manipulate the id parameter to execute arbitrary SQL.",
  "cwe": "CWE-89",
  "confidence": "HIGH",
  "code_snippet": "const query = `SELECT * FROM users WHERE id = ${req.params.id}`;"
}
```

| Field | Type | Allowed values / format |
|---|---|---|
| `id` | string | Stable within a single output. SARIF: `<ruleId>-<index>`. Sec-review: `F-001`, `F-002`, …. Freeform: `F-001`, `F-002`, …. |
| `source` | string | Lower-case tool slug: `"codeql"`, `"semgrep"`, `"snyk"`, `"security-review"`, `"freeform"`, etc. Derived from `tool_name`. |
| `category` | string | Canonical category from `../security-comparison/references/category-mapping.md`. Examples: `"SQL Injection"`, `"XSS"`, `"Command Injection"`, `"Hardcoded Secrets"`, `"Weak Cryptography"`, `"Path Traversal"`, `"SSRF"`, `"Incomplete Sanitization"`, `"Prototype Pollution"`, `"ReDoS"`, `"CSRF"`, `"CORS Misconfiguration"`, `"Data Exposure"`, `"Missing Rate Limiting"`, `"XXE"`, `"Insecure Deserialization"`. Use `"Other"` only when no mapping fits. |
| `severity` | enum | EXACTLY one of: `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"INFO"`. Upper-case. |
| `file` | string \| null | Repo-relative path (no leading `./`). `null` if not locatable (e.g. dependency CVE, architectural finding). |
| `line` | int \| null | Start line number (1-indexed). `null` if `file` is `null` or line is unknown. |
| `description` | string | Plain-English risk explanation. 1–3 sentences. No Markdown formatting. |
| `cwe` | string \| null | Format `"CWE-<number>"` (e.g. `"CWE-89"`). `null` if not derivable. |
| `confidence` | enum | EXACTLY one of: `"HIGH"`, `"MEDIUM"`, `"LOW"`. Upper-case. |
| `code_snippet` | string \| null | The vulnerable code line(s) verbatim. May contain newlines. `null` if not available. |

---

## §A — Mapping: security-review Markdown → Finding Object

The `security-review` skill emits finding cards delimited by `━━━` lines (see
`../security-review/references/report-format.md`). Extract one Finding Object per card.

| Card element | → Finding field | Extraction rule |
|---|---|---|
| Card ordinal (1st, 2nd, …) | `id` | `"F-001"`, `"F-002"`, … zero-padded to 3 digits |
| (constant) | `source` | `"security-review"` |
| `[VULNERABILITY TYPE]` in card header | `category` | Pass through if it matches a canonical category; else map via `category-mapping.md` reverse table; else `"Other"` |
| `[SEVERITY]` in card header (after emoji) | `severity` | Already in `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO` — pass through, upper-case |
| `📍 Location:` line — path before `,` | `file` | Strip `Line N` suffix. Repo-relative. |
| `📍 Location:` line — `Line N` | `line` | Parse integer. If a range, take start. |
| `⚠️  Risk:` block (until next emoji marker) | `description` | Collapse to plain text, single paragraph, strip example-attack lines if very long |
| `📚 Reference:` line — OWASP category | `cwe` | Map OWASP category → CWE: `A03 → CWE-89` (Injection), `A07 → CWE-287` (Auth), etc. If no `📚` line, infer from `category` (e.g. `SQL Injection → CWE-89`, `XSS → CWE-79`). `null` if not derivable. |
| `Confidence:` line | `confidence` | Already `HIGH`/`MEDIUM`/`LOW` — pass through, upper-case |
| `🔍 Vulnerable Code:` block | `code_snippet` | Verbatim code lines, joined with `\n`, leading whitespace preserved |

**Dependency Audit and Secrets Scan sections** are also findings:
- Dependency: `file` = `"package.json"` (or relevant manifest), `line` = `null`, `category` = `"Insecure Dependency"`, `cwe` = `"CWE-1395"`, `code_snippet` = `null`, `confidence` = `"HIGH"`
- Secrets: `category` = `"Hardcoded Secrets"`, `cwe` = `"CWE-798"`, extract file/line from the secrets card, `confidence` = `"HIGH"`

---

## §B — Mapping: SARIF → Finding Object

For each `runs[r].results[i]` in the input SARIF:

| SARIF path | → Finding field | Extraction rule |
|---|---|---|
| `"<ruleId>-<i>"` (i = result index in run) | `id` | Concatenate; if `ruleId` absent use `"result-<i>"` |
| `runs[r].tool.driver.name`, lower-cased + slugified | `source` | `"CodeQL"` → `"codeql"`, `"Semgrep"` → `"semgrep"`, etc. |
| `results[i].ruleId` | `category` | Look up in `../security-comparison/references/category-mapping.md`. If not found, check `runs[r].tool.driver.rules[*].id == ruleId` and use that rule's `shortDescription.text`. Else `"Other"`. |
| See severity sub-table below | `severity` | — |
| `results[i].locations[0].physicalLocation.artifactLocation.uri` | `file` | Strip `file://` prefix and any URI-decode. `null` if no `locations`. |
| `results[i].locations[0].physicalLocation.region.startLine` | `line` | `null` if absent |
| `results[i].message.text` | `description` | Required by SARIF spec — always present |
| First tag in `results[i].properties.tags[]` matching `^external/cwe/cwe-(\d+)` | `cwe` | Format as `"CWE-<n>"`. Also check `runs[r].tool.driver.rules[*].properties.tags[]`. `null` if no match. |
| `results[i].rank` (0.0–100.0) | `confidence` | `>= 80` → `"HIGH"`, `>= 40` → `"MEDIUM"`, else `"LOW"`. If `rank` absent: `"MEDIUM"`. |
| `results[i].locations[0].physicalLocation.region.snippet.text` | `code_snippet` | `null` if absent. Some tools put it in `contextRegion.snippet.text` — check both. |

**SARIF severity sub-table** (matches `../security-comparison/SKILL.md` §Severity Normalization):

| SARIF source | Value | → `severity` |
|---|---|---|
| `properties."security-severity"` (CodeQL numeric) | `>= 9.0` | `CRITICAL` |
| | `>= 7.0` | `HIGH` |
| | `>= 4.0` | `MEDIUM` |
| | `> 0` | `LOW` |
| `level` (if no security-severity) | `"error"` | `MEDIUM` |
| | `"warning"` | `LOW` |
| | `"note"` / `"none"` | `INFO` |
| Rule-level `properties.problem.severity` | `"error"` | `MEDIUM` |
| | `"warning"` | `LOW` |
| | `"recommendation"` | `INFO` |

Check in priority order: result-level `properties."security-severity"` → result `level` →
rule-level `properties.problem.severity` → default `"MEDIUM"`.

---

## §C — Mapping: Free-form LLM Text → Finding Object (Best Effort)

Read the input text and segment it into finding-like blocks. A "finding-like block" is a
paragraph or section that describes a single security issue. Heuristics:

- Numbered lists (`1.`, `2.`, …) often delimit findings
- Headings containing severity keywords (`Critical`, `High`, …) often start findings
- Markdown horizontal rules (`---`) often separate findings

For each block, extract what's available and apply defaults for the rest:

| Heuristic | → Finding field | Default if not found |
|---|---|---|
| Block ordinal | `id` | `"F-001"`, `"F-002"`, … |
| (constant) | `source` | `"freeform"` |
| Vulnerability-type keyword in block (`SQL injection`, `XSS`, `path traversal`, `hardcoded`, `weak crypto`, …) matched against canonical categories | `category` | `"Other"` |
| Severity keyword in block (`critical`, `high`, `medium`, `low`, `info`/`informational`) — case-insensitive | `severity` | `"MEDIUM"` |
| First `path/to/file.ext:NN` or `path/to/file.ext line NN` pattern | `file` + `line` | both `null` |
| Block text with file/line/code stripped, condensed to 1–3 sentences | `description` | (always derivable — use the block itself if nothing else) |
| `CWE-<n>` literal in block, OR derive from `category` (`SQL Injection → CWE-89`, `XSS → CWE-79`, `Command Injection → CWE-78`, `Path Traversal → CWE-22`, `Hardcoded Secrets → CWE-798`, `Weak Cryptography → CWE-327`) | `cwe` | `null` |
| (constant — freeform extraction is inherently uncertain) | `confidence` | `"LOW"` |
| First fenced code block (` ``` `) or 4-space-indented block within the finding | `code_snippet` | `null` |

**Always emit `parsing_notes`** in the envelope for freeform input. One note per
extraction gap, e.g.:
- `"3 of 5 findings had no file location — set to null"`
- `"No severity keywords found in finding F-002 — defaulted to MEDIUM"`
- `"Category 'Other' assigned to F-004 (no matching keyword)"`

