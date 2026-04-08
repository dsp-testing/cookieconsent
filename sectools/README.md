# sectools

Shell tooling for the security-findings pipeline. Deterministic CLI for
fetching, serializing, deduplicating, and orchestrating security findings —
only delegating to Copilot CLI for LLM-centric tasks like `security-review`.

## Requirements

- **Python 3.8+** (stdlib only — no pip dependencies)
- **[`gh` CLI](https://cli.github.com)** — authenticated with a token that has
  the `security_events` scope (needed only for the `fetch-codeql` and `scan`
  subcommands)

## Quick start

```bash
# Show help
python3 -m sectools --help

# Serialize a SARIF file into normalized findings
python3 -m sectools serialize codeql-results.sarif

# Deduplicate findings from multiple sources
python3 -m sectools dedup findings-codeql/normalized.json findings-llm/normalized.json

# Run the full pipeline (CodeQL only)
python3 -m sectools scan --sources codeql-only

# Run the full pipeline (CodeQL + LLM security review)
python3 -m sectools scan --sources all --llm-report security-review-report.md
```

## Subcommands

### `fetch-codeql`

Fetch the most recent CodeQL analysis as SARIF from the GitHub Code Scanning
API.

```
python3 -m sectools fetch-codeql [--repo OWNER/REPO] [--output DIR] [--analysis-id ID]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--repo` | auto-detected | Repository in `owner/repo` format |
| `--output` | `.` (cwd) | Directory to write `codeql-raw.sarif` |
| `--analysis-id` | latest | Specific CodeQL analysis ID |

**Example:**

```bash
python3 -m sectools fetch-codeql --repo orestbida/cookieconsent --output codeql-raw/
# ✅ CodeQL SARIF fetched → codeql-raw/codeql-raw.sarif (analysis ID: 123456)
```

---

### `serialize`

Parse a SARIF file or security-review Markdown report into a normalized
`normalized.json` + `findings.sarif` pair.

```
python3 -m sectools serialize <input> [--output DIR]
```

| Argument | Description |
|----------|-------------|
| `input` | Path to a SARIF file (`.sarif`, `.json`) or security-review Markdown report |
| `--output` | Output directory (default: `findings-<tool>-<timestamp>/`) |

Input type is auto-detected:
- **SARIF**: contains `"version"` and `"runs"` keys
- **Security-review Markdown**: contains `━━━` delimiters and `📍 Location:` markers

**Example:**

```bash
python3 -m sectools serialize codeql-results.sarif --output findings-codeql/
# ✅ Findings serialized → findings-codeql/
#   normalized.json   12 findings   [validated]
#   findings.sarif    12 results    [validated]
#   Severity:  CRITICAL 1  HIGH 3  MEDIUM 5  LOW 2  INFO 1
#   Source:    sarif (CodeQL)
```

---

### `dedup`

Merge and deduplicate findings from multiple `normalized.json` files into a
single unified set.

```
python3 -m sectools dedup [files...] [--strategy strict|moderate|fuzzy] [--output DIR]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `files` | auto-discovered | Paths to `normalized.json` files |
| `--strategy` | `moderate` | Deduplication strategy (see below) |
| `--output` | `dedup-<timestamp>/` | Output directory |

If no files are provided, the tool auto-discovers `findings-*/normalized.json`
and `scan-*/*/normalized.json` in the current directory, skipping any
previously deduplicated outputs.

#### Strategies

| Strategy | Match criteria | Best for |
|----------|---------------|----------|
| **strict** | Same file + same category + lines within ±5 | Precise, low false-positive merges |
| **moderate** | Same file + same category | Balanced default |
| **fuzzy** | Same category + description similarity ≥ 0.7 (Jaccard) | Cross-tool findings with different wording |

All strategies require findings to come from **different sources** — findings
from the same tool are never merged with each other.

#### Merge rules

When duplicate findings are merged:

| Field | Rule |
|-------|------|
| `severity` | Highest wins (CRITICAL > HIGH > MEDIUM > LOW > INFO) |
| `confidence` | Highest wins (HIGH > MEDIUM > LOW) |
| `description` | Longest description wins |
| `code_snippet` | Longest non-null snippet wins |
| `file` / `line` | From the highest-severity finding |
| `cwe` | First non-null CWE in severity order |
| `source` | Alphabetical join with `+` (e.g. `codeql+security-review`) |
| `id` | `M-001`, `M-002`, … for merged; `<source>:<original_id>` for singletons |

Merged findings include a `duplicate_sources` array tracking provenance:

```json
{
  "id": "M-001",
  "source": "codeql+security-review",
  "duplicate_sources": [
    { "tool": "codeql", "original_id": "js/xss-0" },
    { "tool": "security-review", "original_id": "SR-1" }
  ]
}
```

**Example:**

```bash
python3 -m sectools dedup findings-codeql/normalized.json findings-llm/normalized.json --strategy moderate
# 📥 Loaded 4 findings from 2 source(s)
# 🔍 Strategy: moderate | Duplicates removed: 1 | Output: 3 findings
# ✅ Deduplication complete → dedup-20260408-223600/
```

---

### `scan`

Full pipeline orchestrator — chains `fetch-codeql` → `serialize` → `dedup`
into a single command, and writes a `run-metadata.json` sidecar.

```
python3 -m sectools scan [--sources all|codeql-only|llm-only] [--llm-report PATH]
                         [--strategy strict|moderate|fuzzy] [--output DIR] [--repo OWNER/REPO]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--sources` | `codeql-only` | Which finding sources to include |
| `--llm-report` | — | Path to security-review Markdown report |
| `--strategy` | `moderate` | Dedup strategy (used when `--sources all`) |
| `--output` | `scan-<timestamp>/` | Output directory |
| `--repo` | auto-detected | Repository in `owner/repo` format |

#### Source modes

| Mode | What happens |
|------|-------------|
| `codeql-only` | Fetch CodeQL SARIF → serialize. Fully automated. |
| `llm-only` | Serialize the provided `--llm-report`. Requires `--llm-report`. |
| `all` | Fetch CodeQL + serialize, serialize LLM report, then dedup both. |

When `--sources all` is used without `--llm-report`, the tool looks for
existing `findings-security-review-*/normalized.json` files in the current
directory.

#### Output structure

```
scan-20260408-223600/
├── codeql-raw/
│   └── codeql-raw.sarif          # Raw SARIF from GitHub API
├── findings-codeql/
│   ├── normalized.json           # Normalized CodeQL findings
│   └── findings.sarif            # Re-emitted SARIF
├── findings-security-review/
│   ├── normalized.json           # Normalized LLM findings
│   └── findings.sarif            # Re-emitted SARIF
├── deduplicated/
│   ├── deduplicated.json         # Merged findings
│   └── deduplicated.sarif        # Merged SARIF
└── run-metadata.json             # Run metadata sidecar
```

#### run-metadata.json

Captures repository context, timing, tool versions, and finding counts:

```json
{
  "schema_version": "1.0",
  "run_id": "20260408-223600",
  "repository": "orestbida/cookieconsent",
  "branch": "master",
  "commit": "fa052b6...",
  "started_at": "2026-04-08T22:35:58+00:00",
  "completed_at": "2026-04-08T22:36:02+00:00",
  "elapsed_seconds": 4.21,
  "sources": "all",
  "dedup_strategy": "moderate",
  "tools": {
    "sectools": "0.1.0",
    "python": "3.11.5"
  },
  "finding_counts": {
    "per_source": {
      "CodeQL": 8,
      "security-review": 5
    },
    "after_dedup": 10
  }
}
```

**Example:**

```bash
# CodeQL only (fully automated)
python3 -m sectools scan

# Full pipeline with LLM report
python3 -m sectools scan --sources all --llm-report report.md --strategy strict
```

## Architecture

```
sectools/
├── __init__.py          Package marker + version
├── __main__.py          python -m sectools entry point
├── cli.py               argparse wiring for all 4 subcommands
├── schemas.py           Constants, enums, category/CWE maps
├── parsers.py           SARIF parser + security-review Markdown parser
├── sarif_emitter.py     Normalized findings → SARIF 2.1.0
├── validator.py         Pure-Python validation (normalized, dedup, SARIF)
├── fetch_codeql.py      fetch-codeql subcommand (gh API)
├── serialize.py         serialize subcommand
├── dedup.py             dedup subcommand (3 strategies + union-find)
└── scan.py              scan subcommand (full pipeline orchestrator)
```

### Module dependency graph

```
cli.py
  ├── fetch_codeql.py
  ├── serialize.py ──→ parsers.py ──→ schemas.py
  │                ──→ sarif_emitter.py ──→ schemas.py
  │                ──→ validator.py ──→ schemas.py
  ├── dedup.py ──→ sarif_emitter.py, validator.py, schemas.py
  └── scan.py ──→ fetch_codeql.py, serialize.py, dedup.py, schemas.py
```

### Design principles

- **Stdlib-only** — no pip dependencies. Uses `json`, `re`, `subprocess`,
  `argparse`, `pathlib`, `datetime`. Runs on any Python 3.8+ installation.
- **`gh` is the only external dependency** — used for GitHub API calls in
  `fetch-codeql`. Everything else is pure Python.
- **Schema parity** — outputs match the format defined by the
  `findings-serializer` and `findings-deduplicator` Copilot skills
  (`normalized.json` + `findings.sarif`).
- **Self-validating** — every output is validated before the command reports
  success. Broken files are deleted rather than left on disk.

### Normalized finding schema

Every finding (in both `normalized.json` and `deduplicated.json`) has this
10-field structure:

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | ✅ | Unique within the file |
| `source` | string | ✅ | e.g. `codeql`, `security-review`, `codeql+security-review` |
| `category` | string | ✅ | Canonical category (e.g. `SQL Injection`, `XSS`) |
| `severity` | string | ✅ | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `file` | string \| null | ✅ | Relative file path |
| `line` | integer \| null | ✅ | Line number |
| `description` | string | ✅ | Human-readable description |
| `cwe` | string \| null | ✅ | e.g. `CWE-79` |
| `confidence` | string | ✅ | `HIGH` / `MEDIUM` / `LOW` |
| `code_snippet` | string \| null | ✅ | Vulnerable code excerpt |

### Category mapping

The `schemas.py` module includes a mapping of 53 CodeQL rule IDs to canonical
categories and 20 categories to CWE IDs. When a CodeQL rule ID is recognized,
the finding is automatically categorized and assigned a CWE. Unmapped rules
fall back to the SARIF rule description.

## Relationship to Copilot skills

This package implements the **deterministic** parts of the security-findings
pipeline as shell-runnable Python. The **LLM-dependent** parts live as Copilot
skills:

| Concern | Implementation |
|---------|---------------|
| Security code review (reasoning) | `security-review` skill (LLM) |
| Fetching CodeQL SARIF | `sectools fetch-codeql` (deterministic) |
| Parsing & normalizing findings | `sectools serialize` (deterministic) |
| Deduplication & merging | `sectools dedup` (deterministic) |
| Pipeline orchestration | `sectools scan` (deterministic) |

The typical workflow:

1. Run `security-review` via Copilot CLI → produces a Markdown report
2. Run `python3 -m sectools scan --sources all --llm-report report.md`
   → fetches CodeQL, serializes both, deduplicates, writes metadata
