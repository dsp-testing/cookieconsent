---
name: scan-orchestrator
description: 'Meta-skill that orchestrates a full multi-source security scan pipeline. Chains security-review → findings-serializer (LLM findings) and CodeQL SARIF → findings-serializer (SAST findings), then deduplicates all findings into a single normalized set. Captures run metadata (repo, tools, timings, finding counts) in a JSON sidecar. Use this skill when asked to "run a full security scan", "scan with all tools", "orchestrate security analysis", "produce findings from all sources", or "benchmark security tools on this repo". Supports --sources flag for llm-only, codeql-only, or all.'
---

# Scan Orchestrator

A meta-skill that runs a **full multi-source security scan pipeline** in a single
invocation. It chains together the `security-review`, `findings-serializer`, and
`findings-deduplicator` skills — plus optional CodeQL SARIF fetching — to produce a
unified, deduplicated set of findings with rich run metadata.

All outputs land in a single timestamped `scan-YYYYMMDD-HHMMSS/` folder.

## When to Use This Skill

Use this skill when the request involves:

- Running a full security scan across multiple tools
- Scanning a codebase with both LLM-based review and CodeQL/SAST
- Orchestrating a multi-source security analysis pipeline
- Producing findings from all available sources in one shot
- Benchmarking or comparing security tools on a repository
- Any phrasing like "run a full security scan", "scan with all tools",
  "orchestrate security analysis", "produce findings from all sources",
  "benchmark security tools on this repo", or `/scan-orchestrator`

**Supported `--sources` flag:**

| Value | Behavior |
|-------|----------|
| `all` (default) | Run both LLM security-review and CodeQL SARIF fetch |
| `llm-only` | Run only the LLM security-review phase |
| `codeql-only` | Run only the CodeQL SARIF fetch phase |

## Dependencies

This skill depends on the following sub-skills and tools:

| Dependency | Role |
|------------|------|
| `security-review` skill | LLM-based codebase security scanner — produces the Markdown report |
| `findings-serializer` skill | Normalizes each source's output into `normalized.json` + `findings.sarif` |
| `findings-deduplicator` skill | Merges N `normalized.json` files into one deduplicated set |
| `gh` CLI | Fetches CodeQL SARIF from the GitHub Code Scanning analyses endpoint |

## Outputs

Written to `scan-YYYYMMDD-HHMMSS/` in the repository root:

| Path | Purpose |
|------|---------|
| `llm/normalized.json` | Normalized findings from the LLM security-review |
| `llm/findings.sarif` | SARIF 2.1.0 from the LLM security-review |
| `codeql/normalized.json` | Normalized findings from CodeQL SARIF |
| `codeql/findings.sarif` | SARIF 2.1.0 from CodeQL |
| `deduplicated.json` | Merged + deduplicated findings across all sources |
| `deduplicated.sarif` | SARIF 2.1.0 for the deduplicated finding set |
| `run-metadata.json` | Run metadata: repo, branch, commit, timestamps, tools, finding counts |

> **Note:** If a source is skipped (via `--sources` or due to failure), its subfolder
> will not be present. Deduplication is skipped when only one source produced findings.

## Execution Workflow

Follow these steps **in order** every time:

### Step 1 — Resolve Scope and Sources

1. Determine the repository, branch, and commit SHA from the git remote:
   ```bash
   REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
   BRANCH=$(git rev-parse --abbrev-ref HEAD)
   COMMIT=$(git rev-parse HEAD)
   ```
2. Parse the `--sources` flag:
   - `all` (default) — run both LLM and CodeQL phases
   - `llm-only` — skip the CodeQL phase entirely
   - `codeql-only` — skip the LLM phase entirely
3. If `all` or `codeql-only`: verify Code Scanning is available:
   ```bash
   gh api "/repos/${REPO}/code-scanning/alerts" --jq 'length' 2>/dev/null
   ```
   - **If unavailable and `--sources=all`:** log a warning and fall back to `llm-only`:
     ```
     ⚠️  Code Scanning not available for <repo> — falling back to llm-only
     ```
   - **If unavailable and `--sources=codeql-only`:** fail with a clear error:
     ```
     ❌ Code Scanning not available for <repo> — cannot run codeql-only scan
     ```
4. Record the run start timestamp:
   ```bash
   RUN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   ```

### Step 2 — Create Output Folder

```bash
TS=$(date -u +%Y%m%d-%H%M%S)
SCAN_DIR="scan-${TS}"
mkdir -p "$SCAN_DIR"
```

Use this `$SCAN_DIR` for all subsequent writes.

### Step 3 — LLM Security Review Phase (skip if `codeql-only`)

1. Record phase start time:
   ```bash
   LLM_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   ```
2. Invoke the **`security-review`** skill on the codebase.
3. Wait for the Markdown report to be generated.
4. Invoke the **`findings-serializer`** skill on the security-review output.
   - The serializer produces a `findings-security-review-TS/` folder containing
     `normalized.json` and `findings.sarif`.
5. Move/copy outputs into `$SCAN_DIR/llm/`:
   ```bash
   mkdir -p "$SCAN_DIR/llm"
   cp findings-security-review-*/normalized.json "$SCAN_DIR/llm/"
   cp findings-security-review-*/findings.sarif  "$SCAN_DIR/llm/"
   ```
6. Record phase end time and finding count:
   ```bash
   LLM_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   LLM_COUNT=$(jq '.finding_count' "$SCAN_DIR/llm/normalized.json")
   ```

### Step 4 — CodeQL SARIF Phase (skip if `llm-only`)

1. Record phase start time:
   ```bash
   CODEQL_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   ```
2. Fetch CodeQL SARIF from the Code Scanning API:
   ```bash
   REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
   ANALYSIS_ID=$(gh api "/repos/${REPO}/code-scanning/analyses" --jq '.[0].id')
   gh api "/repos/${REPO}/code-scanning/analyses/${ANALYSIS_ID}" \
     -H "Accept: application/sarif+json" > "$SCAN_DIR/codeql-raw.sarif"
   ```
3. Invoke the **`findings-serializer`** skill on the fetched SARIF
   (`$SCAN_DIR/codeql-raw.sarif`).
   - The serializer produces a `findings-codeql-TS/` folder containing
     `normalized.json` and `findings.sarif`.
4. Move/copy outputs into `$SCAN_DIR/codeql/`:
   ```bash
   mkdir -p "$SCAN_DIR/codeql"
   cp findings-codeql-*/normalized.json "$SCAN_DIR/codeql/"
   cp findings-codeql-*/findings.sarif  "$SCAN_DIR/codeql/"
   ```
5. Record phase end time and finding count:
   ```bash
   CODEQL_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   CODEQL_COUNT=$(jq '.finding_count' "$SCAN_DIR/codeql/normalized.json")
   ```
6. **On failure:** record the error in metadata and continue — do **not** abort the run.
   Log a warning and mark the CodeQL phase as failed in `run-metadata.json`:
   ```
   ⚠️  CodeQL phase failed: <error message> — continuing with available results
   ```

### Step 5 — Deduplication Phase

1. Collect all `normalized.json` files from `$SCAN_DIR/llm/` and `$SCAN_DIR/codeql/`:
   ```bash
   NORM_FILES=()
   [ -f "$SCAN_DIR/llm/normalized.json" ]    && NORM_FILES+=("$SCAN_DIR/llm/normalized.json")
   [ -f "$SCAN_DIR/codeql/normalized.json" ]  && NORM_FILES+=("$SCAN_DIR/codeql/normalized.json")
   ```
2. If only **one** source produced findings, skip dedup and copy as-is:
   ```bash
   if [ ${#NORM_FILES[@]} -eq 1 ]; then
     cp "${NORM_FILES[0]}" "$SCAN_DIR/deduplicated.json"
     # Also copy the corresponding SARIF
     SARIF_DIR=$(dirname "${NORM_FILES[0]}")
     cp "$SARIF_DIR/findings.sarif" "$SCAN_DIR/deduplicated.sarif"
   fi
   ```
3. If **two** sources produced findings, invoke the **`findings-deduplicator`** skill:
   - Pass both `normalized.json` files as input
   - Use `moderate` strategy (default): same file + same category = duplicate
   - The deduplicator produces `deduplicated.json` and `deduplicated.sarif`
4. Move/copy deduplicator outputs into `$SCAN_DIR/`:
   ```bash
   cp deduplicated.json  "$SCAN_DIR/"
   cp deduplicated.sarif "$SCAN_DIR/"
   ```

### Step 6 — Write Run Metadata

1. Build the `run-metadata.json` per `references/metadata-schema.md`.
2. Write it to `$SCAN_DIR/run-metadata.json` using Python to ensure valid JSON:
   ```bash
   python3 - "$SCAN_DIR/run-metadata.json" <<'PY'
   import json, sys, datetime

   metadata = {
       "schema_version": "1.0",
       "run_id": "...",              # scan-YYYYMMDD-HHMMSS
       "repository": "...",          # owner/repo
       "branch": "...",
       "commit_sha": "...",
       "started_at": "...",          # ISO 8601
       "completed_at": "...",        # ISO 8601
       "sources_requested": "...",   # all | llm-only | codeql-only
       "sources_executed": [...],    # ["llm", "codeql"] or subset
       "phases": {
           "llm": {
               "status": "...",      # success | skipped | failed
               "started_at": "...",
               "completed_at": "...",
               "finding_count": 0,
               "error": None         # or error message string
           },
           "codeql": {
               "status": "...",
               "started_at": "...",
               "completed_at": "...",
               "finding_count": 0,
               "error": None
           },
           "deduplication": {
               "strategy": "moderate",
               "input_count": 0,
               "duplicates_removed": 0,
               "output_count": 0
           }
       },
       "severity_summary": {
           "CRITICAL": 0,
           "HIGH": 0,
           "MEDIUM": 0,
           "LOW": 0,
           "INFO": 0
       },
       "environment": {
           "gh_version": "...",
           "python_version": "...",
           "os": "..."
       }
   }

   with open(sys.argv[1], "w", encoding="utf-8") as f:
       json.dump(metadata, f, indent=2, ensure_ascii=False)
   print(f"wrote metadata → {sys.argv[1]}")
   PY
   ```
3. Validate the output:
   ```bash
   jq empty "$SCAN_DIR/run-metadata.json"
   ```

### Step 7 — Report

Print a concise summary:

```
✅ Security scan complete → scan-YYYYMMDD-HHMMSS/

  Sources:
    🧠 LLM (security-review):  <n> findings  [serialized]
    📊 CodeQL:                  <n> findings  [serialized]

  Deduplication:
    Strategy: moderate
    Input: <n> total findings
    Duplicates removed: <n>
    Output: <n> unique findings

  Severity:  CRITICAL <n>  HIGH <n>  MEDIUM <n>  LOW <n>  INFO <n>

  Artifacts:
    scan-YYYYMMDD-HHMMSS/
    ├── llm/normalized.json + findings.sarif
    ├── codeql/normalized.json + findings.sarif
    ├── deduplicated.json + deduplicated.sarif
    └── run-metadata.json
```

Adjust the tree to omit any source that was skipped or failed. For example, if
`--sources=llm-only`, omit the `codeql/` line. If dedup was skipped (single source),
note that:

```
  Deduplication:
    Skipped (single source) — copied as-is
```

## Reference Files

| File | Use when | Content |
|------|----------|---------|
| `references/metadata-schema.md` | Step 6 | Full JSON schema for `run-metadata.json` |
| `references/pipeline-steps.md` | Steps 3–5 | Detailed sub-skill invocation instructions, error handling, timeout guidance |
