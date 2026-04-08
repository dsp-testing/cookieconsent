# Pipeline Steps — Detailed Reference

The orchestrator runs up to **4 phases** in sequence. Each phase is self-contained — a
failure in one phase does **not** abort the run. The orchestrator records every phase
outcome (success, failed, skipped) in `run-metadata.json` and continues to the next phase.

| Phase | Name | Depends on | Can be skipped? |
|-------|------|------------|-----------------|
| 1 | LLM Security Review | — | No (core phase) |
| 2 | CodeQL SARIF Fetch & Serialization | `gh` auth + Code Scanning enabled | Yes (if unavailable) |
| 3 | Deduplication | ≥ 1 source from Phases 1–2 | Yes (if only 1 source) |
| 4 | Metadata & Reporting | — | No (always runs) |

---

## Phase 1 — LLM Security Review

### Goal

Perform a full security review of the codebase, then serialize the findings into the
normalized comparison format.

### Steps

1. **Record `phase_start`** — capture the current UTC timestamp before any work begins.

2. **Perform the `security-review` skill workflow** — execute all 8 steps defined in
   `.github/skills/security-review/SKILL.md`:
   - Step 1: Scope the codebase (languages, frameworks, entry points)
   - Step 2: Dependency audit
   - Step 3: Secrets scan
   - Step 4: Static analysis — injection flaws
   - Step 5: Static analysis — auth & access control
   - Step 6: Static analysis — crypto & data exposure
   - Step 7: Business logic & architecture review
   - Step 8: Generate the Markdown report

3. **Capture the Markdown report output** — the security-review skill writes a full
   Markdown report to the conversation. This is the input for the next step.

4. **Perform the `findings-serializer` skill workflow** on the Markdown report — execute
   the serialization steps defined in `.github/skills/findings-serializer/SKILL.md`. The
   serializer auto-detects the input as `security-review` modality based on the report
   structure (finding cards delimited by `━━━` lines, `📍 Location:` markers, etc.).

5. **Expected outputs** from the serializer:
   - `findings-security-review-<TS>/normalized.json` — normalized findings JSON
   - `findings-security-review-<TS>/findings.sarif` — SARIF 2.1.0 representation

6. **Move outputs to scan directory:**
   ```bash
   mkdir -p "$SCAN_DIR/llm"
   mv findings-security-review-*/normalized.json "$SCAN_DIR/llm/normalized.json"
   mv findings-security-review-*/findings.sarif  "$SCAN_DIR/llm/findings.sarif"
   rmdir findings-security-review-*/
   ```

7. **Record `phase_end`** — capture the current UTC timestamp after serialization completes.

### Error Handling

| Scenario | Action |
|----------|--------|
| Security review produces zero findings | Still serialize — the serializer emits a valid `normalized.json` with an empty `findings` array and `finding_count: 0` |
| Security review fails mid-run | Record phase as `failed` in metadata, set `error` to the failure description, continue to Phase 2 |
| Serialization fails on first attempt | Retry up to 3 times (see `validation.md` retry logic). Fix validation errors between attempts |
| Serialization fails after all retries | Record phase as `failed` in metadata, set `error` to the last validator message, continue to Phase 2 |

---

## Phase 2 — CodeQL SARIF Fetch & Serialization

### Goal

Fetch the latest CodeQL SARIF from the GitHub Code Scanning API, then serialize those
findings into the same normalized format used by Phase 1.

### Steps

1. **Record `phase_start`** — capture the current UTC timestamp.

2. **Fetch CodeQL SARIF from the API:**

   ```bash
   REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
   ANALYSIS_ID=$(gh api "/repos/${REPO}/code-scanning/analyses" --jq '.[0].id')
   if [ -n "$ANALYSIS_ID" ]; then
     gh api "/repos/${REPO}/code-scanning/analyses/${ANALYSIS_ID}" \
       -H "Accept: application/sarif+json" > "$SCAN_DIR/codeql-raw.sarif"
   fi
   ```

   The raw SARIF file is kept at `$SCAN_DIR/codeql-raw.sarif` for provenance — it is
   never deleted or overwritten.

3. **Validate the fetch succeeded** — confirm `codeql-raw.sarif` exists and is valid JSON:
   ```bash
   jq empty "$SCAN_DIR/codeql-raw.sarif"
   ```

4. **Perform the `findings-serializer` skill workflow** on `codeql-raw.sarif`. The
   serializer auto-detects the input as `sarif` modality and extracts the `tool_slug`
   from `runs[0].tool.driver.name` (e.g. `"CodeQL"` → `"codeql"`).

5. **Expected outputs** from the serializer:
   - `findings-codeql-<TS>/normalized.json` — normalized findings JSON
   - `findings-codeql-<TS>/findings.sarif` — re-emitted SARIF 2.1.0

6. **Move outputs to scan directory:**
   ```bash
   mkdir -p "$SCAN_DIR/codeql"
   mv findings-codeql-*/normalized.json "$SCAN_DIR/codeql/normalized.json"
   mv findings-codeql-*/findings.sarif  "$SCAN_DIR/codeql/findings.sarif"
   rmdir findings-codeql-*/
   ```

7. **Record `phase_end`** — capture the current UTC timestamp.

### Error Handling

| Scenario | Status | Action |
|----------|--------|--------|
| `gh` not authenticated or not installed | `failed` | Record `error: "gh CLI not authenticated"`, continue to Phase 3 |
| No Code Scanning analyses found (`ANALYSIS_ID` is empty) | `skipped` | Record `error: "No Code Scanning analyses available"`, continue to Phase 3 |
| SARIF fetch returns an API error (403, 404, etc.) | `failed` | Record `error` with the HTTP status and message, continue to Phase 3 |
| `jq empty` fails on the fetched SARIF | `failed` | Record `error: "Fetched SARIF is not valid JSON"`, continue to Phase 3 |
| Serialization fails after retries | `failed` | Record `error` with the last validator message, continue to Phase 3 |

---

## Phase 3 — Deduplication

### Goal

Merge findings from all sources that produced valid `normalized.json` files, removing
duplicates that appear in more than one source.

### Steps

1. **Record `phase_start`** — capture the current UTC timestamp.

2. **Count valid sources** — check which of the following exist and are valid JSON:
   - `$SCAN_DIR/llm/normalized.json`
   - `$SCAN_DIR/codeql/normalized.json`

3. **Branch on source count:**

   | Sources | Action |
   |---------|--------|
   | **0** | Report total failure — no findings were produced by any phase. Record `status: "failed"` with `error: "No sources produced valid normalized.json"`. Skip to Phase 4. |
   | **1** | Skip deduplication — copy the single source's files as the final output: |

   ```bash
   # Single-source shortcut (example for llm-only)
   cp "$SCAN_DIR/llm/normalized.json" "$SCAN_DIR/deduplicated.json"
   cp "$SCAN_DIR/llm/findings.sarif"  "$SCAN_DIR/deduplicated.sarif"
   ```

   | Sources | Action |
   |---------|--------|
   | **2+** | Perform the `findings-deduplicator` skill workflow (see below) |

4. **Deduplication (2+ sources):**
   - Default strategy: `moderate` (user can override at invocation time)
   - The deduplicator reads all `normalized.json` files, matches findings by location +
     category + description similarity, and produces a merged output with duplicates removed
   - Each retained finding records which source(s) reported it

5. **Expected outputs:**
   - `$SCAN_DIR/deduplicated.json` — merged normalized findings
   - `$SCAN_DIR/deduplicated.sarif` — merged SARIF representation

6. **Record `phase_end`** — capture the current UTC timestamp.

### Error Handling

| Scenario | Action |
|----------|--------|
| Deduplication fails | Fall back to concatenating all source findings without dedup. Record `error` in metadata. |
| Single source available | Record `strategy: "passthrough"` in dedup metadata — no merge was needed |

---

## Phase 4 — Metadata & Reporting

### Goal

Build the `run-metadata.json` file that describes the entire scan run, then print a
human-readable summary report.

### Steps

1. **Record `phase_start`** — capture the current UTC timestamp.

2. **Build the `run-metadata.json` object** — follow the schema defined in
   `metadata-schema.md`. The object has three top-level sections:

   **Sources** — for each source (`llm`, `codeql`), populate:

   | Field | Description |
   |-------|-------------|
   | `tool` | Tool name (e.g. `"security-review"`, `"codeql"`) |
   | `phase` | Phase number (`1` or `2`) |
   | `status` | `"success"`, `"failed"`, or `"skipped"` |
   | `finding_count` | Number of findings in `normalized.json`, or `0` if phase failed |
   | `phase_start` | UTC ISO-8601 timestamp recorded at phase start |
   | `phase_end` | UTC ISO-8601 timestamp recorded at phase end |
   | `error` | Error message string, or `null` if successful |

   **Deduplication** — populate:

   | Field | Description |
   |-------|-------------|
   | `strategy` | `"moderate"`, `"strict"`, `"lenient"`, or `"passthrough"` |
   | `input_total` | Sum of `finding_count` across all successful sources |
   | `duplicates_removed` | Number of findings identified as duplicates |
   | `output_total` | Number of findings in `deduplicated.json` |

   **Environment** — capture tool versions:

   ```bash
   gh --version | head -1
   python3 --version
   jq --version
   uname -sr
   ```

3. **Write with Python `json.dump`** — never hand-write JSON:
   ```bash
   python3 -c "
   import json
   metadata = { ... }  # the assembled metadata dict
   with open('$SCAN_DIR/run-metadata.json', 'w') as f:
       json.dump(metadata, f, indent=2)
   "
   ```

4. **Validate with `jq empty`:**
   ```bash
   jq empty "$SCAN_DIR/run-metadata.json" && echo "✅ run-metadata.json: valid JSON" \
     || echo "❌ run-metadata.json: INVALID JSON"
   ```

5. **Record `phase_end`** — capture the current UTC timestamp.

6. **Print the summary report** — output a human-readable table to the conversation:

   ```
   ╔══════════════════════════════════════════════════════╗
   ║  SCAN ORCHESTRATOR — RUN SUMMARY                    ║
   ╠══════════════════════════════════════════════════════╣
   ║  Scan folder:   scan-YYYYMMDD-HHMMSS                ║
   ║  Total phases:  4                                    ║
   ╠══════════╦═══════════╦══════════╦════════════════════╣
   ║  Phase   ║  Name     ║  Status  ║  Findings          ║
   ╠══════════╬═══════════╬══════════╬════════════════════╣
   ║  1       ║  LLM      ║  ✅/❌   ║  <n>               ║
   ║  2       ║  CodeQL   ║  ✅/❌/⏭ ║  <n>               ║
   ║  3       ║  Dedup    ║  ✅/❌/⏭ ║  <n> (−<d> dupes)  ║
   ║  4       ║  Metadata ║  ✅      ║  —                 ║
   ╠══════════╩═══════════╩══════════╩════════════════════╣
   ║  Final deduplicated findings:  <n>                   ║
   ╚══════════════════════════════════════════════════════╝
   ```

---

## Cross-Cutting Concerns

### Folder Structure

Every scan run writes to a single timestamped folder:

```
scan-YYYYMMDD-HHMMSS/
├── llm/
│   ├── normalized.json
│   └── findings.sarif
├── codeql/
│   ├── normalized.json
│   └── findings.sarif
├── codeql-raw.sarif          # raw SARIF from API, kept for provenance
├── deduplicated.json
├── deduplicated.sarif
└── run-metadata.json
```

| Path | Written by | Purpose |
|------|------------|---------|
| `llm/normalized.json` | Phase 1 | Normalized LLM security-review findings |
| `llm/findings.sarif` | Phase 1 | SARIF representation of LLM findings |
| `codeql/normalized.json` | Phase 2 | Normalized CodeQL findings |
| `codeql/findings.sarif` | Phase 2 | Re-emitted SARIF of CodeQL findings |
| `codeql-raw.sarif` | Phase 2 | Unmodified SARIF from Code Scanning API |
| `deduplicated.json` | Phase 3 | Merged + deduplicated normalized findings |
| `deduplicated.sarif` | Phase 3 | Merged + deduplicated SARIF |
| `run-metadata.json` | Phase 4 | Full run metadata (see `metadata-schema.md`) |

### Timing

All timestamps use UTC in ISO-8601 format.

| Context | Method |
|---------|--------|
| Python | `datetime.now(timezone.utc).isoformat()` |
| Bash | `date -u +%Y-%m-%dT%H:%M:%S%z` |

Duration is computed as the difference in seconds between `phase_end` and `phase_start`.
Store both the raw timestamps and the computed `duration_seconds` in metadata.

### Idempotency

If `scan-*/` folders already exist from previous runs, the orchestrator **always** creates
a **new** timestamped folder. It never overwrites, modifies, or deletes previous runs.

```bash
SCAN_DIR="scan-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$SCAN_DIR"
```

The timestamp granularity (seconds) prevents collisions under normal usage. If a collision
occurs (e.g. scripted rapid re-runs), append a short suffix:

```bash
if [ -d "$SCAN_DIR" ]; then
  SCAN_DIR="${SCAN_DIR}-$(python3 -c 'import random; print(random.randint(100,999))')"
  mkdir -p "$SCAN_DIR"
fi
```
