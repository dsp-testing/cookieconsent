# Run Metadata Schema

The canonical sidecar file emitted as `run-metadata.json` inside every scan output folder.
It captures the full provenance of the orchestrator run — which sources were invoked, how
long each took, deduplication stats, and the runtime environment — so downstream consumers
can audit and reproduce results without re-running the scan.

---

## Envelope

```json
{
  "schema_version": "1.0",
  "run_id": "scan-20260408-190000",
  "repository": "owner/repo",
  "branch": "main",
  "commit_sha": "abc123def456...",
  "started_at": "2026-04-08T19:00:00+00:00",
  "completed_at": "2026-04-08T19:05:30+00:00",
  "duration_seconds": 330,
  "sources_requested": "all",
  "sources": [ /* see Source Object below */ ],
  "deduplication": { /* see Deduplication Object below */ },
  "environment": { /* see Environment Object below */ }
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | string | ✅ | Always `"1.0"` for this skill version |
| `run_id` | string | ✅ | Matches the output folder name, format `scan-YYYYMMDD-HHMMSS` |
| `repository` | string | ✅ | `owner/repo` slug from `gh repo view --json nameWithOwner` |
| `branch` | string | ✅ | Git branch at scan time, e.g. `"main"` |
| `commit_sha` | string | ✅ | Full 40-character SHA of HEAD at scan time |
| `started_at` | string | ✅ | ISO-8601 UTC timestamp when the orchestrator began |
| `completed_at` | string | ✅ | ISO-8601 UTC timestamp when the orchestrator finished |
| `duration_seconds` | int | ✅ | Wall-clock seconds from `started_at` to `completed_at` |
| `sources_requested` | enum | ✅ | One of: `"all"`, `"llm-only"`, `"codeql-only"` |
| `sources` | array | ✅ | Array of Source Objects. At least one entry. |
| `deduplication` | object | ✅ | Deduplication Object — always present even if skipped |
| `environment` | object | ✅ | Environment Object — tool versions used during the run |

---

## Source Object

One entry per scan source (LLM, CodeQL, etc.) in the order they were executed.

```json
{
  "tool": "security-review",
  "phase": "llm",
  "skill_invoked": "security-review",
  "serializer_invoked": "findings-serializer",
  "output_dir": "llm",
  "finding_count": 7,
  "status": "success",
  "started_at": "2026-04-08T19:00:01+00:00",
  "completed_at": "2026-04-08T19:03:15+00:00",
  "error": null
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `tool` | string | ✅ | Tool identifier: `"security-review"`, `"codeql"`, etc. |
| `phase` | string | ✅ | Orchestrator phase name: `"llm"`, `"codeql"` |
| `skill_invoked` | string \| null | ✅ | Copilot skill name if a skill was called, e.g. `"security-review"`. `null` for sources that don't invoke a skill (e.g. CodeQL fetched via API). |
| `serializer_invoked` | string \| null | ✅ | `"findings-serializer"` if serialization was performed. `null` if the source failed before serialization. |
| `output_dir` | string | ✅ | Sub-directory inside the run folder containing this source's outputs (e.g. `"llm"`, `"codeql"`) |
| `finding_count` | int | ✅ | Number of findings produced. `0` if the source failed or was skipped. |
| `status` | enum | ✅ | One of: `"success"`, `"failed"`, `"skipped"` |
| `started_at` | string | ✅ | ISO-8601 UTC timestamp when this source phase began |
| `completed_at` | string | ✅ | ISO-8601 UTC timestamp when this source phase ended |
| `error` | string \| null | ✅ | `null` on success. Brief error message if `status` is `"failed"`. |

**CodeQL-specific field:**

| Field | Type | Required | Notes |
|---|---|---|---|
| `codeql_analysis_id` | int | CodeQL only | GitHub Code Scanning analysis ID used to fetch results. Omit entirely for non-CodeQL sources. |

---

## Deduplication Object

Summarizes the cross-source deduplication pass.

```json
{
  "strategy": "moderate",
  "input_total": 12,
  "duplicates_removed": 3,
  "output_total": 9,
  "skipped": false,
  "skip_reason": null
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `strategy` | string | ✅ | Dedup strategy used: `"strict"`, `"moderate"`, or `"lenient"` |
| `input_total` | int | ✅ | Sum of `finding_count` across all successful sources before dedup |
| `duplicates_removed` | int | ✅ | Number of findings removed as duplicates. `0` if skipped. |
| `output_total` | int | ✅ | `input_total - duplicates_removed`. Equals `input_total` if skipped. |
| `skipped` | bool | ✅ | `true` if dedup was not performed |
| `skip_reason` | string \| null | ✅ | `null` if dedup ran. Explanation string if `skipped` is `true`, e.g. `"only 1 source succeeded — nothing to deduplicate"` |

---

## Environment Object

Records the runtime tool versions for reproducibility.

```json
{
  "gh_cli_version": "2.65.0",
  "python_version": "3.12.4",
  "jq_version": "1.7.1",
  "os": "Darwin 24.3.0"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `gh_cli_version` | string | ✅ | Output of `gh --version`, first line, version number only |
| `python_version` | string | ✅ | Output of `python3 --version`, version number only |
| `jq_version` | string | ✅ | Output of `jq --version`, version number only |
| `os` | string | ✅ | `uname -s` + `uname -r`, e.g. `"Darwin 24.3.0"`, `"Linux 6.5.0"` |

---

## Notes

- **Timestamps** — All timestamp fields (`started_at`, `completed_at`) are ISO-8601 with
  UTC offset (`+00:00`). Produce with `datetime.now(timezone.utc).isoformat()` in Python
  or `date -u +%Y-%m-%dT%H:%M:%S+00:00` in Bash.

- **`run_id` and folder name** — `run_id` always matches the output folder name. The
  orchestrator creates the folder as `scan-YYYYMMDD-HHMMSS` and writes that same string
  into `run_id`.

- **`sources_requested`** — Reflects what the user asked for, not what succeeded. One of:
  `"all"` (both LLM + CodeQL), `"llm-only"`, or `"codeql-only"`.

- **Source `status`** — Each source reports exactly one of:
  - `"success"` — source ran and produced findings (including zero findings)
  - `"failed"` — source was attempted but encountered an error
  - `"skipped"` — source was not attempted (e.g. CodeQL not available for this repo)

- **Source failure** — When `status` is `"failed"`, `error` contains a brief human-readable
  message (e.g. `"No CodeQL analyses found for this repository"`). `finding_count` is `0`.
  `serializer_invoked` is `null` if the failure occurred before serialization.

- **Dedup skipped** — If only one source succeeded (or only one was requested), dedup is
  skipped: `skipped` is `true`, `skip_reason` explains why, `duplicates_removed` is `0`,
  and `output_total` equals `input_total`.

- **Forward compatibility** — This schema is forward-compatible. Consumers SHOULD ignore
  unknown keys. Future versions may add new fields to any object without bumping
  `schema_version`.

---

## Validation

Pure-stdlib Python script to validate `run-metadata.json` against this schema. No pip
installs required.

```bash
python3 - "$OUTDIR/run-metadata.json" <<'PY'
import json, sys, re

STATUSES           = {"success", "failed", "skipped"}
SOURCES_REQUESTED  = {"all", "llm-only", "codeql-only"}
DEDUP_STRATEGIES   = {"strict", "moderate", "lenient"}
ISO_8601_RE        = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?[+\-]\d{2}:\d{2}$")
RUN_ID_RE          = re.compile(r"^scan-\d{8}-\d{6}$")

ENVELOPE_KEYS = {"schema_version", "run_id", "repository", "branch", "commit_sha",
                 "started_at", "completed_at", "duration_seconds",
                 "sources_requested", "sources", "deduplication", "environment"}
SOURCE_KEYS   = {"tool", "phase", "skill_invoked", "serializer_invoked",
                 "output_dir", "finding_count", "status", "started_at",
                 "completed_at", "error"}
DEDUP_KEYS    = {"strategy", "input_total", "duplicates_removed", "output_total",
                 "skipped", "skip_reason"}
ENV_KEYS      = {"gh_cli_version", "python_version", "jq_version", "os"}

errors = []
path = sys.argv[1]

with open(path, encoding="utf-8") as f:
    doc = json.load(f)

# --- Envelope ---
missing = ENVELOPE_KEYS - set(doc.keys())
if missing:
    errors.append(f"envelope missing keys: {sorted(missing)}")
if doc.get("schema_version") != "1.0":
    errors.append(f"schema_version must be '1.0', got {doc.get('schema_version')!r}")
if not RUN_ID_RE.match(doc.get("run_id", "")):
    errors.append(f"run_id must match 'scan-YYYYMMDD-HHMMSS', got {doc.get('run_id')!r}")
if doc.get("sources_requested") not in SOURCES_REQUESTED:
    errors.append(f"sources_requested must be one of {sorted(SOURCES_REQUESTED)}, got {doc.get('sources_requested')!r}")
for ts_field in ("started_at", "completed_at"):
    val = doc.get(ts_field, "")
    if not ISO_8601_RE.match(val):
        errors.append(f"{ts_field}={val!r} is not valid ISO-8601 UTC")
if not isinstance(doc.get("duration_seconds"), int) or doc.get("duration_seconds", -1) < 0:
    errors.append(f"duration_seconds must be a non-negative int, got {doc.get('duration_seconds')!r}")

# --- Sources ---
sources = doc.get("sources", [])
if not isinstance(sources, list) or len(sources) == 0:
    errors.append("sources must be a non-empty array")
else:
    for i, src in enumerate(sources):
        prefix = f"sources[{i}]"
        if not isinstance(src, dict):
            errors.append(f"{prefix} is not an object")
            continue
        missing = SOURCE_KEYS - set(src.keys())
        if missing:
            errors.append(f"{prefix} missing keys: {sorted(missing)}")
        if src.get("status") not in STATUSES:
            errors.append(f"{prefix}.status={src.get('status')!r} not in {sorted(STATUSES)}")
        if not isinstance(src.get("finding_count"), int) or src.get("finding_count", -1) < 0:
            errors.append(f"{prefix}.finding_count must be a non-negative int")
        if src.get("status") == "failed" and src.get("error") is None:
            errors.append(f"{prefix}.status is 'failed' but error is null")
        if src.get("status") == "success" and src.get("error") is not None:
            errors.append(f"{prefix}.status is 'success' but error is not null")
        for ts_field in ("started_at", "completed_at"):
            val = src.get(ts_field, "")
            if not ISO_8601_RE.match(val):
                errors.append(f"{prefix}.{ts_field}={val!r} is not valid ISO-8601 UTC")

# --- Deduplication ---
dedup = doc.get("deduplication", {})
if not isinstance(dedup, dict):
    errors.append("deduplication must be an object")
else:
    missing = DEDUP_KEYS - set(dedup.keys())
    if missing:
        errors.append(f"deduplication missing keys: {sorted(missing)}")
    if dedup.get("strategy") not in DEDUP_STRATEGIES:
        errors.append(f"deduplication.strategy={dedup.get('strategy')!r} not in {sorted(DEDUP_STRATEGIES)}")
    if not isinstance(dedup.get("skipped"), bool):
        errors.append(f"deduplication.skipped must be a bool")
    if dedup.get("skipped") is True and dedup.get("skip_reason") is None:
        errors.append("deduplication.skipped is true but skip_reason is null")
    if dedup.get("skipped") is False and dedup.get("skip_reason") is not None:
        errors.append("deduplication.skipped is false but skip_reason is set")
    for int_field in ("input_total", "duplicates_removed", "output_total"):
        val = dedup.get(int_field)
        if not isinstance(val, int) or val < 0:
            errors.append(f"deduplication.{int_field} must be a non-negative int, got {val!r}")
    if (isinstance(dedup.get("input_total"), int) and isinstance(dedup.get("duplicates_removed"), int)
            and isinstance(dedup.get("output_total"), int)):
        expected = dedup["input_total"] - dedup["duplicates_removed"]
        if dedup["output_total"] != expected:
            errors.append(f"deduplication.output_total={dedup['output_total']} but expected {expected} "
                          f"(input_total - duplicates_removed)")

# --- Environment ---
env = doc.get("environment", {})
if not isinstance(env, dict):
    errors.append("environment must be an object")
else:
    missing = ENV_KEYS - set(env.keys())
    if missing:
        errors.append(f"environment missing keys: {sorted(missing)}")
    for key in ENV_KEYS:
        val = env.get(key)
        if val is not None and not isinstance(val, str):
            errors.append(f"environment.{key} must be a string, got {type(val).__name__}")

# --- Result ---
if errors:
    print(f"❌ run-metadata.json: {len(errors)} schema violation(s)")
    for e in errors:
        print(f"   - {e}")
    sys.exit(1)
print(f"✅ run-metadata.json: schema valid ({len(sources)} source(s), "
      f"dedup {'skipped' if dedup.get('skipped') else 'applied'})")
PY
```

---

## Example: Partial Failure

When CodeQL is unavailable (e.g. Code Scanning not enabled), the metadata records the
failure and dedup is automatically skipped.

```json
{
  "schema_version": "1.0",
  "run_id": "scan-20260408-193000",
  "repository": "owner/repo",
  "branch": "main",
  "commit_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
  "started_at": "2026-04-08T19:30:00+00:00",
  "completed_at": "2026-04-08T19:33:45+00:00",
  "duration_seconds": 225,
  "sources_requested": "all",
  "sources": [
    {
      "tool": "security-review",
      "phase": "llm",
      "skill_invoked": "security-review",
      "serializer_invoked": "findings-serializer",
      "output_dir": "llm",
      "finding_count": 4,
      "status": "success",
      "started_at": "2026-04-08T19:30:01+00:00",
      "completed_at": "2026-04-08T19:33:10+00:00",
      "error": null
    },
    {
      "tool": "codeql",
      "phase": "codeql",
      "skill_invoked": null,
      "serializer_invoked": null,
      "output_dir": "codeql",
      "finding_count": 0,
      "status": "failed",
      "started_at": "2026-04-08T19:33:11+00:00",
      "completed_at": "2026-04-08T19:33:44+00:00",
      "error": "No CodeQL analyses found for this repository"
    }
  ],
  "deduplication": {
    "strategy": "moderate",
    "input_total": 4,
    "duplicates_removed": 0,
    "output_total": 4,
    "skipped": true,
    "skip_reason": "only 1 source succeeded — nothing to deduplicate"
  },
  "environment": {
    "gh_cli_version": "2.65.0",
    "python_version": "3.12.4",
    "jq_version": "1.7.1",
    "os": "Darwin 24.3.0"
  }
}
```

Key observations in this example:

- `sources_requested` is `"all"` — the user asked for both sources
- The CodeQL source has `status: "failed"` with a descriptive `error` message
- `serializer_invoked` is `null` for the failed source (never reached serialization)
- `finding_count` is `0` for the failed source
- Deduplication was `skipped` because only one source succeeded
- `output_total` equals `input_total` (no duplicates removed)
