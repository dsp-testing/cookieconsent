---
name: security-comparison
description: 'Compare GitHub Code Scanning (CodeQL) alerts with AI security review findings to identify coverage gaps, false positives, and unique detections from each approach. Use this skill when asked to "compare CodeQL with security review", "what did CodeQL miss", "what did the security review miss", "compare SAST results", "analyze code scanning coverage", "gap analysis for security tools", or "benchmark security findings". Works with any repository that has GitHub Code Scanning enabled.'
---

# Security Comparison

Compares GitHub Code Scanning (CodeQL) alerts against AI security review findings to produce
a structured gap analysis. Identifies what each approach uniquely catches, where they overlap,
and where false positives occur — helping teams understand the complementary value of
pattern-based SAST and reasoning-based security review.

## When to Use This Skill

Use this skill when the request involves:

- Comparing CodeQL / Code Scanning alerts with security review findings
- Understanding what CodeQL missed or what the security review missed
- Gap analysis between SAST tooling and AI-based review
- Benchmarking security tool coverage
- Evaluating false positive rates between approaches
- Any request like "compare security results", "what did CodeQL miss", or "coverage gaps"

## Prerequisites

- The repository must have **GitHub Code Scanning** enabled (CodeQL or third-party SARIF)
- The `security-review` skill should be available, OR the user provides security review
  findings from a previous run
- The `gh` CLI must be authenticated with access to the repository

## Execution Workflow

Follow these steps **in order** every time:

### Step 1 — Identify Repository and Branch

1. Determine the GitHub owner/repo from git remotes:
   ```bash
   git remote -v
   ```
2. Identify the current branch:
   ```bash
   git branch --show-current
   ```
3. Confirm Code Scanning is enabled by testing the API:
   ```bash
   gh api /repos/{owner}/{repo}/code-scanning/alerts --paginate -q 'length' 2>&1 | cat
   ```
4. If Code Scanning is not enabled or returns an error, inform the user and stop.

### Step 2 — Fetch Code Scanning Alerts

Retrieve all open Code Scanning alerts with full detail:

```bash
gh api /repos/{owner}/{repo}/code-scanning/alerts --paginate -q '.[] | {
  number: .number,
  rule_id: .rule.id,
  rule_description: .rule.description,
  severity: .rule.severity,
  security_severity: (.rule.security_severity_level // "n/a"),
  tool: .tool.name,
  state: .state,
  path: .most_recent_instance.location.path,
  start_line: .most_recent_instance.location.start_line,
  end_line: .most_recent_instance.location.end_line,
  message: .most_recent_instance.message.text
}' 2>&1 | cat
```

For each alert, also read the flagged source code to understand the actual vulnerability:

```bash
# Read the code at each flagged location
view {path} lines {start_line-5} to {end_line+5}
```

Record all alerts in a structured format for comparison.

### Step 3 — Obtain Security Review Findings

Check if a security review has already been performed in this session. If not:

1. Invoke the `security-review` skill to scan the codebase
2. Wait for the scan to complete
3. Record all findings with their severity, file, line, and category

If the user provides findings from a previous run, parse and structure them.

### Step 4 — Normalize Findings

Map both sets of findings to a common schema for comparison:

| Field | Description |
|-------|-------------|
| `id` | Unique identifier (alert number or finding number) |
| `source` | `codeql` or `security-review` |
| `category` | Normalized vulnerability category (see `references/category-mapping.md`) |
| `severity` | Normalized to: CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `file` | File path relative to repo root |
| `line` | Line number(s) |
| `description` | What was found |
| `cwe` | CWE ID if available |

Use `references/category-mapping.md` to normalize CodeQL rule IDs to the same
vulnerability categories used by the security review skill.

### Step 5 — Classify Each Finding

For every finding from both sources, classify it into one of:

1. **Overlap** — Both tools flagged the same (or closely related) issue in the same file/region
2. **CodeQL-only** — Only CodeQL flagged this; the security review missed it
3. **Review-only** — Only the security review flagged this; CodeQL missed it

**Matching criteria for overlap:**
- Same file AND lines within 10 lines of each other AND same vulnerability category
- OR same file AND same vulnerability category (broader match)

For partial overlaps (same file, related but different specific issue), note both the
overlap and the differences.

### Step 6 — Analyze Each Classification

For every finding, determine **why** the other tool missed it (or caught it):

**Common reasons CodeQL misses findings:**
- Taint source is config/developer input, not HTTP request parameters
- Vulnerability requires understanding architectural intent (e.g., innerHTML is intentional)
- Build scripts, CLI tools, or non-web code outside CodeQL's analysis scope
- Business logic flaws requiring contextual reasoning
- Cookie/header configuration audits not covered by SAST rules
- Cross-file data flow too complex for static taint tracking

**Common reasons the security review misses findings:**
- Scope gap — peripheral directories or files not deeply scanned
- Pattern-level bugs (e.g., `.replace()` vs `.replaceAll()`) that require syntactic precision
- Framework-specific rules the review doesn't have patterns for
- Transitive dependency vulnerabilities requiring package graph analysis
- Subtle type coercion or language-specific edge cases

### Step 7 — Assess False Positives

For each finding, evaluate whether it is a **true positive** or **false positive**:

1. Read the actual code at the flagged location
2. Trace the data flow — is the flagged input actually attacker-controllable?
3. Check for upstream sanitization, framework protections, or mitigating context
4. Assign a verdict: **True Positive**, **False Positive**, or **Context-Dependent**

A finding is a false positive if:
- The flagged code is unreachable or dead code
- Upstream sanitization fully neutralizes the risk
- The framework provides automatic protection the tool didn't recognize
- The "dangerous" API is used safely (e.g., `innerHTML` with hardcoded SVG)

### Step 8 — Generate Comparison Report

Output the report using the format defined in `references/report-format.md`.

The report must include:
1. Executive summary with finding counts per tool
2. Venn diagram (text-based) showing overlap
3. Detailed comparison table
4. Analysis of each overlap, CodeQL-only, and review-only finding
5. False positive assessment
6. Strengths and blind spots of each approach
7. Recommendations for the team

### Step 9 — Provide Recommendations

Based on the comparison, recommend:

1. **Which CodeQL-only findings to act on** — are they real bugs or noise?
2. **Which review-only findings to act on** — prioritized by severity
3. **How to improve coverage** — e.g., custom CodeQL queries, broader skill scan scope
4. **Which tool to trust for which category** — practical guidance for the team

## Severity Normalization

Map CodeQL severities to the skill's severity scale:

| CodeQL `security_severity_level` | Normalized Severity |
|----------------------------------|---------------------|
| critical | 🔴 CRITICAL |
| high | 🟠 HIGH |
| medium | 🟡 MEDIUM |
| low | 🔵 LOW |
| n/a (non-security rule) | ⚪ INFO |

| CodeQL `severity` (non-security) | Normalized Severity |
|----------------------------------|---------------------|
| error | 🟡 MEDIUM |
| warning | 🔵 LOW |
| note | ⚪ INFO |

## Output Rules

- **Always** produce the executive summary table first
- **Always** include the code at each flagged location — don't just reference line numbers
- **Be specific** about WHY each tool missed what it missed
- **Distinguish** true positives from false positives with clear reasoning
- **Group findings** by classification (overlap → CodeQL-only → review-only)
- If one tool has zero findings, say so clearly and explain likely reasons

## Reference Files

- `references/category-mapping.md` — Maps CodeQL rule IDs to normalized vulnerability categories
- `references/report-format.md` — Structured output template for comparison reports
