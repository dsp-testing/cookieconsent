# Security Comparison Report Format

Use this template for all security-comparison skill output. Generated during Step 8.

---

## Report Structure

### Header

```
╔══════════════════════════════════════════════════════════╗
║     🔍 SECURITY COMPARISON REPORT                       ║
║     CodeQL vs. AI Security Review                       ║
╚══════════════════════════════════════════════════════════╝

Repository:          <owner/repo>
Branch:              <branch name>
Report Date:         <today's date>
CodeQL Tool:         <tool name and version from alert metadata>
Security Review:     security-review skill
```

---

### Executive Summary

Always show this first — at-a-glance overview:

```
┌──────────────────────────────────────────────────────────┐
│                 FINDINGS OVERVIEW                        │
├──────────────┬───────────────┬───────────────────────────┤
│              │   CodeQL      │   Security Review         │
├──────────────┼───────────────┼───────────────────────────┤
│ 🔴 CRITICAL  │   <n>         │   <n>                     │
│ 🟠 HIGH      │   <n>         │   <n>                     │
│ 🟡 MEDIUM    │   <n>         │   <n>                     │
│ 🔵 LOW       │   <n>         │   <n>                     │
│ ⚪ INFO      │   <n>         │   <n>                     │
├──────────────┼───────────────┼───────────────────────────┤
│ TOTAL        │   <n>         │   <n>                     │
└──────────────┴───────────────┴───────────────────────────┘
```

### Venn Diagram (Text)

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│   ┌──────────────┐         ┌──────────────┐         │
│   │              │         │              │         │
│   │   CodeQL     │         │   Security   │         │
│   │   Only       ├────┬────┤   Review     │         │
│   │              │Over│    │   Only       │         │
│   │   <n>        │lap │    │   <n>        │         │
│   │   findings   │<n> │    │   findings   │         │
│   │              │    │    │              │         │
│   └──────────────┴────┴────┴──────────────┘         │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

### Overlap Findings

For each overlapping finding, use this card:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔄 OVERLAP — [CATEGORY]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📍 Location: <file>:<line>

CodeQL says:
  Rule: <rule_id>
  Severity: <severity>
  Message: <message>

Security Review says:
  Category: <category>
  Severity: <severity>
  Description: <description>

🔍 Code:
  <show the actual code>

Assessment:
  Match type: EXACT / PARTIAL / RELATED
  True positive? YES / NO / CONTEXT-DEPENDENT
  Which tool gave the better assessment? <explain>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### CodeQL-Only Findings

For each finding only CodeQL caught:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 CODEQL-ONLY — [CATEGORY]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📍 Location: <file>:<line>

CodeQL Alert:
  Rule: <rule_id>
  Severity: <severity>
  Message: <message>

🔍 Code:
  <show the actual code>

True positive? YES / NO / CONTEXT-DEPENDENT

Why the security review missed it:
  <explanation — e.g., scope gap, pattern-level bug, etc.>

Action needed? YES / NO
  <if yes, what should be done>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### Review-Only Findings

For each finding only the security review caught:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🧠 REVIEW-ONLY — [CATEGORY]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📍 Location: <file>:<line>

Security Review Finding:
  Category: <category>
  Severity: <severity>
  Description: <description>

🔍 Code:
  <show the actual code>

True positive? YES / NO / CONTEXT-DEPENDENT

Why CodeQL missed it:
  <explanation — e.g., taint source not tracked, no rule exists, etc.>

Could a custom CodeQL query catch this? YES / NO
  <if yes, brief sketch of the query approach>

Action needed? YES / NO
  <if yes, what should be done>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

### Comparison Summary Table

```
┌─────────┬──────────────────────┬─────────┬─────────────┬──────────────┬──────────┐
│ Finding │ Category             │ File    │ CodeQL      │ Sec. Review  │ True     │
│ #       │                      │         │ Severity    │ Severity     │ Positive │
├─────────┼──────────────────────┼─────────┼─────────────┼──────────────┼──────────┤
│ 1       │ <category>           │ <file>  │ <sev>/MISS  │ <sev>/MISS   │ Y/N/CTX  │
│ 2       │ ...                  │ ...     │ ...         │ ...          │ ...      │
└─────────┴──────────────────────┴─────────┴─────────────┴──────────────┴──────────┘

MISS = Tool did not flag this finding
CTX  = Context-dependent (may or may not be exploitable)
```

---

### Strengths & Blind Spots

```
┌─────────────────┬──────────────────────────┬──────────────────────────┐
│ Dimension       │ CodeQL                   │ Security Review          │
├─────────────────┼──────────────────────────┼──────────────────────────┤
│ Approach        │ <describe>               │ <describe>               │
│ Strengths       │ <describe>               │ <describe>               │
│ Blind spots     │ <describe>               │ <describe>               │
│ False positives │ <count and details>      │ <count and details>      │
│ Coverage        │ <n alerts, n files>      │ <n findings, n files>    │
└─────────────────┴──────────────────────────┴──────────────────────────┘
```

---

### Recommendations

```
⚡ RECOMMENDATIONS
══════════════════

1. IMMEDIATE ACTIONS
   - <list findings to address now, from either tool>

2. COVERAGE IMPROVEMENTS
   - <suggestions for improving CodeQL coverage>
   - <suggestions for improving security review scope>

3. PROCESS RECOMMENDATIONS
   - <how to use both tools together effectively>

💡 NOTE: CodeQL excels at precise pattern matching and taint analysis
   from known sources. AI security review excels at contextual reasoning
   and architectural analysis. Using both provides the best coverage.
```

---

### Footer

```
══════════════════════════════════════════════════════════

📋 SCAN DETAILS
  CodeQL alerts analyzed:          <n>
  Security review findings:        <n>
  Total unique findings:           <n>
  Overlapping findings:            <n>
  True positives confirmed:        <n>
  False positives identified:      <n>

══════════════════════════════════════════════════════════
```
