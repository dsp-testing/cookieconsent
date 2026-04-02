# CodeQL Rule ID → Vulnerability Category Mapping

Use this reference to normalize CodeQL rule IDs to the same vulnerability categories
used by the security-review skill, enabling direct comparison.

---

## Injection Flaws

| CodeQL Rule ID | Category | Notes |
|----------------|----------|-------|
| `js/sql-injection` | SQL Injection | Taint from HTTP source to SQL query |
| `js/stored-sql-injection` | SQL Injection | Second-order via stored data |
| `py/sql-injection` | SQL Injection | Python variant |
| `java/sql-injection` | SQL Injection | Java variant |
| `go/sql-injection` | SQL Injection | Go variant |
| `rb/sql-injection` | SQL Injection | Ruby variant |
| `js/xss` | XSS | DOM or reflected XSS |
| `js/xss-through-dom` | XSS | DOM-based XSS |
| `js/reflected-xss` | XSS | Reflected XSS |
| `js/stored-xss` | XSS | Stored XSS |
| `py/reflective-xss` | XSS | Python variant |
| `java/xss` | XSS | Java variant |
| `js/code-injection` | Command Injection | eval / Function / code execution |
| `js/command-line-injection` | Command Injection | exec / spawn with tainted input |
| `py/command-line-injection` | Command Injection | Python variant |
| `java/command-line-injection` | Command Injection | Java variant |
| `js/server-side-unvalidated-url-redirection` | SSRF / Open Redirect | URL from user input |
| `js/request-forgery` | SSRF | Server-side request forgery |
| `py/request-forgery` | SSRF | Python variant |
| `js/log-injection` | Log Injection | User input in log messages |
| `js/path-injection` | Path Traversal | User input in file paths |
| `py/path-injection` | Path Traversal | Python variant |

## Sanitization & Encoding

| CodeQL Rule ID | Category | Notes |
|----------------|----------|-------|
| `js/incomplete-sanitization` | Incomplete Sanitization | `.replace()` only replaces first occurrence |
| `js/incomplete-multi-character-sanitization` | Incomplete Sanitization | Regex doesn't fully strip dangerous characters |
| `js/incomplete-url-scheme-check` | Incomplete Sanitization | URL scheme validation bypass |
| `js/incomplete-url-substring-sanitization` | Incomplete Sanitization | URL validation via substring is bypassable |
| `js/double-escaping` | Encoding Issue | Double-encoding may bypass filters |
| `js/bad-tag-filter` | XSS | HTML tag filter is too permissive |

## Authentication & Access Control

| CodeQL Rule ID | Category | Notes |
|----------------|----------|-------|
| `js/missing-rate-limiting` | Missing Rate Limiting | Express route handler without rate limit |
| `js/hardcoded-credentials` | Hardcoded Secrets | Credentials in source code |
| `py/hardcoded-credentials` | Hardcoded Secrets | Python variant |
| `java/hardcoded-credential-api-call` | Hardcoded Secrets | Java variant |
| `js/insecure-randomness` | Weak Cryptography | Math.random() for security |
| `py/insecure-randomness` | Weak Cryptography | Python variant |
| `js/clear-text-logging` | Data Exposure | Sensitive data in logs |
| `js/clear-text-storage` | Data Exposure | Sensitive data stored unencrypted |

## Cryptography

| CodeQL Rule ID | Category | Notes |
|----------------|----------|-------|
| `js/weak-cryptographic-algorithm` | Weak Cryptography | MD5, SHA1, DES usage |
| `py/weak-cryptographic-algorithm` | Weak Cryptography | Python variant |
| `java/weak-cryptographic-algorithm` | Weak Cryptography | Java variant |
| `js/insufficient-key-size` | Weak Cryptography | Key too short for algorithm |
| `js/biased-cryptographic-random` | Weak Cryptography | Biased PRNG output |

## Data Handling

| CodeQL Rule ID | Category | Notes |
|----------------|----------|-------|
| `js/xml-bomb` | XXE | XML entity expansion DoS |
| `js/xxe` | XXE | XML external entity injection |
| `java/xxe` | XXE | Java variant |
| `js/unsafe-deserialization` | Insecure Deserialization | Untrusted data deserialized |
| `js/prototype-polluting-assignment` | Prototype Pollution | JS-specific injection |
| `js/prototype-pollution-utility` | Prototype Pollution | Library-level pollution |
| `js/regex-injection` | ReDoS | User input in regex pattern |
| `js/polynomial-redos` | ReDoS | Regex with polynomial backtracking |

## Configuration & Best Practices

| CodeQL Rule ID | Category | Notes |
|----------------|----------|-------|
| `js/cors-misconfiguration-for-credentials` | CORS Misconfiguration | Reflects origin with credentials |
| `js/missing-token-validation` | CSRF | Missing CSRF token check |
| `js/zipslip` | Path Traversal | Archive extraction traversal |
| `js/unsafe-jquery-plugin` | XSS | jQuery plugin with unsafe defaults |

---

## Mapping Rules

When a CodeQL rule ID is not in this table:

1. Check the rule ID prefix for the language (`js/`, `py/`, `java/`, `go/`, `rb/`, `cpp/`)
2. Check the `rule.description` field for keywords matching these categories
3. Map based on the CWE ID if available in the alert metadata
4. If no match, classify as **"Other"** and note the rule description

## Reverse Mapping — Security Review Categories to CodeQL Rules

| Security Review Category | Likely CodeQL Rules | Coverage Gap? |
|--------------------------|---------------------|---------------|
| DOM XSS via innerHTML | `js/xss`, `js/xss-through-dom` | Often missed when source is config, not HTTP |
| SQL Injection | `js/sql-injection`, `py/sql-injection` | Well covered for HTTP taint sources |
| Command Injection | `js/command-line-injection` | May miss build scripts, CLI tools |
| Hardcoded Secrets | `js/hardcoded-credentials` | Covers passwords; misses API keys in some formats |
| Missing Auth/AuthZ | None (no standard rule) | Not covered by CodeQL |
| Cookie Configuration | None (no standard rule) | Not covered by CodeQL |
| Business Logic Flaws | None (no standard rule) | Not covered by CodeQL |
| Insecure Dependencies | Dependabot (separate tool) | CodeQL doesn't audit deps; Dependabot does |
