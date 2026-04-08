"""Constants, enums, and mappings for the sectools CLI package.

This is the foundation module — all other sectools modules import from here.
Defines severity/confidence scales, CodeQL-to-category mappings, CWE inference,
SARIF conversion helpers, and envelope/finding validation keys.

Pure stdlib; no third-party dependencies.
"""

# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}  # lower index = higher severity

# ---------------------------------------------------------------------------
# Confidence constants
# ---------------------------------------------------------------------------
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
CONFIDENCE_ORDER = {c: i for i, c in enumerate(CONFIDENCES)}

# ---------------------------------------------------------------------------
# Source type constants
# ---------------------------------------------------------------------------
SOURCE_TYPES = {"security-review", "sarif", "freeform", "merged"}

# ---------------------------------------------------------------------------
# Dedup strategies
# ---------------------------------------------------------------------------
DEDUP_STRATEGIES = ("strict", "moderate", "fuzzy")

# ---------------------------------------------------------------------------
# SARIF level map (normalized severity -> SARIF level)
# ---------------------------------------------------------------------------
SARIF_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# ---------------------------------------------------------------------------
# CodeQL rule ID -> canonical category map
# ---------------------------------------------------------------------------
CODEQL_CATEGORY_MAP = {
    # Injection Flaws
    "js/sql-injection": "SQL Injection",
    "js/stored-sql-injection": "SQL Injection",
    "py/sql-injection": "SQL Injection",
    "java/sql-injection": "SQL Injection",
    "go/sql-injection": "SQL Injection",
    "rb/sql-injection": "SQL Injection",
    "js/xss": "XSS",
    "js/xss-through-dom": "XSS",
    "js/reflected-xss": "XSS",
    "js/stored-xss": "XSS",
    "py/reflective-xss": "XSS",
    "java/xss": "XSS",
    "js/code-injection": "Command Injection",
    "js/command-line-injection": "Command Injection",
    "py/command-line-injection": "Command Injection",
    "java/command-line-injection": "Command Injection",
    "js/server-side-unvalidated-url-redirection": "SSRF / Open Redirect",
    "js/request-forgery": "SSRF",
    "py/request-forgery": "SSRF",
    "js/log-injection": "Log Injection",
    "js/path-injection": "Path Traversal",
    "py/path-injection": "Path Traversal",
    # Sanitization & Encoding
    "js/incomplete-sanitization": "Incomplete Sanitization",
    "js/incomplete-multi-character-sanitization": "Incomplete Sanitization",
    "js/incomplete-url-scheme-check": "Incomplete Sanitization",
    "js/incomplete-url-substring-sanitization": "Incomplete Sanitization",
    "js/double-escaping": "Encoding Issue",
    "js/bad-tag-filter": "XSS",
    # Authentication & Access Control
    "js/missing-rate-limiting": "Missing Rate Limiting",
    "js/hardcoded-credentials": "Hardcoded Secrets",
    "py/hardcoded-credentials": "Hardcoded Secrets",
    "java/hardcoded-credential-api-call": "Hardcoded Secrets",
    "js/insecure-randomness": "Weak Cryptography",
    "py/insecure-randomness": "Weak Cryptography",
    "js/clear-text-logging": "Data Exposure",
    "js/clear-text-storage": "Data Exposure",
    # Cryptography
    "js/weak-cryptographic-algorithm": "Weak Cryptography",
    "py/weak-cryptographic-algorithm": "Weak Cryptography",
    "java/weak-cryptographic-algorithm": "Weak Cryptography",
    "js/insufficient-key-size": "Weak Cryptography",
    "js/biased-cryptographic-random": "Weak Cryptography",
    # Data Handling
    "js/xml-bomb": "XXE",
    "js/xxe": "XXE",
    "java/xxe": "XXE",
    "js/unsafe-deserialization": "Insecure Deserialization",
    "js/prototype-polluting-assignment": "Prototype Pollution",
    "js/prototype-pollution-utility": "Prototype Pollution",
    "js/regex-injection": "ReDoS",
    "js/polynomial-redos": "ReDoS",
    # Configuration & Best Practices
    "js/cors-misconfiguration-for-credentials": "CORS Misconfiguration",
    "js/missing-token-validation": "CSRF",
    "js/zipslip": "Path Traversal",
    "js/unsafe-jquery-plugin": "XSS",
}

# ---------------------------------------------------------------------------
# CWE inference map (category -> CWE)
# ---------------------------------------------------------------------------
CATEGORY_CWE_MAP = {
    "SQL Injection": "CWE-89",
    "XSS": "CWE-79",
    "Command Injection": "CWE-78",
    "Path Traversal": "CWE-22",
    "Hardcoded Secrets": "CWE-798",
    "Weak Cryptography": "CWE-327",
    "SSRF": "CWE-918",
    "SSRF / Open Redirect": "CWE-918",
    "XXE": "CWE-611",
    "Insecure Deserialization": "CWE-502",
    "Prototype Pollution": "CWE-1321",
    "ReDoS": "CWE-1333",
    "CSRF": "CWE-352",
    "CORS Misconfiguration": "CWE-942",
    "Data Exposure": "CWE-532",
    "Missing Rate Limiting": "CWE-770",
    "Incomplete Sanitization": "CWE-20",
    "Log Injection": "CWE-117",
    "Encoding Issue": "CWE-838",
    "Insecure Dependency": "CWE-1395",
}

# ---------------------------------------------------------------------------
# SARIF security-severity -> normalized severity
# ---------------------------------------------------------------------------


def sarif_security_severity_to_normalized(score):
    """Map SARIF numeric security-severity score (0-10) to normalized severity."""
    if score is None:
        return None
    score = float(score)
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def sarif_level_to_severity(level):
    """Map SARIF level string to normalized severity (fallback when no security-severity)."""
    return {"error": "MEDIUM", "warning": "LOW", "note": "INFO", "none": "INFO"}.get(
        level, "MEDIUM"
    )


def rank_to_confidence(rank):
    """Map SARIF result rank (0-100) to confidence level."""
    if rank is None:
        return "MEDIUM"
    rank = float(rank)
    if rank >= 80:
        return "HIGH"
    if rank >= 40:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Envelope + finding required fields (for validation)
# ---------------------------------------------------------------------------
ENVELOPE_KEYS = {
    "schema_version",
    "generated_at",
    "source_type",
    "source_hint",
    "tool_name",
    "finding_count",
    "findings",
}
FINDING_REQUIRED_KEYS = {
    "id",
    "source",
    "category",
    "severity",
    "file",
    "line",
    "description",
    "cwe",
    "confidence",
    "code_snippet",
}
FINDING_OPTIONAL_KEYS = {"duplicate_sources"}

# ---------------------------------------------------------------------------
# Helpers: severity / confidence comparison
# ---------------------------------------------------------------------------


def higher_severity(a, b):
    """Return the higher severity of two severity strings."""
    return a if SEVERITY_ORDER.get(a, 99) <= SEVERITY_ORDER.get(b, 99) else b


def higher_confidence(a, b):
    """Return the higher confidence of two confidence strings."""
    return a if CONFIDENCE_ORDER.get(a, 99) <= CONFIDENCE_ORDER.get(b, 99) else b
