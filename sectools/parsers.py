"""Deterministic parsers for converting security findings into normalized dicts.

Provides two parsers:
  - parse_sarif(): SARIF 2.1.0 JSON → normalized findings
  - parse_security_review_md(): security-review Markdown → normalized findings

And a file-type detector:
  - detect_input_type(): classify a file as 'sarif', 'security-review', or 'unknown'

All parsers emit dicts whose keys match sectools.schemas.FINDING_REQUIRED_KEYS.
Pure stdlib; no third-party dependencies.
"""

import json
import re
from typing import Dict, List, Optional, Tuple

from sectools import schemas

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_CWE_TAG_RE = re.compile(r"^external/cwe/cwe-(\d+)$")
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    """Lowercase *name*, replace non-alnum runs with ``-``, strip edges."""
    slug = _SLUG_RE.sub("-", name.lower()).strip("-")
    return slug or "unknown"


def _safe_get(obj, *keys, default=None):
    """Walk nested dicts/lists safely, returning *default* on any miss."""
    cur = obj
    for k in keys:
        try:
            cur = cur[k]
        except (KeyError, IndexError, TypeError):
            return default
    return cur


def _extract_cwe_from_tags(tags: Optional[list]) -> Optional[str]:
    """Return first ``CWE-<n>`` found in a SARIF tags list, or ``None``."""
    if not tags:
        return None
    for tag in tags:
        m = _CWE_TAG_RE.match(str(tag))
        if m:
            return f"CWE-{m.group(1)}"
    return None


# ---------------------------------------------------------------------------
# Parser 1 – SARIF
# ---------------------------------------------------------------------------

def parse_sarif(sarif_data: dict) -> Tuple[List[dict], str, str]:
    """Parse a SARIF 2.1.0 object into normalized finding dicts.

    Returns
    -------
    (findings, tool_name, tool_slug)
    """
    run = _safe_get(sarif_data, "runs", 0, default={})

    # 1. tool name + slug
    tool_name: str = _safe_get(run, "tool", "driver", "name", default="unknown")
    tool_slug: str = _slugify(tool_name)

    # 2. rules lookup
    raw_rules = _safe_get(run, "tool", "driver", "rules", default=[])
    rules: Dict[str, dict] = {}
    for rule in raw_rules:
        rid = rule.get("id")
        if rid:
            rules[rid] = rule

    # 3. iterate results
    findings: List[dict] = []
    results = _safe_get(run, "results", default=[])

    for index, result in enumerate(results):
        rule_id: str = result.get("ruleId", "unknown")
        rule: dict = rules.get(rule_id, {})

        # -- category
        category = schemas.CODEQL_CATEGORY_MAP.get(rule_id)
        if category is None:
            category = _safe_get(rule, "shortDescription", "text")
        if category is None:
            category = "Other"

        # -- severity (priority cascade)
        severity: Optional[str] = None
        sec_sev = _safe_get(result, "properties", "security-severity")
        if sec_sev is not None:
            severity = schemas.sarif_security_severity_to_normalized(sec_sev)

        if severity is None:
            level = result.get("level")
            if level is not None:
                severity = schemas.sarif_level_to_severity(level)

        if severity is None:
            prob_sev = _safe_get(rule, "properties", "problem", "severity")
            if prob_sev is not None:
                severity = {
                    "error": "MEDIUM",
                    "warning": "LOW",
                    "recommendation": "INFO",
                }.get(prob_sev, "MEDIUM")

        if severity is None:
            severity = "MEDIUM"

        # -- location
        loc0 = _safe_get(result, "locations", 0, default={})
        phys = _safe_get(loc0, "physicalLocation", default={})
        raw_uri = _safe_get(phys, "artifactLocation", "uri")
        file_path: Optional[str] = raw_uri.lstrip("./") if raw_uri else None
        line: Optional[int] = _safe_get(phys, "region", "startLine")

        # -- description
        description: str = _safe_get(result, "message", "text", default="")

        # -- CWE
        cwe = _extract_cwe_from_tags(_safe_get(result, "properties", "tags"))
        if cwe is None:
            cwe = _extract_cwe_from_tags(_safe_get(rule, "properties", "tags"))
        if cwe is None:
            cwe = schemas.CATEGORY_CWE_MAP.get(category)

        # -- confidence
        confidence = schemas.rank_to_confidence(result.get("rank"))

        # -- code snippet
        code_snippet = _safe_get(phys, "region", "snippet", "text")
        if code_snippet is None:
            code_snippet = _safe_get(phys, "region", "contextRegion", "snippet", "text")

        findings.append({
            "id": f"{rule_id}-{index}",
            "source": tool_slug,
            "category": category,
            "severity": severity,
            "file": file_path,
            "line": line,
            "description": description,
            "cwe": cwe,
            "confidence": confidence,
            "code_snippet": code_snippet,
        })

    return findings, tool_name, tool_slug


# ---------------------------------------------------------------------------
# Parser 2 – security-review Markdown
# ---------------------------------------------------------------------------

# Regex building blocks
_CARD_SPLIT_RE = re.compile(r"━{3,}")
_SEVERITY_KW_RE = re.compile(
    r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", re.IGNORECASE
)
_SEVERITY_EMOJI = {
    "\U0001f534": "CRITICAL",  # 🔴
    "\U0001f7e0": "HIGH",      # 🟠
    "\U0001f7e1": "MEDIUM",    # 🟡
    "\U0001f535": "LOW",       # 🔵
    "\u26aa": "INFO",          # ⚪
}
_CATEGORY_BRACKET_RE = re.compile(r"\[([^\]]+)\]")
_LOCATION_RE = re.compile(
    r"📍\s*Location:\s*(.+?)(?:,?\s*[Ll]ines?\s*(\d+)|\:(\d+))?\s*$",
    re.MULTILINE,
)
_RISK_RE = re.compile(
    r"⚠️\s{1,3}Risk:\s*(.*?)(?=\n\s*(?:[📍📚🔍✅⚠️🔐]|\Z))",
    re.DOTALL,
)
_CWE_NUM_RE = re.compile(r"CWE[- ]?(\d+)", re.IGNORECASE)
_REFERENCE_RE = re.compile(r"📚\s*Reference:\s*(.+)", re.MULTILINE)
_CONFIDENCE_RE = re.compile(r"Confidence:\s*(HIGH|MEDIUM|LOW)", re.IGNORECASE)
_CODE_BLOCK_RE = re.compile(
    r"🔍\s*Vulnerable Code:\s*\n\s*```[^\n]*\n(.*?)```",
    re.DOTALL,
)
_CODE_BLOCK_NOMARKER_RE = re.compile(
    r"🔍\s*Vulnerable Code:\s*\n((?:[ \t]+\S[^\n]*\n?)+)",
    re.DOTALL,
)

# Dependency / secrets section patterns
_DEP_SECTION_RE = re.compile(
    r"(?:Dependency\s+Audit|Dependencies)[^\n]*\n(.*?)(?=\n#{1,3}\s|\n━{3,}|\Z)",
    re.DOTALL | re.IGNORECASE,
)
_DEP_ITEM_RE = re.compile(
    r"[•\-\*]\s*\*?\*?`?([^`\n*]+)`?\*?\*?.*?(?:severity|risk|CVE|vulnerable)",
    re.IGNORECASE,
)
_SECRETS_SECTION_RE = re.compile(
    r"(?:Secrets?\s+Scan|Hardcoded\s+Secrets?)[^\n]*\n(.*?)(?=\n#{1,3}\s|\n━{3,}|\Z)",
    re.DOTALL | re.IGNORECASE,
)
_SECRETS_ITEM_RE = re.compile(
    r"[•\-\*]\s*\*?\*?`?([^`\n*]+)`?\*?\*?",
)


def _extract_severity_from_block(block: str) -> str:
    """Return severity from the first few lines of a finding card."""
    header = block[:500]
    # Try emoji first
    for emoji, sev in _SEVERITY_EMOJI.items():
        if emoji in header:
            return sev
    m = _SEVERITY_KW_RE.search(header)
    if m:
        return m.group(1).upper()
    return "MEDIUM"


def _extract_category_from_block(block: str) -> str:
    """Return category from a bracketed label in the first lines."""
    header = block[:500]
    m = _CATEGORY_BRACKET_RE.search(header)
    if m:
        return m.group(1).strip()
    return "Other"


def _looks_like_finding(block: str) -> bool:
    """Heuristic: does this block contain enough markers to be a real finding?"""
    indicators = 0
    if _CATEGORY_BRACKET_RE.search(block):
        indicators += 1
    if _SEVERITY_KW_RE.search(block[:500]):
        indicators += 1
    for emoji in ("📍", "⚠️", "🔍", "📚"):
        if emoji in block:
            indicators += 1
    return indicators >= 2


def parse_security_review_md(text: str) -> List[dict]:
    """Parse a security-review Markdown report into normalized finding dicts."""
    findings: List[dict] = []
    seq = 0

    # --- Finding cards ---
    cards = _CARD_SPLIT_RE.split(text)
    for block in cards:
        block = block.strip()
        if not block or not _looks_like_finding(block):
            continue

        category = _extract_category_from_block(block)
        severity = _extract_severity_from_block(block)

        # location
        file_path: Optional[str] = None
        line: Optional[int] = None
        loc_m = _LOCATION_RE.search(block)
        if loc_m:
            raw_path = loc_m.group(1).strip().rstrip(",: ")
            # Remove trailing line-number portion that may cling to path
            raw_path = re.sub(r"[,:\s]+$", "", raw_path)
            file_path = raw_path or None
            line_str = loc_m.group(2) or loc_m.group(3)
            if line_str:
                try:
                    line = int(line_str)
                except ValueError:
                    pass

        # description (risk)
        description = ""
        risk_m = _RISK_RE.search(block)
        if risk_m:
            description = re.sub(r"\s+", " ", risk_m.group(1)).strip()
        if not description:
            # Fallback: first meaningful paragraph
            for para in block.split("\n\n"):
                stripped = para.strip()
                if stripped and not stripped.startswith(("━", "#", "📍", "🔍", "📚")):
                    description = re.sub(r"\s+", " ", stripped).strip()
                    break

        # CWE
        cwe: Optional[str] = None
        ref_m = _REFERENCE_RE.search(block)
        if ref_m:
            cwe_m = _CWE_NUM_RE.search(ref_m.group(1))
            if cwe_m:
                cwe = f"CWE-{cwe_m.group(1)}"
        if cwe is None:
            cwe_m = _CWE_NUM_RE.search(block)
            if cwe_m:
                cwe = f"CWE-{cwe_m.group(1)}"
        if cwe is None:
            cwe = schemas.CATEGORY_CWE_MAP.get(category)

        # confidence
        confidence = "MEDIUM"
        conf_m = _CONFIDENCE_RE.search(block)
        if conf_m:
            confidence = conf_m.group(1).upper()

        # code snippet
        code_snippet: Optional[str] = None
        code_m = _CODE_BLOCK_RE.search(block)
        if code_m:
            code_snippet = code_m.group(1).rstrip("\n")
        else:
            code_m = _CODE_BLOCK_NOMARKER_RE.search(block)
            if code_m:
                code_snippet = code_m.group(1).rstrip("\n")

        seq += 1
        findings.append({
            "id": f"F-{seq:03d}",
            "source": "security-review",
            "category": category,
            "severity": severity,
            "file": file_path,
            "line": line,
            "description": description,
            "cwe": cwe,
            "confidence": confidence,
            "code_snippet": code_snippet,
        })

    # --- Dependency audit section ---
    dep_m = _DEP_SECTION_RE.search(text)
    if dep_m:
        for item_m in _DEP_ITEM_RE.finditer(dep_m.group(1)):
            seq += 1
            dep_name = item_m.group(1).strip()
            findings.append({
                "id": f"F-{seq:03d}",
                "source": "security-review",
                "category": "Insecure Dependency",
                "severity": "MEDIUM",
                "file": "package.json",
                "line": None,
                "description": dep_name,
                "cwe": "CWE-1395",
                "confidence": "HIGH",
                "code_snippet": None,
            })

    # --- Secrets scan section ---
    sec_m = _SECRETS_SECTION_RE.search(text)
    if sec_m:
        for item_m in _SECRETS_ITEM_RE.finditer(sec_m.group(1)):
            seq += 1
            secret_desc = item_m.group(1).strip()
            if not secret_desc or len(secret_desc) < 4:
                seq -= 1
                continue
            findings.append({
                "id": f"F-{seq:03d}",
                "source": "security-review",
                "category": "Hardcoded Secrets",
                "severity": "HIGH",
                "file": None,
                "line": None,
                "description": secret_desc,
                "cwe": "CWE-798",
                "confidence": "HIGH",
                "code_snippet": None,
            })

    return findings


# ---------------------------------------------------------------------------
# File-type detector
# ---------------------------------------------------------------------------

def detect_input_type(file_path: str) -> str:
    """Detect whether *file_path* is SARIF or security-review Markdown.

    Returns
    -------
    ``'sarif'``, ``'security-review'``, or ``'unknown'``
    """
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except (OSError, UnicodeDecodeError):
        return "unknown"

    # Try JSON / SARIF first
    try:
        data = json.loads(content)
        if isinstance(data, dict) and data.get("version") == "2.1.0" and "runs" in data:
            return "sarif"
    except (json.JSONDecodeError, ValueError):
        pass

    # Security-review markers
    if "\U0001f510 SECURITY REVIEW REPORT" in content or "━━━" in content:
        return "security-review"

    return "unknown"
