from __future__ import annotations

import re
from typing import List, Dict, Optional, Tuple
from .models import DetectorFinding

# Use ONLY synthetic data in tests/demos.

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

KEYWORDS_PII = {"ssn", "social security", "dob", "date of birth", "patient", "mrn", "driver", "passport"}
KEYWORDS_CONF = {"confidential", "internal use only", "proprietary", "do not distribute", "nda"}

def luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

def keyword_hits(text_lower: str, keywords: set[str]) -> int:
    return sum(1 for kw in keywords if kw in text_lower)

def detect(text: str) -> List[DetectorFinding]:
    t = text or ""
    tl = t.lower()
    findings: List[DetectorFinding] = []

    ssns = SSN_RE.findall(t)
    if ssns:
        findings.append(DetectorFinding(name="SSN_PATTERN", count=len(ssns)))

    cc_candidates = CC_CANDIDATE_RE.findall(t)
    cc_valid = sum(1 for cand in cc_candidates if luhn_check(cand))
    if cc_valid:
        findings.append(DetectorFinding(name="CC_LUHN_VALID", count=cc_valid))

    emails = EMAIL_RE.findall(t)
    if emails:
        findings.append(DetectorFinding(name="EMAIL_PATTERN", count=len(emails)))

    pii_kw = keyword_hits(tl, KEYWORDS_PII)
    if pii_kw:
        findings.append(DetectorFinding(name="PII_KEYWORDS", count=pii_kw))

    conf_kw = keyword_hits(tl, KEYWORDS_CONF)
    if conf_kw:
        findings.append(DetectorFinding(name="CONF_KEYWORDS", count=conf_kw))

    return findings

def summarize_findings(findings: List[DetectorFinding]) -> Dict[str, int]:
    return {f.name: f.count for f in findings}


# -------------------------------------------------------------------
# ✅ NEW: Primary match + redacted excerpt (for dashboard/export)
# -------------------------------------------------------------------

def _redact_excerpt(s: str) -> str:
    # Mask SSNs
    s = re.sub(r"\b(\d{3})-(\d{2})-(\d{4})\b", r"\1-XX-XXXX", s)
    # Mask emails
    s = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<redacted_email>", s)
    # Mask long digit strings (possible CC) but keep last 4
    def _mask_cc(m):
        raw = m.group(0)
        digits = "".join([c for c in raw if c.isdigit()])
        if len(digits) < 13:
            return raw
        return "XXXX-XXXX-XXXX-" + digits[-4:]
    s = re.sub(CC_CANDIDATE_RE, _mask_cc, s)
    return s

def primary_match(text: str, window: int = 90) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (match_type, redacted_excerpt). Prioritizes high-confidence patterns.
    """
    t = text or ""

    # Priority order: SSN -> Email -> CC candidates (validity checked) -> keywords
    m = SSN_RE.search(t)
    if m:
        start = max(0, m.start() - window)
        end = min(len(t), m.end() + window)
        return "SSN_PATTERN", _redact_excerpt(t[start:end].replace("\n", " "))

    m = EMAIL_RE.search(t)
    if m:
        start = max(0, m.start() - window)
        end = min(len(t), m.end() + window)
        return "EMAIL_PATTERN", _redact_excerpt(t[start:end].replace("\n", " "))

    # CC: find first LUHN-valid candidate and excerpt around it
    for cand in CC_CANDIDATE_RE.finditer(t):
        if luhn_check(cand.group(0)):
            start = max(0, cand.start() - window)
            end = min(len(t), cand.end() + window)
            return "CC_LUHN_VALID", _redact_excerpt(t[start:end].replace("\n", " "))

    tl = t.lower()
    if any(kw in tl for kw in KEYWORDS_PII):
        # excerpt around the first keyword hit
        for kw in KEYWORDS_PII:
            idx = tl.find(kw)
            if idx != -1:
                start = max(0, idx - window)
                end = min(len(t), idx + len(kw) + window)
                return "PII_KEYWORDS", _redact_excerpt(t[start:end].replace("\n", " "))

    if any(kw in tl for kw in KEYWORDS_CONF):
        for kw in KEYWORDS_CONF:
            idx = tl.find(kw)
            if idx != -1:
                start = max(0, idx - window)
                end = min(len(t), idx + len(kw) + window)
                return "CONF_KEYWORDS", _redact_excerpt(t[start:end].replace("\n", " "))

    return None, None
