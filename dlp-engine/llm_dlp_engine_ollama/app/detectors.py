from __future__ import annotations

import re
from typing import List, Dict
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
