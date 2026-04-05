from __future__ import annotations

import json
import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict

# Where we store quarantine evidence (JSONL for easy grep/parse)
DEFAULT_QUARANTINE_PATH = os.environ.get("DLP_QUARANTINE_PATH", "data/quarantine_events.jsonl")

# --- Redaction patterns (demo-safe) ---
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# "sk_test_..." / "sk_live_..." style secrets
SK_KEY_RE = re.compile(r"\bsk_(?:test|live)_[A-Za-z0-9]{10,}\b", re.IGNORECASE)
# generic key/value secrets
GENERIC_SECRET_KV_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?"
)
PRIVATE_KEY_BLOCK_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")

def sha256_hex(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()

def redact_text(text: str, max_chars: int = 400) -> str:
    t = (text or "")
    # mask the obvious
    t = SSN_RE.sub("XXX-XX-XXXX", t)
    t = EMAIL_RE.sub("<redacted_email>", t)
    t = SK_KEY_RE.sub("<redacted_sk_key>", t)

    # mask generic secrets: keep key name, mask value
    t = GENERIC_SECRET_KV_RE.sub(lambda m: f"{m.group(1)}=<redacted_secret>", t)

    # mask private keys completely (don’t even excerpt them)
    if PRIVATE_KEY_BLOCK_RE.search(t):
        return "<redacted_private_key_block>"

    # normalize whitespace and truncate
    t = t.replace("\r\n", "\n")
    t = t.strip()
    return t[:max_chars] + ("…" if len(t) > max_chars else "")

def write_quarantine_event(record: Dict[str, Any], path: str = DEFAULT_QUARANTINE_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def build_quarantine_record(event, decision) -> Dict[str, Any]:
    # event: DLPEvent, decision: DLPDecision
    full_text = getattr(event, "extracted_text", "") or ""
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "destination": getattr(event, "destination", ""),
        "content_type": getattr(event, "content_type", ""),
        "channel": getattr(event, "channel", ""),
        "encryption_visibility": getattr(event, "encryption_visibility", ""),
        "label": getattr(decision, "label", ""),
        "action": getattr(decision, "action", ""),
        "risk_score": getattr(decision, "risk_score", 0),
        "confidence": getattr(decision, "confidence", None),
        "decision_source": (decision.reasons[0] if getattr(decision, "reasons", None) else ""),
        "top_reasons": (decision.reasons[:4] if getattr(decision, "reasons", None) else []),
        "payload_sha256": sha256_hex(full_text),
        "redacted_excerpt": redact_text(full_text, max_chars=400),
        "metadata": getattr(event, "metadata", {}) or {},
    }
