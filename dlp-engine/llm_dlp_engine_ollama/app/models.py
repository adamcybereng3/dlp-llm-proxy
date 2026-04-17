from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Dict, List, Literal, Optional

EncryptionVisibility = Literal["decrypted", "metadata_only"]

class DLPEvent(BaseModel):
    channel: str = Field(..., description="e.g., web_upload, form_post")
    destination: str = Field(..., description="domain or URL")
    content_type: str = Field(..., description="txt/pdf/docx/image/unknown")
    extracted_text: str = Field("", description="normalized extracted text (may be empty)")
    metadata: Dict[str, str] = Field(default_factory=dict, description="filename, size, hashes, etc.")
    encryption_visibility: EncryptionVisibility = Field("decrypted")

class DetectorFinding(BaseModel):
    name: str
    count: int = 0
    details: Dict[str, str] = Field(default_factory=dict)

class DLPDecision(BaseModel):
    label: Literal["PII", "CONFIDENTIAL", "BENIGN", "UNKNOWN"] = "UNKNOWN"
    confidence: float = 0.0
    reasons: List[str] = Field(default_factory=list)
    action: Literal["ALLOW", "COACH", "BLOCK", "QUARANTINE"] = "ALLOW"
    risk_score: int = 0
    findings: List[DetectorFinding] = Field(default_factory=list)

    # ✅ NEW: drive dashboard/export from engine truth, not addon parsing
    match_type: Optional[str] = Field(None, description="Primary detector match type (e.g., SSN_PATTERN)")
    match_excerpt: Optional[str] = Field(None, description="Redacted excerpt around first match")
