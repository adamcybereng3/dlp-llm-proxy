from __future__ import annotations

from typing import Optional, List

from .models import DLPEvent, DLPDecision
from .detectors import detect
from .policy import build_decision, risk_score
from .llm_ollama import call_ollama_classify, make_excerpt

# ---- Tuning knobs ----
LLM_SKIP_LOW_SCORE = 15       # below this (with some weak signals), skip LLM
LLM_SKIP_HIGH_SCORE = 60      # above this, skip LLM (already confident sensitive)
LLM_USE_SCORE_MIN = 15        # call LLM in this band...
LLM_USE_SCORE_MAX = 60        # ...up to this band
MAX_LLM_EXCERPT_CHARS = 1800

# Strong deterministic findings: if any present, skip LLM (already high confidence)
STRONG_FINDINGS_SKIP_LLM = {"SSN_PATTERN", "CC_LUHN_VALID"}


def analyze_event(event: DLPEvent, use_llm: bool = True, ollama_model: str = "llama3.1:8b") -> DLPDecision:
    findings = detect(event.extracted_text)

    reasons: List[str] = []

    # We'll set this in each path so output always shows what drove the decision.
    decision_source = "UNKNOWN"

    if findings:
        reasons.append(
            "Deterministic detectors triggered: "
            + ", ".join(f"{f.name}({f.count})" for f in findings)
        )
    else:
        reasons.append("No deterministic detector hits.")

    # If traffic isn't decrypted, content-based LLM classification is not possible.
    if event.encryption_visibility != "decrypted":
        decision_source = "METADATA_ONLY (no TLS decrypt)"
        reasons.append("Encrypted traffic not decrypted: metadata-only posture (content classification limited).")
        reasons.insert(0, f"DecisionSource={decision_source}")
        return build_decision(findings, llm_label=None, llm_conf=None, reasons=reasons)

    # If LLM is disabled, return deterministic decision only.
    if not use_llm:
        decision_source = "DETERMINISTIC_ONLY (LLM disabled)"
        reasons.append("LLM disabled: using deterministic logic only.")
        reasons.insert(0, f"DecisionSource={decision_source}")
        return build_decision(findings, llm_label=None, llm_conf=None, reasons=reasons)

    # If we have no extracted text, we can't call the LLM.
    has_text = bool((event.extracted_text or "").strip())
    if not has_text:
        decision_source = "DETERMINISTIC_ONLY (no extracted text)"
        reasons.append("No extracted text available for LLM classification.")
        reasons.insert(0, f"DecisionSource={decision_source}")
        return build_decision(findings, llm_label=None, llm_conf=None, reasons=reasons)

    # Deterministic-only score (LLM not included yet)
    det_score = risk_score(findings, llm_label=None, llm_conf=None)

    # Strong deterministic signals -> skip LLM
    strong_hit = any(f.name in STRONG_FINDINGS_SKIP_LLM for f in findings)
    if strong_hit or det_score >= LLM_SKIP_HIGH_SCORE:
        decision_source = f"DETERMINISTIC_ONLY (LLM skipped: strong signal, det_score={det_score})"
        reasons.append(f"Skipping LLM (strong deterministic signal). det_score={det_score}")
        reasons.insert(0, f"DecisionSource={decision_source}")
        return build_decision(findings, llm_label=None, llm_conf=None, reasons=reasons)

    llm_label: Optional[str] = None
    llm_conf: Optional[float] = None

    # If there are NO findings, use LLM for context-aware classification
    # (this is where LLM adds value for secrets/passwords/keys/etc.)
    if not findings:
        reasons.append("No deterministic hits: using LLM for context-aware classification.")
        excerpt = make_excerpt(event.extracted_text, max_chars=MAX_LLM_EXCERPT_CHARS)
        try:
            label, conf, rationale = call_ollama_classify(excerpt, model=ollama_model)
            llm_label, llm_conf = label, conf
            decision_source = "LLM_USED (no deterministic hits)"

            if rationale:
                reasons.append(f"LLM rationale: {rationale}")
        except Exception:
            # LLM failed, fall back to deterministic-only decision
            decision_source = "DETERMINISTIC_ONLY (LLM failed/timeout; fallback)"
            reasons.append("LLM error/timeout; falling back to deterministic logic.")
            llm_label, llm_conf = None, None

        reasons.insert(0, f"DecisionSource={decision_source}")
        return build_decision(findings, llm_label=llm_label, llm_conf=llm_conf, reasons=reasons)

    # Low score WITH some weak signals -> skip LLM (save time)
    if det_score <= LLM_SKIP_LOW_SCORE:
        decision_source = f"DETERMINISTIC_ONLY (LLM skipped: low score, det_score={det_score})"
        reasons.append(f"Skipping LLM (low deterministic score). det_score={det_score}")
        reasons.insert(0, f"DecisionSource={decision_source}")
        return build_decision(findings, llm_label=None, llm_conf=None, reasons=reasons)

    # Borderline band -> call LLM
    if LLM_USE_SCORE_MIN <= det_score <= LLM_USE_SCORE_MAX:
        excerpt = make_excerpt(event.extracted_text, max_chars=MAX_LLM_EXCERPT_CHARS)
        try:
            label, conf, rationale = call_ollama_classify(excerpt, model=ollama_model)
            llm_label, llm_conf = label, conf
            decision_source = f"LLM_USED (borderline score, det_score={det_score})"

            if rationale:
                reasons.append(f"LLM rationale: {rationale}")
            else:
                reasons.append("LLM returned no rationale; continuing with hybrid decision.")
        except Exception:
            decision_source = f"DETERMINISTIC_ONLY (LLM failed/timeout; fallback, det_score={det_score})"
            reasons.append("LLM error/timeout; falling back to deterministic logic.")
            llm_label, llm_conf = None, None
    else:
        decision_source = f"DETERMINISTIC_ONLY (LLM skipped: outside band, det_score={det_score})"
        reasons.append(f"Skipping LLM (score outside borderline band). det_score={det_score}")

    reasons.insert(0, f"DecisionSource={decision_source}")
    return build_decision(findings, llm_label=llm_label, llm_conf=llm_conf, reasons=reasons)
