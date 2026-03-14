import json
import re
import requests
from typing import Tuple, Optional

OLLAMA_URL_DEFAULT = "http://localhost:11434"

# -----------------------------------------------------------------------------
# ROLE OF THIS MODULE IN THE ENGINE ARCHITECTURE
# -----------------------------------------------------------------------------
# engine.py owns ALL deterministic logic:
#   - detect()         -> regex/pattern findings
#   - risk_score()     -> numeric score from findings
#   - build_decision() -> final label + action
#
# This module (llm_ollama.py) is called by engine.py ONLY when:
#   a) no deterministic findings exist (score == 0, LLM adds context-aware value)
#   b) score is in the borderline band [LLM_USE_SCORE_MIN, LLM_USE_SCORE_MAX]
#
# Therefore: this module must NOT run its own pre-scan or make early-return
# decisions. It must always call Ollama and return (label, confidence, rationale).
# The engine decides what to do with those values via build_decision().
# -----------------------------------------------------------------------------

SYSTEM_PROMPT = (
"""
You are a Data Loss Prevention (DLP) classifier. Your job is to detect sensitive content in file uploads.

=== LABEL DEFINITIONS ===

CONFIDENTIAL -- use when the text contains ANY of:
  - API keys, secret keys, access tokens (patterns like sk_*, ghp_*, AKIA*, Bearer *)
  - Passwords, credentials, passphrases (password=, pwd=, passwd=, token=)
  - Private keys or cryptographic secrets (-----BEGIN * KEY-----)
  - Database connection strings (postgresql://, mongodb://, mysql://)
  - OAuth tokens, session tokens, JWT tokens
  - Internal/unreleased business strategy, M&A targets, non-public financials
  - Bank routing numbers, account numbers, wire transfer instructions

PII -- use when the text contains ANY of:
  - Full names combined with email, phone, SSN, DOB, or address
  - Credit card numbers (16-digit groups, with or without dashes)
  - Social Security Numbers (XXX-XX-XXXX format)
  - Medical records, diagnoses, prescriptions tied to a person
  - Combinations of personal identifiers (name + phone, name + email, etc.)

BENIGN -- use when:
  - No credentials, keys, tokens, or secrets are present
  - No personal identifiers or financial account data are present
  - Content is routine: meeting notes, generic docs, system logs without secrets

UNKNOWN -- use ONLY when:
  - Content is heavily redacted/masked and classification is genuinely impossible
  - Use sparingly; if ANY signal of CONFIDENTIAL or PII exists, prefer those labels

=== PRIORITY RULE ===
If BOTH PII and CONFIDENTIAL signals appear, output CONFIDENTIAL.
When in doubt between BENIGN and CONFIDENTIAL, choose CONFIDENTIAL.

=== FEW-SHOT EXAMPLES ===

Example 1 -- API key + token (CONFIDENTIAL)
Excerpt: "api_key = sk_test_51N8ExampleSecretKeyValue12345\ntoken = 8f3a9c1d2e3f4a5b6c7d8e9f\nDo not distribute"
Output: {"label":"CONFIDENTIAL","confidence":0.99,"rationale":"Contains an API secret key (sk_test_ prefix) and an access token that grant system access."}

Example 2 -- AWS credentials (CONFIDENTIAL)
Excerpt: "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
Output: {"label":"CONFIDENTIAL","confidence":0.99,"rationale":"Contains AWS access key ID (AKIA prefix) and secret access key -- live cloud credentials."}

Example 3 -- GitHub token in script (CONFIDENTIAL)
Excerpt: "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456\ncurl -H 'Authorization: token $GITHUB_TOKEN' https://api.github.com"
Output: {"label":"CONFIDENTIAL","confidence":0.98,"rationale":"Contains a GitHub personal access token (ghp_ prefix) embedded in a shell script."}

Example 4 -- Database connection string (CONFIDENTIAL)
Excerpt: "DATABASE_URL=postgresql://admin:S3cr3tP@ss@prod-db.internal:5432/customers"
Output: {"label":"CONFIDENTIAL","confidence":0.99,"rationale":"Contains a database connection string with embedded username and plaintext password."}

Example 5 -- Personal contact info (PII)
Excerpt: "Contact me at alice.nguyen@acme.com or +1-415-555-0182."
Output: {"label":"PII","confidence":0.99,"rationale":"Contains a personal email address and phone number -- direct contact PII."}

Example 6 -- Credit card data (PII)
Excerpt: "Person Name,Credit Card\nJohn Smith,4111-1111-1111-1111\nJane Doe,5500-0000-0000-0004"
Output: {"label":"PII","confidence":0.99,"rationale":"Contains full names paired with credit card numbers -- financial PII requiring immediate blocking."}

Example 7 -- Medical record (PII)
Excerpt: "Patient: Lisa Samson, SSN: 523-36-8350, Drug: Alprazolam, Diagnosis: anxiety disorder"
Output: {"label":"PII","confidence":0.99,"rationale":"Contains patient name, SSN, diagnosis and prescription -- protected health information (PHI)."}

Example 8 -- Routine content (BENIGN)
Excerpt: "The meeting starts at 3 PM in Conference Room B. Agenda: Q3 retrospective."
Output: {"label":"BENIGN","confidence":0.95,"rationale":"Routine meeting logistics with no credentials, keys, or personal identifiers."}

Example 9 -- Generic log without secrets (BENIGN)
Excerpt: "INFO 2024-01-15 10:23:45 Server started on port 8080. Health check passed."
Output: {"label":"BENIGN","confidence":0.94,"rationale":"Standard application log with no sensitive data, credentials, or personal information."}

Example 10 -- Heavily masked content (UNKNOWN)
Excerpt: "[REDACTED] account [MASKED] ref 82X"
Output: {"label":"UNKNOWN","confidence":0.62,"rationale":"Insufficient context -- heavy masking prevents reliable classification."}

=== OUTPUT FORMAT ===
Return ONLY valid JSON with exactly these keys: label, confidence, rationale.
- label: one of PII, CONFIDENTIAL, BENIGN, UNKNOWN
- confidence: float between 0.0 and 1.0
- rationale: one sentence explaining the key signal that drove the label
"""
)


def make_excerpt(text: str, max_chars: int = 1800) -> str:
    t = (text or "").strip()
    return t if len(t) <= max_chars else t[:max_chars] + "..."


def call_ollama_classify(
    excerpt: str,
    model: str = "llama3.1:8b",
    ollama_url: str = OLLAMA_URL_DEFAULT,
    timeout_s: int = 120,
) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    """
    Send excerpt to Ollama and return (label, confidence, rationale).

    Pure LLM call -- no deterministic pre-scanning here.
    engine.py owns that logic via detect() + risk_score().
    The engine's scoring band (LLM_USE_SCORE_MIN / LLM_USE_SCORE_MAX) is the
    single source of truth for when this function gets called.
    """
    payload = {
        "model": model,
        "format": "json",
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": excerpt},
        ],
        "options": {"temperature": 0.0},
    }

    r = requests.post(f"{ollama_url}/api/chat", json=payload, timeout=timeout_s)
    r.raise_for_status()
    data = r.json()

    content = (data.get("message", {}) or {}).get("content", "").strip()
    parsed = json.loads(content)

    label = parsed.get("label")
    conf = parsed.get("confidence")
    rationale = parsed.get("rationale")

    if isinstance(conf, (int, float)):
        conf = float(conf)
    else:
        conf = None

    return label, conf, rationale