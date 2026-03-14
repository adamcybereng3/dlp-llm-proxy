from __future__ import annotations

import re
import requests
from mitmproxy import http, ctx

# -----------------------------
# CONFIG (edit for your environment)
# -----------------------------

# DLP engine is running on same Ubuntu gateway (Option A)
DLP_ENGINE_URL = "http://127.0.0.1:8000/analyze"

# Ollama model used by your engine
USE_LLM = 1
LLM_MODEL = "llama3.1:8b"

# Request timeout to the DLP engine
TIMEOUT_S = 120

# Demo-only filtering:
# Only inspect traffic whose destination contains one of these strings.
# This prevents background browser traffic (telemetry) from cluttering your logs.
DEMO_TARGETS = [
    "10.0.1.130:9000",     # your test exfil server
    "/submit",             # (optional) ensure the submit endpoint is in path
    # Add additional demo targets here, e.g. "yourdomain.com/upload"
]

# Max bytes to inspect from request body to avoid huge uploads
MAX_BODY_BYTES = 300_000


# -----------------------------
# SIMPLE HTML PAGES FOR ENFORCEMENT
# -----------------------------
COACH_HTML = b"""<html><body>
<h2>DLP Coaching</h2>
<p>This request appears to contain <b>sensitive data</b>.</p>
<p>Please verify the destination is approved before proceeding.</p>
</body></html>"""

BLOCK_HTML = b"""<html><body>
<h2>DLP Blocked</h2>
<p>This request was <b>blocked</b> by DLP policy.</p>
</body></html>"""

QUAR_HTML = b"""<html><body>
<h2>DLP Quarantined</h2>
<p>This request was <b>quarantined</b> by DLP policy (simulated).</p>
</body></html>"""


# -----------------------------
# HELPERS
# -----------------------------

def should_inspect(dest: str) -> bool:
    """Return True if this request is part of the demo target set."""
    return any(t in dest for t in DEMO_TARGETS)

def respond(flow: http.HTTPFlow, status_code: int, body: bytes):
    flow.response = http.Response.make(
        status_code,
        body,
        {"Content-Type": "text/html; charset=utf-8"}
    )

def extract_text_from_request(flow: http.HTTPFlow) -> tuple[str, str]:
    """
    Returns (content_type, extracted_text).
    Covers:
      - text/plain, json, urlencoded
      - multipart/form-data (best-effort extraction for demo)
    """
    ctype = (flow.request.headers.get("content-type") or "").lower()
    raw = (flow.request.raw_content or b"")[:MAX_BODY_BYTES]

    # Common text bodies
    if any(x in ctype for x in ["text/plain", "application/json", "application/x-www-form-urlencoded"]):
        return "txt", raw.decode("utf-8", errors="ignore")

    # Multipart form uploads (demo extraction)
    if "multipart/form-data" in ctype:
        body = raw.decode("utf-8", errors="ignore")
        # Pull long printable spans to approximate extracted content
        printable = re.findall(r"[ -~]{20,}", body)
        extracted = "\n".join(printable[:200])
        return "multipart", extracted

    return "unknown", ""

def call_dlp_engine(destination: str, content_type: str, extracted_text: str) -> dict | None:
    """
    Call local DLP engine. Returns decision JSON or None on failure.
    """
    event = {
        "channel": "web_upload" if content_type == "multipart" else "form_post",
        "destination": destination,
        "content_type": content_type,
        "extracted_text": extracted_text,
        "metadata": {},
        "encryption_visibility": "decrypted"
    }
    params = {"use_llm": USE_LLM, "model": LLM_MODEL}

    try:
        r = requests.post(DLP_ENGINE_URL, params=params, json=event, timeout=TIMEOUT_S)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        ctx.log.warn(f"DLP engine call failed: {e}")
        return None


# -----------------------------
# MITMPROXY ADDON
# -----------------------------

class DLPAddon:
    def request(self, flow: http.HTTPFlow):
        # Only inspect methods that typically contain payloads
        if flow.request.method.upper() not in {"POST", "PUT", "PATCH"}:
            return

        dest = flow.request.pretty_url

        # Demo filter to avoid unrelated background traffic
        if not should_inspect(dest):
            return

        ctype, text = extract_text_from_request(flow)

        # If there is no text to analyze, let it pass
        if not text.strip():
            ctx.log.info(f"[DLP] No extractable text; allowing. dest={dest}")
            return

        decision = call_dlp_engine(dest, ctype, text)
        if not decision:
            # Fail-open for demo stability (you can change to fail-closed if needed)
            ctx.log.warn(f"[DLP] Engine unavailable; allowing. dest={dest}")
            return

        action = decision.get("action", "ALLOW")
        label = decision.get("label", "UNKNOWN")
        score = decision.get("risk_score", 0)

        ctx.log.info(f"[DLP] decision action={action} label={label} score={score} dest={dest}")

        if action == "ALLOW":
            return
        elif action == "COACH":
            respond(flow, 200, COACH_HTML)
        elif action == "BLOCK":
            respond(flow, 403, BLOCK_HTML)
        elif action == "QUARANTINE":
            # simulated quarantine: block + inform user
            respond(flow, 403, QUAR_HTML)
        else:
            return


addons = [DLPAddon()]
