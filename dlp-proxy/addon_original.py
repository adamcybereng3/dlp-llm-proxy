from __future__ import annotations

import re
import requests
from urllib.parse import unquote_plus
from urllib.parse import urlparse
from mitmproxy import http, ctx

DLP_ENGINE_URL = "http://127.0.0.1:8000/analyze"
USE_LLM = 1
LLM_MODEL = "llama3.1:8b"
TIMEOUT_S = 60  # give Ollama/engine more room under load

# Toggle to help debug extraction issues during demo prep
DEBUG_EXTRACT_PREVIEW = True

# -----------------------------
# WEBMAIL DEMO FILTERING
# -----------------------------
# Turn this ON to demo email DLP via Gmail/Outlook Web without inspecting everything else.
WEBMAIL_MODE = True

# Webmail host allowlist (Gmail + Outlook Web). You can add more if needed.
WEBMAIL_HOST_ALLOWLIST = {
    "mail.google.com",
    "outlook.office.com",
    "outlook.live.com",
}

# Only inspect requests whose path contains these keywords (reduces noise).
# NOTE: webmail providers change paths often; if you see nothing being inspected,
# temporarily set WEBMAIL_PATH_KEYWORDS = set() to allow all paths for allowed hosts.
WEBMAIL_PATH_KEYWORDS = {
    "send", "compose", "upload", "attachment", "draft", "message"
}

# Ignore tiny extracted texts (filters telemetry/background pings)
MIN_EXTRACTED_CHARS = 40

COACH_HTML = b"<html><body><h2>DLP Coaching</h2><p>Sensitive data detected. Please verify destination.</p></body></html>"
BLOCK_HTML = b"<html><body><h2>DLP Blocked</h2><p>Blocked by DLP policy.</p></body></html>"
QUAR_HTML  = b"<html><body><h2>DLP Quarantined</h2><p>Quarantined by DLP policy (simulated).</p></body></html>"

def respond(flow: http.HTTPFlow, code: int, body: bytes):
    flow.response = http.Response.make(code, body, {"Content-Type": "text/html; charset=utf-8"})

def extract_text(flow: http.HTTPFlow, max_bytes: int = 300_000):
    """
    Returns (content_type, extracted_text).
    Important: form POSTs are usually application/x-www-form-urlencoded and must be decoded,
    otherwise patterns like SSN won't match reliably.
    """
    ctype = (flow.request.headers.get("content-type") or "").lower()
    raw = (flow.request.raw_content or b"")[:max_bytes]

    # 1) Plain text / JSON
    if "text/plain" in ctype or "application/json" in ctype:
        return "txt", raw.decode("utf-8", errors="ignore")

    # 2) HTML form posts (URL-encoded)
    if "application/x-www-form-urlencoded" in ctype:
        decoded = unquote_plus(raw.decode("utf-8", errors="ignore"))
        return "urlencoded", decoded

    # 3) Multipart form uploads (best-effort extraction)
    if "multipart/form-data" in ctype:
        body = raw.decode("utf-8", errors="ignore")
        printable = re.findall(r"[ -~]{20,}", body)
        extracted = "\n".join(printable[:300])
        return "multipart", extracted

    return "unknown", ""

def call_engine(dest: str, ctype: str, text: str):
    event = {
        "channel": "web_upload" if ctype == "multipart" else "form_post",
        "destination": dest,
        "content_type": ctype,
        "extracted_text": text,
        "metadata": {},
        "encryption_visibility": "decrypted"
    }
    params = {"use_llm": USE_LLM, "model": LLM_MODEL}
    r = requests.post(DLP_ENGINE_URL, params=params, json=event, timeout=TIMEOUT_S)
    r.raise_for_status()
    return r.json()

def should_inspect_webmail(flow: http.HTTPFlow, extracted_text: str) -> bool:
    """
    Webmail demo filter: only inspect Gmail/Outlook hosts and likely send/upload paths.
    """
    if not WEBMAIL_MODE:
        return True

    dest = flow.request.pretty_url
    u = urlparse(dest)
    host = (u.hostname or "").lower()
    path = (u.path or "").lower()

    if host not in WEBMAIL_HOST_ALLOWLIST:
        return False

    if len(extracted_text.strip()) < MIN_EXTRACTED_CHARS:
        return False

    # If keyword set is empty, allow all paths for allowed hosts
    if WEBMAIL_PATH_KEYWORDS:
        if not any(k in path for k in WEBMAIL_PATH_KEYWORDS):
            return False

    return True

class DLPAddon:
    def request(self, flow: http.HTTPFlow):
        if flow.request.method.upper() not in {"POST", "PUT", "PATCH"}:
            return

        dest = flow.request.pretty_url
        ctype, text = extract_text(flow)

        if not text.strip():
            return

        # ✅ Webmail filter (Gmail/Outlook)
        if not should_inspect_webmail(flow, text):
            # Optional: uncomment to see why things are skipped (can be noisy)
            # u = urlparse(dest)
            # ctx.log.info(f"[DLP] skipped webmail filter host={u.hostname} path={u.path} ctype={ctype} len={len(text)}")
            return

        if DEBUG_EXTRACT_PREVIEW:
            preview = text[:160].replace("\n", "\\n")
            ctx.log.info(f"[DLP] extracted ({ctype}) preview='{preview}' dest={dest}")

        try:
            decision = call_engine(dest, ctype, text)
        except Exception as e:
            ctx.log.warn(f"DLP engine call failed: {e}")
            return  # fail-open for now

        action = decision.get("action", "ALLOW")
        label  = decision.get("label", "UNKNOWN")
        score  = decision.get("risk_score", 0)

        ctx.log.info(f"DLP decision action={action} label={label} score={score} dest={dest}")

        if action == "ALLOW":
            return
        if action == "COACH":
            respond(flow, 200, COACH_HTML)
        elif action == "BLOCK":
            respond(flow, 403, BLOCK_HTML)
        elif action == "QUARANTINE":
            respond(flow, 403, QUAR_HTML)

addons = [DLPAddon()]
