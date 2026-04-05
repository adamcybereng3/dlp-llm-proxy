from __future__ import annotations

import re
import requests
from urllib.parse import unquote_plus, urlparse
from mitmproxy import http, ctx

# -----------------------------
# Engine config
# -----------------------------
DLP_ENGINE_URL = "http://127.0.0.1:8000/analyze"
USE_LLM = 1
LLM_MODEL = "llama3.1:8b"
TIMEOUT_S = 60

DEBUG_EXTRACT_PREVIEW = True
DEBUG_SKIP_REASON = False  # set True if you want to see skip reasons in logs

# -----------------------------
# Targets: Gmail + Exfil servers
# -----------------------------
ENABLE_GMAIL = True
ENABLE_EXFIL = True

# Gmail host
GMAIL_HOST = "mail.google.com"

# Gmail noise controls
GMAIL_PATH_KEYWORDS = {"/sync/", "/mail/"}
GMAIL_BODY_KEYWORDS = {"subject", "to", "cc", "bcc", "body", "message", "msg", "draft", "thread"}

# Exfil hosts
EXFIL_HOSTS = {"10.0.1.130"}  # add more if needed

# Only inspect these exfil paths (leave empty set() to inspect all exfil paths)
EXFIL_PATH_PREFIXES = {"/submit", "/upload", "/email/send"}
EXFIL_ALLOW_ALL_PATHS = False

# ✅ Separate minimum lengths
MIN_GMAIL_CHARS = 80   # higher to reduce Gmail noise
MIN_EXFIL_CHARS = 10   # lower so short SSN / API-key samples are inspected

# -----------------------------
# Response bodies
# -----------------------------
COACH_HTML = b"<html><body><h2>DLP Coaching</h2><p>Sensitive data detected. Please verify destination.</p></body></html>"
BLOCK_HTML = b"<html><body><h2>DLP Blocked</h2><p>Blocked by DLP policy.</p></body></html>"
QUAR_HTML  = b"<html><body><h2>DLP Quarantined</h2><p>Quarantined by DLP policy (simulated).</p></body></html>"

def respond(flow: http.HTTPFlow, code: int, body: bytes):
    flow.response = http.Response.make(code, body, {"Content-Type": "text/html; charset=utf-8"})

# -----------------------------
# Extraction helpers
# -----------------------------
def extract_text(flow: http.HTTPFlow, max_bytes: int = 300_000):
    ctype = (flow.request.headers.get("content-type") or "").lower()
    raw = (flow.request.raw_content or b"")[:max_bytes]

    if "text/plain" in ctype or "application/json" in ctype:
        return "txt", raw.decode("utf-8", errors="ignore")

    if "application/x-www-form-urlencoded" in ctype:
        decoded = unquote_plus(raw.decode("utf-8", errors="ignore"))
        return "urlencoded", decoded

    if "multipart/form-data" in ctype:
        body = raw.decode("utf-8", errors="ignore")
        printable = re.findall(r"[ -~]{20,}", body)
        extracted = "\n".join(printable[:300])
        return "multipart", extracted

    # fallback: try decode anyway (sometimes no content-type)
    try:
        return "unknown", raw.decode("utf-8", errors="ignore")
    except Exception:
        return "unknown", ""

# -----------------------------
# Target filters
# -----------------------------
def host_of(url: str) -> str:
    u = urlparse(url)
    return (u.hostname or "").lower()

def path_of(url: str) -> str:
    u = urlparse(url)
    return (u.path or "").lower()

def should_inspect_gmail(dest: str, extracted_text: str) -> bool:
    if not ENABLE_GMAIL:
        return False

    h = host_of(dest)
    p = path_of(dest)

    if h != GMAIL_HOST:
        return False

    if len(extracted_text.strip()) < MIN_GMAIL_CHARS:
        return False

    if GMAIL_PATH_KEYWORDS and not any(k in p for k in GMAIL_PATH_KEYWORDS):
        return False

    low = extracted_text.lower()
    if GMAIL_BODY_KEYWORDS and not any(k in low for k in GMAIL_BODY_KEYWORDS):
        return False

    return True

def should_inspect_exfil(dest: str, extracted_text: str) -> bool:
    if not ENABLE_EXFIL:
        return False

    h = host_of(dest)
    p = path_of(dest)

    if h not in {x.lower() for x in EXFIL_HOSTS}:
        return False

    # ✅ exfil uses a lower minimum to catch short samples
    if len(extracted_text.strip()) < MIN_EXFIL_CHARS:
        return False

    if EXFIL_ALLOW_ALL_PATHS:
        return True

    if EXFIL_PATH_PREFIXES and any(p.startswith(prefix) for prefix in EXFIL_PATH_PREFIXES):
        return True

    return False

def should_inspect(dest: str, extracted_text: str) -> bool:
    return should_inspect_exfil(dest, extracted_text) or should_inspect_gmail(dest, extracted_text)

# -----------------------------
# Engine call
# -----------------------------
def call_engine(dest: str, ctype: str, text: str):
    event = {
        "channel": "web_upload" if ctype == "multipart" else "form_post",
        "destination": dest,
        "content_type": ctype,
        "extracted_text": text,
        "metadata": {},
        "encryption_visibility": "decrypted",
    }
    params = {"use_llm": USE_LLM, "model": LLM_MODEL}
    r = requests.post(DLP_ENGINE_URL, params=params, json=event, timeout=TIMEOUT_S)
    r.raise_for_status()
    return r.json()

# -----------------------------
# Addon
# -----------------------------
class DLPAddon:
    def request(self, flow: http.HTTPFlow):
        if flow.request.method.upper() not in {"POST", "PUT", "PATCH"}:
            return

        dest = flow.request.pretty_url
        ctype, text = extract_text(flow)

        if not text.strip():
            return

        if not should_inspect(dest, text):
            if DEBUG_SKIP_REASON:
                ctx.log.info(f"[DLP] skipped dest={dest} host={host_of(dest)} path={path_of(dest)} len={len(text.strip())} ctype={ctype}")
            return

        if DEBUG_EXTRACT_PREVIEW:
            preview = text[:160].replace("\n", "\\n")
            ctx.log.info(f"[DLP] extracted ({ctype}) preview='{preview}' dest={dest}")

        try:
            decision = call_engine(dest, ctype, text)
        except Exception as e:
            ctx.log.warn(f"[DLP] engine call failed: {e}")
            return

        action = decision.get("action", "ALLOW")
        label  = decision.get("label", "UNKNOWN")
        score  = decision.get("risk_score", 0)

        ctx.log.info(f"[DLP] decision action={action} label={label} score={score} dest={dest}")

        if action == "ALLOW":
            return
        if action == "COACH":
            respond(flow, 200, COACH_HTML)
        elif action == "BLOCK":
            respond(flow, 403, BLOCK_HTML)
        elif action == "QUARANTINE":
            respond(flow, 403, QUAR_HTML)

addons = [DLPAddon()]
