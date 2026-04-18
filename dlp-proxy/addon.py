from __future__ import annotations

import re
import csv
import os
import time
from datetime import datetime
import requests
from urllib.parse import unquote_plus, urlparse
from mitmproxy import http, ctx


# --------------------------------------------------
# Engine config
# --------------------------------------------------
DLP_ENGINE_URL = "http://127.0.0.1:8000/analyze"
USE_LLM = 1
LLM_MODEL = "llama3.1:8b"
TIMEOUT_S = 60


# --------------------------------------------------
# Logging config
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "mitmproxy_events.csv")


# --------------------------------------------------
# Debug
# --------------------------------------------------
DEBUG_EXTRACT_PREVIEW = True
DEBUG_SKIP_REASON = False


# --------------------------------------------------
# Targets
# --------------------------------------------------
ENABLE_GMAIL = True
ENABLE_EXFIL = True

GMAIL_HOST = "mail.google.com"

# ✅ Inspect/enforce on BOTH endpoints (reliability)
GMAIL_SEND_PATH_HINT = "/sync/u/"
GMAIL_SEND_SUFFIXES = ("/i/fd", "/i/s")

# ✅ Log only the stable endpoint to keep dashboard clean
GMAIL_LOG_PATH_ONLY = "/i/s"

EXFIL_HOSTS = {"10.0.1.130"}
EXFIL_PATH_PREFIXES = {"/submit", "/upload", "/email/send"}
EXFIL_ALLOW_ALL_PATHS = False

MIN_GMAIL_CHARS = 20
MIN_EXFIL_CHARS = 10


# --------------------------------------------------
# Gmail: dashboard cleanup (ONE log per email send)
# --------------------------------------------------
GMAIL_LOG_ONLY_NON_ALLOW = True
GMAIL_LOG_COOLDOWN_SECONDS = 30  # 1 row per send burst

# ✅ Behavior #2: Gmail QUARANTINE only if truly bulk; else BLOCK
GMAIL_BULK_TEXTLEN_THRESHOLD = 2000

_last_gmail_log_time = 0.0


# --------------------------------------------------
# Response bodies (make BLOCK obvious in Gmail UI)
# --------------------------------------------------
COACH_HTML = b"""
<html><body style="font-family:Arial">
<h2>DLP Coaching</h2>
<p>Sensitive data detected. Please confirm this is allowed before sending.</p>
</body></html>
"""

BLOCK_HTML = b"""
<html><body style="font-family:Arial">
<h1 style="color:#b00020">DLP BLOCKED</h1>
<p><b>Reason:</b> Sensitive data detected in an email send attempt.</p>
<p>This request was blocked by DLP policy.</p>
</body></html>
"""

QUAR_HTML = b"""
<html><body style="font-family:Arial">
<h1 style="color:#b00020">DLP QUARANTINED</h1>
<p><b>Reason:</b> Bulk/high-risk sensitive data detected.</p>
<p>This request was quarantined by DLP policy (simulated).</p>
</body></html>
"""


# --------------------------------------------------
# CSV logging
# --------------------------------------------------
def ensure_csv():
    os.makedirs(LOG_DIR, exist_ok=True)

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "method",
                "destination",
                "host",
                "path",
                "content_type",
                "risk_score",
                "label",
                "action",
                "text_length",
                "preview",
                # ✅ optional upgrades (now populated from engine decision)
                "match_type",
                "match_excerpt",
            ])
        ctx.log.info(f"[DLP] Created log file {LOG_FILE}")


def log_event(method, dest, ctype, score, label, action, text, match_type="", match_excerpt=""):
    host = host_of(dest)
    path = path_of(dest)

    # ✅ Prefer clean extracted text first
    clean_preview = text.strip().replace("\n", " ")

    if clean_preview:
        preview = clean_preview[:200]

    # fallback to match excerpt if extraction failed
    elif match_excerpt:
        preview = match_excerpt.replace("\n", " ")

    else:
        preview = text[:200].replace("\n", " ")

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.utcnow().isoformat(),
            method,
            dest,
            host,
            path,
            ctype,
            score,
            label,
            action,
            len(text),
            preview,
            match_type or "",
            match_excerpt or "",
        ])


# --------------------------------------------------
# URL helpers
# --------------------------------------------------
def host_of(url: str) -> str:
    u = urlparse(url)
    return (u.hostname or "").lower()


def path_of(url: str) -> str:
    u = urlparse(url)
    return (u.path or "").lower()


# --------------------------------------------------
# Request body extraction
# --------------------------------------------------
def extract_printable_chunks(text: str, min_len: int = 6, max_chunks: int = 300):
    chunks = re.findall(r"[ -~]{%d,}" % min_len, text)
    return "\n".join(chunks[:max_chunks])


def extract_text(flow: http.HTTPFlow, max_bytes: int = 300000):
    ctype = (flow.request.headers.get("content-type") or "").lower()
    raw = (flow.request.raw_content or b"")[:max_bytes]
    dest = flow.request.pretty_url
    host = host_of(dest)
    
    if "text/plain" in ctype or "application/json" in ctype:
        decoded = raw.decode("utf-8", errors="ignore")

        # 🔥 Gmail override (THIS is what you're missing)
        if host == GMAIL_HOST:
            extracted_parts = []

            # Try to extract readable strings
            strings = re.findall(r'"([^"]{8,})"', decoded)

            clean_strings = []

            for s in strings:
                s = s.strip()

                # Skip Gmail metadata
                if "thread-f:" in s or "msg-f:" in s:
                    continue

                # Skip tokens/IDs
                if re.fullmatch(r"[A-Za-z0-9\-_:]{15,}", s):
                    continue

                # Keep human text
                if len(s) > 15 and " " in s:
                    clean_strings.append(s)

            if clean_strings:
                extracted_parts.extend(clean_strings[:50])

            # CRITICAL fallback
            extracted_parts.append(decoded)

            combined = "\n".join([p for p in extracted_parts if p.strip()])

            return "txt", combined  # ✅ keep type unchanged

        return "txt", decoded

    if "application/x-www-form-urlencoded" in ctype:
        decoded = unquote_plus(raw.decode("utf-8", errors="ignore"))
        return "urlencoded", decoded

    if "application/x-www-form-urlencoded" in ctype:
        decoded = raw.decode("utf-8", errors="ignore")
        parsed = parse_qs(decoded)

    # ✅ ONLY enhance Gmail traffic
        if host == GMAIL_HOST:
            extracted_parts = []

            # 🔹 1. Direct fields (best signal)
            for key in ["body", "subject", "message", "content"]:
                if key in parsed:
                    extracted_parts.append(" ".join(parsed[key]))

            # 🔹 2. Gmail hidden payload (f.req)
            if "f.req" in parsed:
                try:
                    f_req = parsed["f.req"][0]

                    # Extract all quoted strings
                    strings = re.findall(r'"([^"]{8,})"', f_req)

                    clean_strings = []

                    for s in strings:
                        s = s.strip()

                        # ❌ Skip Gmail metadata
                        if "thread-f:" in s or "msg-f:" in s:
                            continue

                        # ❌ Skip IDs / tokens
                        if re.fullmatch(r"[A-Za-z0-9\-_:]{15,}", s):
                            continue

                        # ✅ Keep human-readable text
                        if len(s) > 15 and " " in s:
                            clean_strings.append(s)

                    if clean_strings:
                        extracted_parts.extend(clean_strings[:50])

                except Exception:
                    pass

            # 🔹 3. CRITICAL fallback (do NOT remove — preserves PII detection)
            extracted_parts.append(unquote_plus(decoded))

            combined = "\n".join([p for p in extracted_parts if p.strip()])

            return "urlencoded", combined  # ✅ KEEP ORIGINAL TYPE

        # ✅ Non-Gmail stays EXACTLY the same
        return "urlencoded", unquote_plus(decoded)


    if "multipart/form-data" in ctype:
        body = raw.decode("utf-8", errors="ignore")
        printable = re.findall(r"[ -~]{20,}", body)
        return "multipart", "\n".join(printable[:300])

    # Gmail sync fallback: best-effort printable extraction
    if host == GMAIL_HOST:
        decoded = raw.decode("utf-8", errors="ignore")
        decoded = unquote_plus(decoded)
        printable = extract_printable_chunks(decoded, min_len=4, max_chunks=400)
        return "gmail_sync", printable

    try:
        return "unknown", raw.decode("utf-8", errors="ignore")
    except Exception:
        return "unknown", ""


# --------------------------------------------------
# Gmail inspection logic
# --------------------------------------------------
def should_inspect_gmail(dest: str, method: str, extracted_text: str) -> bool:
    if not ENABLE_GMAIL:
        return False

    if method.upper() not in {"POST", "PUT", "PATCH"}:
        return False

    if host_of(dest) != GMAIL_HOST:
        return False

    p = path_of(dest)

    # ✅ inspect both /i/fd and /i/s for enforcement reliability
    if not (GMAIL_SEND_PATH_HINT in p and any(p.endswith(sfx) for sfx in GMAIL_SEND_SUFFIXES)):
        return False

    return len(extracted_text.strip()) >= MIN_GMAIL_CHARS


def should_log_gmail(dest: str, action: str) -> bool:
    """
    ✅ Log only /i/fd (stable) and only once per cooldown window.
    """
    global _last_gmail_log_time

    # only log the stable fd endpoint
    if GMAIL_LOG_PATH_ONLY not in path_of(dest):
        return False

    if GMAIL_LOG_ONLY_NON_ALLOW and action == "ALLOW":
        return False

    now = time.time()
    if now - _last_gmail_log_time < GMAIL_LOG_COOLDOWN_SECONDS:
        return False

    _last_gmail_log_time = now
    return True


# --------------------------------------------------
# Exfil inspection logic
# --------------------------------------------------
def should_inspect_exfil(dest: str, extracted_text: str) -> bool:
    if not ENABLE_EXFIL:
        return False

    host = host_of(dest)
    path = path_of(dest)

    if host not in {x.lower() for x in EXFIL_HOSTS}:
        return False

    if len(extracted_text.strip()) < MIN_EXFIL_CHARS:
        return False

    if EXFIL_ALLOW_ALL_PATHS:
        return True

    if any(path.startswith(prefix) for prefix in EXFIL_PATH_PREFIXES):
        return True

    return False


# --------------------------------------------------
# Engine call
# --------------------------------------------------
def call_engine(dest: str, ctype: str, text: str):
    event = {
        "channel": "gmail_send" if ctype == "gmail_sync" else ("web_upload" if ctype == "multipart" else "form_post"),
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


# --------------------------------------------------
# Response helper
# --------------------------------------------------
def respond(flow: http.HTTPFlow, code: int, body: bytes):
    flow.response = http.Response.make(code, body, {"Content-Type": "text/html"})


# --------------------------------------------------
# Main addon
# --------------------------------------------------
class DLPAddon:
    def load(self, loader):
        ensure_csv()
        ctx.log.info("[DLP] CSV logging initialized")

    def request(self, flow: http.HTTPFlow):
        if flow.request.method.upper() not in {"POST", "PUT", "PATCH"}:
            return

        dest = flow.request.pretty_url
        ctype, text = extract_text(flow)

        if not text.strip():
            return

        inspect_it = should_inspect_exfil(dest, text) or should_inspect_gmail(dest, flow.request.method, text)
        if not inspect_it:
            if DEBUG_SKIP_REASON:
                pass
            return

        if DEBUG_EXTRACT_PREVIEW:
            preview = text[:160].replace("\n", "\\n")
            ctx.log.info(f"[DLP] extracted ({ctype}) preview='{preview}' dest={dest}")

        try:
            decision = call_engine(dest, ctype, text)
        except Exception as e:
            ctx.log.warn(f"[DLP] engine call failed: {e}")
            return

        # Engine decision fields
        action = str(decision.get("action", "ALLOW"))
        label = str(decision.get("label", "UNKNOWN"))
        score = int(decision.get("risk_score", 0))

        # ✅ Pull match fields directly from engine response
        match_type = decision.get("match_type") or ""
        match_excerpt = decision.get("match_excerpt") or ""

        # Gmail behavior #2: QUARANTINE only if truly bulk
        if host_of(dest) == GMAIL_HOST:
            if action == "QUARANTINE" and len(text) < GMAIL_BULK_TEXTLEN_THRESHOLD:
                ctx.log.info(
                    f"[DLP] Gmail override QUARANTINE->BLOCK (len={len(text)} < {GMAIL_BULK_TEXTLEN_THRESHOLD})"
                )
                action = "BLOCK"

        ctx.log.info(f"[DLP] decision action={action} label={label} score={score} dest={dest}")

        # Logging rules
        if host_of(dest) == GMAIL_HOST:
            if should_log_gmail(dest, action):
                log_event(flow.request.method, dest, ctype, score, label, action, text, match_type, match_excerpt)
        else:
            log_event(flow.request.method, dest, ctype, score, label, action, text, match_type, match_excerpt)

        # Enforcement
        if action == "ALLOW":
            return
        if action == "COACH":
            respond(flow, 200, COACH_HTML)
        elif action == "BLOCK":
            respond(flow, 403, BLOCK_HTML)
        elif action == "QUARANTINE":
            respond(flow, 403, QUAR_HTML)


addons = [DLPAddon()]
