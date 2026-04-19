from __future__ import annotations

import re
import csv
import os
import time
from datetime import datetime
import requests
from urllib.parse import unquote_plus, urlparse, parse_qs
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

GMAIL_SEND_PATH_HINT = "/sync/u/"
GMAIL_SEND_SUFFIXES = ("/i/fd", "/i/s")

GMAIL_LOG_PATH_ONLY = "/i/s"

EXFIL_HOSTS = {"10.0.1.130"}
EXFIL_PATH_PREFIXES = {"/submit", "/upload", "/email/send"}
EXFIL_ALLOW_ALL_PATHS = False

MIN_GMAIL_CHARS = 75
MIN_EXFIL_CHARS = 10


# --------------------------------------------------
# Gmail behavior
# --------------------------------------------------
GMAIL_LOG_ONLY_NON_ALLOW = True
GMAIL_LOG_COOLDOWN_SECONDS = 30
GMAIL_BULK_TEXTLEN_THRESHOLD = 2000

_last_gmail_log_time = 0.0


# --------------------------------------------------
# Response bodies
# --------------------------------------------------
COACH_HTML = b"""
<html>
<head>
<style>
body {
    font-family: Arial, sans-serif;
    background: linear-gradient(135deg, #0f172a, #1e293b);
    color: #e2e8f0;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
}
.card {
    background: #1e293b;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 0 20px rgba(0,0,0,0.4);
    text-align: center;
}
h1 { color: #38bdf8; }
p { color: #cbd5f5; }
</style>
</head>
<body>
<div class="card">
    <h1>DLP Coaching Notice</h1>
    <p>Your message may contain sensitive information.</p>
    <p>Please review before continuing.</p>
</div>
</body>
</html>
"""

BLOCK_HTML = b"""
<html>
<head>
<style>
body {
    font-family: Arial, sans-serif;
    background: linear-gradient(135deg, #1e1b4b, #7f1d1d);
    color: #f8fafc;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
}
.card {
    background: #111827;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 0 25px rgba(255,0,0,0.4);
    text-align: center;
}
h1 { color: #ef4444; }
p { color: #e5e7eb; }
</style>
</head>
<body>
<div class="card">
    <h1>Blocked by DLP</h1>
    <p>This action violates your organization's data protection policy.</p>
</div>
</body>
</html>
"""

QUAR_HTML = b"""
<html>
<head>
<style>
body {
    font-family: Arial, sans-serif;
    background: linear-gradient(135deg, #1e293b, #78350f);
    color: #f1f5f9;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
}
.card {
    background: #0f172a;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 0 25px rgba(255,165,0,0.4);
    text-align: center;
}
h1 { color: #f59e0b; }
p { color: #e2e8f0; }
</style>
</head>
<body>
<div class="card">
    <h1>Quarantined</h1>
    <p>Your request has been held for review.</p>
</div>
</body>
</html>
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
                "timestamp","method","destination","host","path",
                "content_type","risk_score","label","action",
                "text_length","preview","match_type","match_excerpt"
            ])
        ctx.log.info(f"[DLP] Created log file {LOG_FILE}")


def log_event(method, dest, ctype, score, label, action, text, match_type="", match_excerpt=""):
    host = host_of(dest)
    path = path_of(dest)

    clean_preview = text.strip().replace("\n", " ")

    if clean_preview:
        preview = clean_preview[:200]
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
    return (urlparse(url).hostname or "").lower()


def path_of(url: str) -> str:
    return (urlparse(url).path or "").lower()


# --------------------------------------------------
# Attachment detection
# --------------------------------------------------
def is_gmail_attachment_upload(dest: str, ctype: str) -> bool:
    host = host_of(dest)
    path = path_of(dest)

    if host != GMAIL_HOST:
        return False

    if "upload" in path or "attachment" in path:
        return True

    if "multipart/form-data" in ctype:
        return True

    return False


# --------------------------------------------------
# Extraction helpers
# --------------------------------------------------
def extract_printable_chunks(text: str, min_len: int = 6, max_chunks: int = 300):
    chunks = re.findall(r"[ -~]{%d,}" % min_len, text)
    return "\n".join(chunks[:max_chunks])


# --------------------------------------------------
# Request body extraction
# --------------------------------------------------
def extract_text(flow: http.HTTPFlow, max_bytes: int = 300000):
    ctype = (flow.request.headers.get("content-type") or "").lower()
    raw = (flow.request.raw_content or b"")[:max_bytes]
    dest = flow.request.pretty_url
    host = host_of(dest)

    if "text/plain" in ctype or "application/json" in ctype:
        decoded = raw.decode("utf-8", errors="ignore")

        if host == GMAIL_HOST:
            extracted_parts = []
            strings = re.findall(r'"([^"]{8,})"', decoded)

            clean_strings = []
            for s in strings:
                s = s.strip()
                if "thread-f:" in s or "msg-f:" in s:
                    continue
                if re.fullmatch(r"[A-Za-z0-9\-_:]{15,}", s):
                    continue
                if len(s) > 15 and " " in s:
                    clean_strings.append(s)

            if clean_strings:
                extracted_parts.extend(clean_strings[:50])

            extracted_parts.append(decoded)
            combined = "\n".join([p for p in extracted_parts if p.strip()])
            return "txt", combined

        return "txt", decoded

    if "application/x-www-form-urlencoded" in ctype:
        decoded = raw.decode("utf-8", errors="ignore")
        parsed = parse_qs(decoded)

        if host == GMAIL_HOST:
            extracted_parts = []

            for key in ["body", "subject", "message", "content"]:
                if key in parsed:
                    extracted_parts.append(" ".join(parsed[key]))

            if "f.req" in parsed:
                try:
                    f_req = parsed["f.req"][0]
                    strings = re.findall(r'"([^"]{8,})"', f_req)

                    clean_strings = []
                    for s in strings:
                        s = s.strip()
                        if "thread-f:" in s or "msg-f:" in s:
                            continue
                        if re.fullmatch(r"[A-Za-z0-9\-_:]{15,}", s):
                            continue
                        if len(s) > 15 and " " in s:
                            clean_strings.append(s)

                    if clean_strings:
                        extracted_parts.extend(clean_strings[:50])

                except Exception:
                    pass

            extracted_parts.append(unquote_plus(decoded))
            combined = "\n".join([p for p in extracted_parts if p.strip()])
            return "urlencoded", combined

        return "urlencoded", unquote_plus(decoded)

    if "multipart/form-data" in ctype:
        try:
            body = raw.decode("utf-8", errors="ignore")
            text_parts = re.findall(r"[ -~]{10,}", body)
            combined = "\n".join(text_parts[:300])
            return "multipart", combined
        except Exception:
            return "multipart", ""

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
# Inspection logic
# --------------------------------------------------
def should_inspect_gmail(dest: str, method: str, extracted_text: str) -> bool:
    if not ENABLE_GMAIL:
        return False
    if method.upper() not in {"POST", "PUT", "PATCH"}:
        return False
    if host_of(dest) != GMAIL_HOST:
        return False

    p = path_of(dest)
    if not (GMAIL_SEND_PATH_HINT in p and any(p.endswith(sfx) for sfx in GMAIL_SEND_SUFFIXES)):
        return False

    return len(extracted_text.strip()) >= MIN_GMAIL_CHARS


def should_log_gmail(dest: str, action: str) -> bool:
    global _last_gmail_log_time

    if GMAIL_LOG_PATH_ONLY not in path_of(dest):
        return False

    if GMAIL_LOG_ONLY_NON_ALLOW and action == "ALLOW":
        return False

    now = time.time()
    if now - _last_gmail_log_time < GMAIL_LOG_COOLDOWN_SECONDS:
        return False

    _last_gmail_log_time = now
    return True


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

    return any(path.startswith(prefix) for prefix in EXFIL_PATH_PREFIXES)


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
# MAIN ADDON
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

        # 🔥 NEW: Channel-aware filtering
        is_gmail = host_of(dest) == GMAIL_HOST
        is_exfil = should_inspect_exfil(dest, text)

        if is_gmail:
            if "thread-f:" in text and "msg-f:" in text:
                if not re.search(r"[A-Za-z]{3,}", text):
                    return

            if not re.search(r"[A-Za-z]{3,}", text):
                return

            if re.fullmatch(r"\d{10,}", text.strip()):
                return

            if len(text.split()) < 3:
                return

        elif is_exfil:
            if not re.search(r"[A-Za-z0-9]", text):
                return
            if len(text.strip()) < 5:
                return

        # Inspection pipeline
        inspect_it = (
            should_inspect_exfil(dest, text)
            or should_inspect_gmail(dest, flow.request.method, text)
            or is_gmail_attachment_upload(dest, ctype)
        )

        if not inspect_it:
            return

        if DEBUG_EXTRACT_PREVIEW:
            preview = text[:160].replace("\n", "\\n")
            ctx.log.info(f"[DLP] extracted ({ctype}) preview='{preview}' dest={dest}")

        try:
            decision = call_engine(dest, ctype, text)
        except Exception as e:
            ctx.log.warn(f"[DLP] engine call failed: {e}")
            return

        action = str(decision.get("action", "ALLOW"))
        label = str(decision.get("label", "UNKNOWN"))
        score = int(decision.get("risk_score", 0))

        match_type = decision.get("match_type") or ""
        match_excerpt = decision.get("match_excerpt") or ""

        if host_of(dest) == GMAIL_HOST:
            if action == "QUARANTINE" and len(text) < GMAIL_BULK_TEXTLEN_THRESHOLD:
                ctx.log.info(f"[DLP] Gmail override QUARANTINE->BLOCK")
                action = "BLOCK"

        ctx.log.info(f"[DLP] decision action={action} label={label} score={score} dest={dest}")

        if host_of(dest) == GMAIL_HOST:
            if should_log_gmail(dest, action):
                log_event(flow.request.method, dest, ctype, score, label, action, text, match_type, match_excerpt)
        else:
            log_event(flow.request.method, dest, ctype, score, label, action, text, match_type, match_excerpt)

        if action == "ALLOW":
            return
        if action == "COACH":
            respond(flow, 200, COACH_HTML)
        elif action == "BLOCK":
            respond(flow, 403, BLOCK_HTML)
        elif action == "QUARANTINE":
            respond(flow, 403, QUAR_HTML)


addons = [DLPAddon()]
