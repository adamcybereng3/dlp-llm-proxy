from __future__ import annotations

import re
import csv
import os
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
# Logging config (robust path)
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_DIR = os.path.join(BASE_DIR, "logs")

LOG_FILE = os.path.join(LOG_DIR, "mitmproxy_events.csv")


# --------------------------------------------------
# Debug
# --------------------------------------------------

DEBUG_EXTRACT_PREVIEW = True
DEBUG_SKIP_REASON = True


# --------------------------------------------------
# Targets
# --------------------------------------------------

ENABLE_GMAIL = True
ENABLE_EXFIL = True

GMAIL_HOST = "mail.google.com"

# indicators that an actual email send is occurring
GMAIL_SEND_INDICATORS = [
    "subject=",
    "to=",
    "body=",
    "mime-version",
    "content-transfer-encoding"
]


EXFIL_HOSTS = {"10.0.1.130"}

EXFIL_PATH_PREFIXES = {
    "/submit",
    "/upload",
    "/email/send"
}

EXFIL_ALLOW_ALL_PATHS = False

MIN_GMAIL_CHARS = 50
MIN_EXFIL_CHARS = 10


# --------------------------------------------------
# Response bodies
# --------------------------------------------------

COACH_HTML = b"<html><body><h2>DLP Coaching</h2><p>Sensitive data detected.</p></body></html>"
BLOCK_HTML = b"<html><body><h2>DLP Blocked</h2><p>Blocked by DLP policy.</p></body></html>"
QUAR_HTML = b"<html><body><h2>DLP Quarantined</h2><p>Quarantined by DLP policy.</p></body></html>"


# --------------------------------------------------
# CSV logging
# --------------------------------------------------

def ensure_csv():

    os.makedirs(LOG_DIR, exist_ok=True)

    if not os.path.exists(LOG_FILE):

        with open(LOG_FILE, "w", newline="") as f:

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
                "preview"
            ])

        ctx.log.info(f"[DLP] Created log file {LOG_FILE}")


def log_event(method, dest, ctype, score, label, action, text):

    host = host_of(dest)
    path = path_of(dest)

    preview = text[:120].replace("\n", " ")

    with open(LOG_FILE, "a", newline="") as f:

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
            preview
        ])


# --------------------------------------------------
# URL helpers
# --------------------------------------------------

def host_of(url: str):

    u = urlparse(url)

    return (u.hostname or "").lower()


def path_of(url: str):

    u = urlparse(url)

    return (u.path or "").lower()


# --------------------------------------------------
# Request body extraction
# --------------------------------------------------

def extract_text(flow: http.HTTPFlow, max_bytes: int = 300000):

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

        return "multipart", "\n".join(printable[:300])

    try:

        return "unknown", raw.decode("utf-8", errors="ignore")

    except Exception:

        return "unknown", ""


# --------------------------------------------------
# Gmail inspection logic
# --------------------------------------------------

def should_inspect_gmail(dest: str, extracted_text: str):

    if not ENABLE_GMAIL:
        return False

    host = host_of(dest)
    path = path_of(dest)

    if host != GMAIL_HOST:
        return False

    # Gmail send events happen through /sync/
    if "/sync/" not in path:
        return False

    if len(extracted_text.strip()) < MIN_GMAIL_CHARS:
        return False

    text = extracted_text.lower()

    if not any(indicator in text for indicator in GMAIL_SEND_INDICATORS):

        if DEBUG_SKIP_REASON:
            ctx.log.info(f"[DLP] Gmail skipped (not send event) path={path}")

        return False

    return True


# --------------------------------------------------
# Exfil inspection logic
# --------------------------------------------------

def should_inspect_exfil(dest: str, extracted_text: str):

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


def should_inspect(dest: str, extracted_text: str):

    return (
        should_inspect_exfil(dest, extracted_text)
        or should_inspect_gmail(dest, extracted_text)
    )


# --------------------------------------------------
# Engine call
# --------------------------------------------------

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

    ctx.log.info(f"[DLP] sending request to engine for {dest}")

    r = requests.post(
        DLP_ENGINE_URL,
        params=params,
        json=event,
        timeout=TIMEOUT_S
    )

    r.raise_for_status()

    return r.json()


# --------------------------------------------------
# Response helper
# --------------------------------------------------

def respond(flow: http.HTTPFlow, code: int, body: bytes):

    flow.response = http.Response.make(
        code,
        body,
        {"Content-Type": "text/html"}
    )


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

        if not should_inspect(dest, text):

            if DEBUG_SKIP_REASON:
                ctx.log.info(f"[DLP] skipped dest={dest}")

            return

        if DEBUG_EXTRACT_PREVIEW:

            preview = text[:160].replace("\n", "\\n")

            ctx.log.info(
                f"[DLP] extracted ({ctype}) preview='{preview}' dest={dest}"
            )

        try:

            decision = call_engine(dest, ctype, text)

        except Exception as e:

            ctx.log.warn(f"[DLP] engine call failed: {e}")

            return

        action = decision.get("action", "ALLOW")

        label = decision.get("label", "UNKNOWN")

        score = decision.get("risk_score", 0)

        ctx.log.info(
            f"[DLP] decision action={action} label={label} score={score}"
        )

        log_event(
            flow.request.method,
            dest,
            ctype,
            score,
            label,
            action,
            text
        )

        if action == "ALLOW":
            return

        if action == "COACH":
            respond(flow, 200, COACH_HTML)

        elif action == "BLOCK":
            respond(flow, 403, BLOCK_HTML)

        elif action == "QUARANTINE":
            respond(flow, 403, QUAR_HTML)


addons = [DLPAddon()]
