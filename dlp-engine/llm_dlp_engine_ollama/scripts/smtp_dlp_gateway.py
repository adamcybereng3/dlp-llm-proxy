from aiosmtpd.controller import Controller
from email import policy
from email.parser import BytesParser
import hashlib
import json
import os
import re
import smtplib
import requests
from datetime import datetime, timezone

DLP_ENGINE_URL = "http://127.0.0.1:8000/analyze"
MAILPIT_HOST = "127.0.0.1"
MAILPIT_PORT = 1025
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 2525

QUAR_PATH = "data/email_quarantine_events.jsonl"

def extract_text_from_email(msg):
    parts = []

    subject = msg.get("Subject", "")
    from_ = msg.get("From", "")
    to_ = msg.get("To", "")

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))

            if "attachment" in disp.lower():
                filename = part.get_filename() or ""
                payload = part.get_payload(decode=True) or b""
                if filename.lower().endswith((".txt", ".csv", ".log", ".py")):
                    try:
                        parts.append(payload.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass
            elif ctype == "text/plain":
                try:
                    parts.append(part.get_payload(decode=True).decode("utf-8", errors="ignore"))
                except Exception:
                    pass
    else:
        try:
            parts.append(msg.get_payload(decode=True).decode("utf-8", errors="ignore"))
        except Exception:
            pass

    header_block = f"From: {from_}\nTo: {to_}\nSubject: {subject}\n\n"
    return header_block + "\n".join(parts)

def redact_excerpt(text, max_chars=400):
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "XXX-XX-XXXX", text)
    text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<redacted_email>", text)
    text = re.sub(r"\bsk_(?:test|live)_[A-Za-z0-9]{10,}\b", "<redacted_sk_key>", text, flags=re.I)
    return text[:max_chars] + ("…" if len(text) > max_chars else "")

def write_quarantine(record):
    os.makedirs(os.path.dirname(QUAR_PATH), exist_ok=True)
    with open(QUAR_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

def forward_to_mailpit(mail_from, rcpt_tos, data):
    with smtplib.SMTP(MAILPIT_HOST, MAILPIT_PORT) as smtp:
        smtp.sendmail(mail_from, rcpt_tos, data)

class DLPHandler:
    async def handle_DATA(self, server, session, envelope):
        raw = envelope.original_content
        msg = BytesParser(policy=policy.default).parsebytes(raw)

        extracted = extract_text_from_email(msg)

        payload = {
            "channel": "email",
            "destination": ",".join(envelope.rcpt_tos),
            "content_type": "email",
            "extracted_text": extracted,
            "metadata": {
                "mail_from": envelope.mail_from,
                "rcpt_tos": ",".join(envelope.rcpt_tos),
                "subject": msg.get("Subject", "")
            },
            "encryption_visibility": "decrypted"
        }

        r = requests.post(
            DLP_ENGINE_URL,
            params={"use_llm": 1, "model": "llama3.1:8b"},
            json=payload,
            timeout=120
        )
        r.raise_for_status()
        decision = r.json()

        action = decision.get("action", "ALLOW")

        if action == "ALLOW":
            forward_to_mailpit(envelope.mail_from, envelope.rcpt_tos, raw)
            return "250 Message accepted and forwarded"

        if action == "BLOCK":
            return "550 5.7.1 Blocked by DLP policy"

        if action == "COACH":
            return "451 4.7.1 Sensitive content detected — review before resending"

        if action == "QUARANTINE":
            rec = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "from": envelope.mail_from,
                "to": envelope.rcpt_tos,
                "subject": msg.get("Subject", ""),
                "label": decision.get("label"),
                "action": action,
                "risk_score": decision.get("risk_score"),
                "confidence": decision.get("confidence"),
                "reasons": decision.get("reasons", []),
                "payload_sha256": hashlib.sha256(extracted.encode("utf-8", errors="ignore")).hexdigest(),
                "redacted_excerpt": redact_excerpt(extracted),
            }
            write_quarantine(rec)
            return "250 Message accepted for quarantine"

        return "550 5.7.1 Unknown policy decision"

if __name__ == "__main__":
    controller = Controller(DLPHandler(), hostname=LISTEN_HOST, port=LISTEN_PORT)
    controller.start()
    print(f"SMTP DLP gateway listening on {LISTEN_HOST}:{LISTEN_PORT}")
    try:
        import time
        while True:
            time.sleep(3600)
    finally:
        controller.stop()
