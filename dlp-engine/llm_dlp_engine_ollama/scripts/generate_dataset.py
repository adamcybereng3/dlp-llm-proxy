from __future__ import annotations

import argparse, json, random, os

def rand_name():
    first = random.choice(["Alex","Sam","Jordan","Taylor","Riley","Casey","Morgan","Avery","Jamie","Cameron"])
    last = random.choice(["Smith","Johnson","Lee","Brown","Garcia","Martinez","Davis","Wilson","Anderson","Clark"])
    return f"{first} {last}"

def rand_ssn():
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"

def luhn_valid_cc():
    digits = [random.randint(0,9) for _ in range(15)]
    checksum = 0
    parity = (len(digits)+1) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d2 = d * 2
            if d2 > 9: d2 -= 9
            checksum += d2
        else:
            checksum += d
    check = (10 - (checksum % 10)) % 10
    return "".join(map(str, digits)) + str(check)

def rand_email(name):
    handle = name.lower().replace(" ", ".")
    dom = random.choice(["example.com","corp.local","mail.test","university.edu"])
    return f"{handle}@{dom}"

def benign_numeric_blob():
    return " ".join(str(random.randint(100000, 999999999)) for _ in range(random.randint(3,8)))

def make_sensitive_case():
    kind = random.choice(["ssn_form", "cc_invoice", "hr_csv", "conf_doc"])
    name = rand_name()
    if kind == "ssn_form":
        txt = f"""HR Intake Form
Name: {name}
SSN: {rand_ssn()}
DOB: 1992-0{random.randint(1,9)}-{random.randint(10,28)}
"""
        label="PII"; action="BLOCK"
    elif kind == "cc_invoice":
        txt = f"""Invoice
Customer: {name}
Card: {luhn_valid_cc()}
Email: {rand_email(name)}
"""
        label="PII"; action="BLOCK"
    elif kind == "hr_csv":
        rows = ["name,ssn,email"]
        for _ in range(random.randint(5,20)):
            nm = rand_name()
            rows.append(f"{nm},{rand_ssn()},{rand_email(nm)}")
        txt = "\n".join(rows)
        label="PII"; action="QUARANTINE"
    else:
        txt = f"""CONFIDENTIAL — Internal Use Only
Project Falcon: roadmap and milestones.
Do not distribute outside the organization.
Owner: {name}
"""
        label="CONFIDENTIAL"; action="COACH"
    return txt, label, action

def make_benign_case():
    kind = random.choice(["logs", "code", "metrics", "random_text"])
    if kind == "logs":
        txt = f"""2026-02-{random.randint(10,28)}T12:34:5{random.randint(0,9)}Z INFO request_id={benign_numeric_blob()} status=200
2026-02-{random.randint(10,28)}T12:35:1{random.randint(0,9)}Z WARN retry_count={random.randint(0,5)}
"""
    elif kind == "code":
        txt = """def add(a, b):\n    return a + b\n\n# Numbers below are not PII:\n# 123456789 987654321\n"""
    elif kind == "metrics":
        txt = f"""cpu={random.randint(1,99)}% mem={random.randint(1,99)}% bytes_out={random.randint(10**6, 10**9)}
session_ids: {benign_numeric_blob()}
"""
    else:
        txt = """Team meeting notes: finalize architecture diagram and testing plan.
Next action: run unit tests and update README.
"""
    label="BENIGN"; action="ALLOW"
    return txt, label, action

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/dataset.jsonl")
    ap.add_argument("--n_sensitive", type=int, default=40)
    ap.add_argument("--n_benign", type=int, default=40)
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    records = []
    for i in range(args.n_sensitive):
        text, label, action = make_sensitive_case()
        records.append({
            "id": f"S{i:04d}",
            "event": {
                "channel": "web_upload",
                "destination": "https://upload.example.test",
                "content_type": "txt",
                "extracted_text": text,
                "metadata": {"filename": f"sensitive_{i}.txt"},
                "encryption_visibility": "decrypted"
            },
            "expected": {"label": label, "action": action}
        })

    for i in range(args.n_benign):
        text, label, action = make_benign_case()
        records.append({
            "id": f"B{i:04d}",
            "event": {
                "channel": "form_post",
                "destination": "https://portal.example.test",
                "content_type": "txt",
                "extracted_text": text,
                "metadata": {"filename": f"benign_{i}.txt"},
                "encryption_visibility": "decrypted"
            },
            "expected": {"label": label, "action": action}
        })

    random.shuffle(records)

    with open(args.out, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Wrote {len(records)} records to {args.out}")

if __name__ == "__main__":
    main()
