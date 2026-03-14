import os, json, argparse

TEXT_EXTS = {".txt", ".csv", ".py"}

def infer_label_from_path(path: str) -> str:
    p = path.lower()

    # Benign.zip contains both negative and positive samples
    if "negative_samples" in p or "negative samples" in p:
        return "BENIGN"
    if "positive_samples" in p or "positive samples" in p:
        # These are usually secrets/API keys etc. Treat as sensitive/confidential
        return "CONFIDENTIAL"

    # Everything under Sensitive/ treat as sensitive unless you want finer mapping
    # NOTE: This assumes you unzip into a folder named "Sensitive"
    if "/sensitive/" in p or p.startswith("sensitive" + os.sep) or p.startswith("sensitive/"):
        fname = os.path.basename(p)
        # Heuristic: if filename hints at PII/PHI/PCI, label as PII
        if any(k in fname for k in ["ssn", "pci", "phi", "patient", "passport", "drivers", "credit", "credit_card"]):
            return "PII"
        return "CONFIDENTIAL"

    # Default fallback
    return "BENIGN"

def expected_action(label: str) -> str:
    # Adjust for your demo policy
    return {
        "PII": "BLOCK",
        "CONFIDENTIAL": "COACH",
        "BENIGN": "ALLOW",
        "UNKNOWN": "ALLOW"
    }.get(label, "ALLOW")

def read_text_file(path: str, max_chars: int = 6000) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read()
    return data.replace("\x00", "")[:max_chars]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples_root", default="~/dlp-data", help="Root dir containing Sensitive/ and Benign/")
    ap.add_argument("--out", default="data/train_from_samples.jsonl")
    args = ap.parse_args()

    root = os.path.expanduser(args.samples_root)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    records = 0
    with open(args.out, "w", encoding="utf-8") as out:
        for dirpath, _, files in os.walk(root):
            for fn in files:
                ext = os.path.splitext(fn)[1].lower()
                if ext not in TEXT_EXTS:
                    continue

                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, root)

                label = infer_label_from_path(rel)
                action = expected_action(label)

                text = read_text_file(full)
                if not text.strip():
                    continue

                rec = {
                    "id": rel.replace(os.sep, "_"),
                    "event": {
                        "channel": "web_upload",
                        "destination": "https://upload.test.local/demo",
                        "content_type": ext.lstrip("."),
                        "extracted_text": text,
                        "metadata": {"filename": fn, "path": rel},
                        "encryption_visibility": "decrypted"
                    },
                    "expected": {"label": label, "action": action}
                }
                out.write(json.dumps(rec) + "\n")
                records += 1

    print(f"Wrote {records} records to {args.out}")

if __name__ == "__main__":
    main()
