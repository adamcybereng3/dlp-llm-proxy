from __future__ import annotations

import argparse
import json
import re
import time

from app.models import DLPEvent
from app.engine import analyze_event


# -----------------------------
# Metrics
# -----------------------------

def precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) else 0.0


def recall(tp: int, fn: int) -> float:
    return tp / (tp + fn) if (tp + fn) else 0.0


def f1(p: float, r: float) -> float:
    return (2 * p * r) / (p + r) if (p + r) else 0.0


# -----------------------------
# Normalization
# -----------------------------

def normalize_label(label: str) -> str:
    if not label:
        return "BENIGN"

    upper = str(label).strip().upper()

    if upper in {"PII", "PERSONAL", "SENSITIVE"}:
        return "PII"

    if upper in {"CONF", "CONFIDENTIAL", "INTERNAL", "PRIVATE"}:
        return "CONFIDENTIAL"

    if upper in {"BENIGN", "SAFE", "NORMAL", "NON-SENSITIVE", "NONSENSITIVE"}:
        return "BENIGN"

    letters_only = re.sub(r"[^A-Z]", "", upper)

    if "PII" in letters_only or "PERSONAL" in letters_only:
        return "PII"

    if "CONF" in letters_only or "CONFIDENTIAL" in letters_only:
        return "CONFIDENTIAL"

    if "BENIGN" in letters_only or "SAFE" in letters_only:
        return "BENIGN"

    return "BENIGN"


def normalize_action(action: str) -> str:

    if not action:
        return "ALLOW"

    upper = str(action).strip().upper()

    if upper in {"BLOCK", "DENY", "STOP"}:
        return "BLOCK"

    if upper in {"COACH", "WARN", "WARNING"}:
        return "COACH"

    if upper in {"REVIEW", "ESCALATE", "FLAG"}:
        return "REVIEW"

    if upper in {"ALLOW", "PERMIT", "PASS"}:
        return "ALLOW"

    letters_only = re.sub(r"[^A-Z]", "", upper)

    if "BLOCK" in letters_only:
        return "BLOCK"

    if "COACH" in letters_only:
        return "COACH"

    if "ALLOW" in letters_only:
        return "ALLOW"

    return "ALLOW"


# -----------------------------
# Policy Engine Fix
# -----------------------------

def enforce_policy(label: str) -> str:
    """
    Deterministic policy enforcement
    """

    label = normalize_label(label)

    if label == "PII":
        return "BLOCK"

    if label == "CONFIDENTIAL":
        return "COACH"

    return "ALLOW"


# -----------------------------
# Main Evaluation
# -----------------------------

def main() -> None:

    ap = argparse.ArgumentParser()

    ap.add_argument("--data", required=True, help="dataset.jsonl path")
    ap.add_argument("--use_llm", type=int, default=1)
    ap.add_argument("--model", default="llama3.1:8b")
    ap.add_argument("--sleep", type=float, default=0.15)

    args = ap.parse_args()

    tp = fp = fn = tn = 0
    label_correct = 0
    action_correct = 0
    total = 0
    llm_failures = 0

    with open(args.data, "r", encoding="utf-8") as f:

        for line_num, line in enumerate(f, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                print(f"[Line {line_num}] Invalid JSON")
                continue

            event_data = rec.get("event")
            expected = rec.get("expected")

            if not event_data or not expected:
                print(f"[Line {line_num}] Missing fields")
                continue

            try:
                ev = DLPEvent(**event_data)
            except TypeError as e:
                print(f"[Line {line_num}] Event parse error: {e}")
                continue

            exp_label = normalize_label(expected.get("label"))
            exp_action = normalize_action(expected.get("action"))

            try:
                dec = analyze_event(
                    ev,
                    use_llm=bool(args.use_llm),
                    ollama_model=args.model
                )

            except Exception as e:

                llm_failures += 1
                print(f"[Line {line_num}] LLM failure ? deterministic fallback")

                dec = analyze_event(
                    ev,
                    use_llm=False,
                    ollama_model=args.model
                )

            if args.sleep > 0:
                time.sleep(args.sleep)

            pred_label = normalize_label(getattr(dec, "label", "BENIGN"))

            # enforce policy mapping
            pred_action = enforce_policy(pred_label)

            total += 1

            print(f"[Line {line_num}] Expected: {exp_label} / {exp_action}")
            print(f"[Line {line_num}] Predicted: {pred_label} / {pred_action}")
            print("-" * 60)

            if pred_label == exp_label:
                label_correct += 1

            if pred_action == exp_action:
                action_correct += 1

            exp_sensitive = exp_label in ("PII", "CONFIDENTIAL")
            pred_sensitive = pred_label in ("PII", "CONFIDENTIAL")

            if exp_sensitive and pred_sensitive:
                tp += 1
            elif not exp_sensitive and pred_sensitive:
                fp += 1
            elif exp_sensitive and not pred_sensitive:
                fn += 1
            else:
                tn += 1

    p = precision(tp, fp)
    r = recall(tp, fn)
    f = f1(p, r)

    label_acc = label_correct / total if total else 0
    policy_acc = action_correct / total if total else 0

    print("\n============================")
    print("Evaluation Summary")
    print("============================")

    print(f"Records: {total}")
    print(f"LLM failures: {llm_failures}")

    print("\nLabel Accuracy")
    print(f"{label_acc:.3f} ({label_correct}/{total})")

    print("\nPolicy Accuracy")
    print(f"{policy_acc:.3f} ({action_correct}/{total})")

    print("\nBinary Sensitive Detection")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"Precision={p:.3f}")
    print(f"Recall={r:.3f}")
    print(f"F1={f:.3f}")


if __name__ == "__main__":
    main()