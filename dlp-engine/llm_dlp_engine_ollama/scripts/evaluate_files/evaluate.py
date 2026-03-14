from __future__ import annotations

import argparse
import json
import time
from app.models import DLPEvent
from app.engine import analyze_event


def precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) else 0.0


def recall(tp: int, fn: int) -> float:
    return tp / (tp + fn) if (tp + fn) else 0.0


def f1(p: float, r: float) -> float:
    return (2 * p * r) / (p + r) if (p + r) else 0.0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Path to dataset.jsonl")
    ap.add_argument("--use_llm", type=int, default=1, help="1=use Ollama LLM, 0=deterministic only")
    ap.add_argument("--model", default="llama3.1:8b", help="Ollama model name")
    ap.add_argument("--sleep", type=float, default=0.15, help="Seconds to sleep between records (throttle)")
    args = ap.parse_args()

    tp = fp = fn = tn = 0
    action_correct = 0
    total = 0
    llm_failures = 0

    with open(args.data, "r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)

            ev = DLPEvent(**rec["event"])
            exp_label = rec["expected"]["label"]
            exp_action = rec["expected"]["action"]

            # Run analysis; if LLM causes an exception (timeout), fall back to deterministic
            try:
                dec = analyze_event(ev, use_llm=bool(args.use_llm), ollama_model=args.model)
            except Exception as e:
                llm_failures += 1
                dec = analyze_event(ev, use_llm=False, ollama_model=args.model)

            # Throttle to avoid overloading Ollama during batch eval
            if args.sleep > 0:
                time.sleep(args.sleep)

            total += 1

            # Policy correctness
            if dec.action == exp_action:
                action_correct += 1

            # Binary sensitive vs benign (for course metrics)
            exp_sensitive = exp_label in ("PII", "CONFIDENTIAL")
            pred_sensitive = dec.label in ("PII", "CONFIDENTIAL")

            if exp_sensitive and pred_sensitive:
                tp += 1
            elif (not exp_sensitive) and pred_sensitive:
                fp += 1
            elif exp_sensitive and (not pred_sensitive):
                fn += 1
            else:
                tn += 1

    p = precision(tp, fp)
    r = recall(tp, fn)
    f = f1(p, r)
    policy_acc = action_correct / total if total else 0.0

    print("=== Evaluation Summary ===")
    print(f"Records: {total}")
    print(f"Use LLM: {bool(args.use_llm)} (model={args.model})")
    print(f"Throttle sleep: {args.sleep}s")
    print(f"LLM failures (fell back to deterministic): {llm_failures}")
    print("")
    print("Binary sensitivity detection (PII/CONF vs BENIGN):")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"Precision={p:.3f} Recall={r:.3f} F1={f:.3f}")
    print("")
    print("Policy correctness (expected action match):")
    print(f"Accuracy={policy_acc:.3f} ({action_correct}/{total})")


if __name__ == "__main__":
    main()
