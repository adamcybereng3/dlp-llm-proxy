import json
import csv
import argparse
from app.models import DLPEvent
from app.engine import analyze_event

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Path to dataset.jsonl")
    ap.add_argument("--out", default="data/review_sheet.csv")
    ap.add_argument("--use_llm", type=int, default=1)
    ap.add_argument("--model", default="llama3.1:8b")
    ap.add_argument("--max_rows", type=int, default=0, help="0=all")
    args = ap.parse_args()

    rows_written = 0
    with open(args.data, "r", encoding="utf-8") as f, open(args.out, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow([
            "id",
            "file_name",
            "path",
            "destination",
            "expected_label",
            "expected_action",
            "pred_label",
            "pred_action",
            "risk_score",
            "llm_confidence",
            "top_reasons",
            "excerpt",
            "human_label",
            "human_action",
            "is_pred_correct",
            "review_notes"
        ])

        for line in f:
            rec = json.loads(line)
            ev = DLPEvent(**rec["event"])
            exp_label = rec["expected"]["label"]
            exp_action = rec["expected"]["action"]
            meta = rec["event"].get("metadata", {})
            fname = meta.get("filename", "")
            path = meta.get("path", "")
            dest = rec["event"].get("destination", "")

            dec = analyze_event(ev, use_llm=bool(args.use_llm), ollama_model=args.model)

            excerpt = (ev.extracted_text or "").replace("\n", "\\n")[:250]

            # keep reasons short for CSV readability
            reasons = " | ".join((dec.reasons or [])[:3])

            writer.writerow([
                rec.get("id",""),
                fname,
                path,
                dest,
                exp_label,
                exp_action,
                dec.label,
                dec.action,
                dec.risk_score,
                dec.confidence,
                reasons,
                excerpt,
                "",  # human_label
                "",  # human_action
                "",  # is_pred_correct (Y/N)
                ""   # review_notes
            ])

            rows_written += 1
            if args.max_rows and rows_written >= args.max_rows:
                break

    print(f"Wrote review sheet: {args.out} ({rows_written} rows)")

if __name__ == "__main__":
    main()
