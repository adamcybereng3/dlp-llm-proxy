import json
import random
import argparse
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="data/train_from_samples.jsonl")
    ap.add_argument("--train", default="data/train.jsonl")
    ap.add_argument("--test", default="data/test.jsonl")
    ap.add_argument("--ratio", type=float, default=0.8, help="train split ratio")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed)

    src_path = Path(args.src)
    rows = [json.loads(line) for line in src_path.open("r", encoding="utf-8")]

    random.shuffle(rows)
    cut = int(args.ratio * len(rows))

    Path(args.train).parent.mkdir(parents=True, exist_ok=True)
    Path(args.test).parent.mkdir(parents=True, exist_ok=True)

    with open(args.train, "w", encoding="utf-8") as f:
        for r in rows[:cut]:
            f.write(json.dumps(r) + "\n")

    with open(args.test, "w", encoding="utf-8") as f:
        for r in rows[cut:]:
            f.write(json.dumps(r) + "\n")

    print(f"train: {cut}  test: {len(rows)-cut}  total: {len(rows)}")
    print(f"Wrote: {args.train}")
    print(f"Wrote: {args.test}")

if __name__ == "__main__":
    main()
