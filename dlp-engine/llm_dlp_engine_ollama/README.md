# LLM-Powered DLP Engine (Local) — Ollama + FastAPI

This is a **local-first** DLP engine you can test on your laptop/desktop before deploying a proxy on AWS.
It uses a **hybrid** approach:
- Deterministic detectors (regex + validation + thresholds)
- Local LLM (Ollama) for context-aware classification + explanation
- Policy engine to map findings -> actions (ALLOW / COACH / BLOCK / QUARANTINE)

## Prerequisites
- Python 3.10+
- Ollama installed and running locally: https://ollama.com
- Pull a model (example): `ollama pull llama3.1:8b` (or another instruction model)

## Quick start
```bash
python -m venv .venv
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Try a demo request
```bash
python scripts/demo_request.py
```

## Generate dataset + evaluate
Generate a synthetic labeled dataset:
```bash
python scripts/generate_dataset.py --out data/dataset.jsonl --n_sensitive 40 --n_benign 40
```

Run evaluation:
```bash
python scripts/evaluate.py --data data/dataset.jsonl --use_llm 1
python scripts/evaluate.py --data data/dataset.jsonl --use_llm 0
```

## What you’ll connect later (AWS/mitmproxy)
- Your mitmproxy addon will extract request bodies/files and call `POST /analyze`.
- For HTTPS inspection in a lab, mitmproxy provides decrypted payloads after the Windows client trusts the mitmproxy CA.

## Layout
- `app/` FastAPI service + DLP engine modules
- `scripts/` dataset generator, evaluation, demo request
- `data/` generated datasets
