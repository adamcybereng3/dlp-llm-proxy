from __future__ import annotations

from fastapi import FastAPI
from .models import DLPEvent, DLPDecision
from .engine import analyze_event

app = FastAPI(title="LLM-Powered DLP Engine (Local)", version="0.1.0")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze", response_model=DLPDecision)
def analyze(event: DLPEvent, use_llm: int = 1, model: str = "llama3.1:8b"):
    return analyze_event(event, use_llm=bool(use_llm), ollama_model=model)
