#!/usr/bin/env python3
"""
FastAPI server for DeBERTa prompt injection classification.
Keeps model warm in memory. Runs on port 8404.

Usage: .venv/bin/uvicorn injection_server:app --host 127.0.0.1 --port 8404
"""
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch

MODEL_NAME = "ProtectAI/deberta-v3-base-prompt-injection-v2"

app = FastAPI()

# Load model once at startup
print(f"Loading {MODEL_NAME}...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
classifier = pipeline(
    "text-classification",
    model=model,
    tokenizer=tokenizer,
    truncation=True,
    max_length=512,
    device=device,
)
print(f"Model loaded on {device}")

class ClassifyRequest(BaseModel):
    content: str

class ClassifyResponse(BaseModel):
    label: int
    score: float
    injection: bool

@app.post("/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest):
    result = classifier(req.content)[0]
    injection = result["label"] == "INJECTION"
    label = 1 if injection else 0
    score = round(result["score"], 4)
    return {"label": label, "score": score, "injection": injection and score > 0.5}

@app.get("/health")
def health():
    return {"status": "ok", "model": MODEL_NAME, "device": str(device)}
