#!/usr/bin/env python3
"""
Prompt injection classifier using deberta-v3-base-prompt-injection-v2.
Called as subprocess from TypeScript. Reads content from stdin, outputs JSON.

Model: ProtectAI/deberta-v3-base-prompt-injection-v2
License: Apache 2.0
"""
import sys
import json

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
    import torch
except ImportError as e:
    print(json.dumps({"error": f"Missing dependency: {e}. Run: pip install torch transformers"}))
    sys.exit(1)

MODEL_NAME = "ProtectAI/deberta-v3-base-prompt-injection-v2"
_classifier = None

def get_classifier():
    global _classifier
    if _classifier is None:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
        device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
        _classifier = pipeline(
            "text-classification",
            model=model,
            tokenizer=tokenizer,
            truncation=True,
            max_length=512,
            device=device,
        )
    return _classifier

def classify(content: str) -> dict:
    classifier = get_classifier()
    result = classifier(content)[0]
    label = int(result["label"].split("_")[1])
    score = result["score"]
    return {"label": label, "score": round(score, 4), "injection": label == 1 and score > 0.5}

if __name__ == "__main__":
    content = sys.stdin.read().strip()
    if not content:
        print(json.dumps({"error": "No content provided"}))
        sys.exit(1)
    try:
        print(json.dumps(classify(content)))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
