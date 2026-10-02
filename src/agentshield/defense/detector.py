"""Prompt-injection detectors: score a piece of text for injected instructions.

Three implementations share one interface, ``score(texts) -> list[float]``:

- ``HeuristicDetector``: regexes for well-known injection phrasing. No deps.
- ``TfidfDetector``: any pickled scikit-learn text pipeline with ``predict_proba``.
- ``TransformerDetector``: a fine-tuned HF classifier, e.g. DistilBERT (``pip install agent-shield[detector]``).

``load_detector()`` picks one by name. AgentShield does not ship trained
weights; point the transformer detector at any sequence classifier whose
positive label is ``INJECTION`` (or ``LABEL_1``).
"""

from __future__ import annotations

import pickle
import hashlib
import json
import re
from pathlib import Path
from typing import Protocol


class Detector(Protocol):
    name: str

    def score(self, texts: list[str]) -> list[float]: ...


class HeuristicDetector:
    """Keyword/regex baseline. Catches textbook attacks, misses paraphrases and other languages."""

    name = "heuristic"
    PATTERNS = [
        r"\bignore\b.{0,40}\b(previous|prior|above|all|earlier|your)\b.{0,40}\b(instructions?|prompts?|rules|directions)",
        r"\b(disregard|forget|override)\b.{0,40}\b(instructions?|prompts?|rules|guidelines|system)",
        r"\b(new|updated|revised|real)\s+(instructions?|task|directive|system prompt)\b",
        r"\byou are now\b|\bact as\b|\bpretend (to be|you are)\b|\bfrom now on\b",
        r"\b(system|admin|developer)\s*(prompt|message|override|note|instruction)\s*[:\]]",
        r"\[(system|inst|admin)\]|<\s*/?\s*(system|instructions?|im_start|im_end)\s*>|<\|im_start\|>",
        r"\b(ai|llm|assistant|agent|model|language model|bot)s?\b.{0,60}\b(must|should|need to|are required to|please)\b",
        r"\bdo not (tell|inform|mention|reveal|alert)\b.{0,30}\b(user|anyone|human)",
        r"\b(send|forward|email|post|upload|exfiltrate)\b.{0,60}\b(password|code|secret|key|token|credential|\.env)",
        r"\bimportant (message|instructions?)\b.{0,40}\b(from|for)\b",
        r"\bbefore (you|doing|completing|finishing)\b.{0,40}\b(task|anything|request)",
    ]

    def __init__(self) -> None:
        self.regexes = [re.compile(p, re.I | re.S) for p in self.PATTERNS]

    def score(self, texts: list[str]) -> list[float]:
        out = []
        for t in texts:
            hits = sum(1 for r in self.regexes if r.search(t))
            out.append(min(1.0, 0.6 * hits))
        return out


class TfidfDetector:
    name = "tfidf-logreg"

    def __init__(self, path: str | Path):
        self.identity = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        with open(path, "rb") as f:
            self.pipeline = pickle.load(f)  # only load pickles you created yourself

    def score(self, texts: list[str]) -> list[float]:
        if not texts:
            return []
        return [float(p) for p in self.pipeline.predict_proba(texts)[:, 1]]


class TransformerDetector:
    """A fine-tuned sequence classifier. Long inputs are scored in overlapping windows; the max wins."""

    def __init__(self, path: str | Path, device: str | None = None, max_length: int = 256, stride: int = 64,
                 batch_size: int = 16):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.name = Path(path).name
        self.identity = str(path)
        weights = Path(path) / 'model.safetensors'
        if weights.is_file():
            with weights.open('rb') as handle:
                digest = hashlib.sha256()
                for chunk in iter(lambda: handle.read(1024*1024), b''):
                    digest.update(chunk)
                self.identity = digest.hexdigest()
        self.tok = AutoTokenizer.from_pretrained(str(path))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(path)).eval()
        self.identity += ':' + hashlib.sha256(json.dumps({
            'config':self.model.config.to_dict(), 'vocabulary':self.tok.get_vocab(),
            'special_tokens':self.tok.special_tokens_map,
        },sort_keys=True,default=str).encode()).hexdigest()
        if device is None:
            device = "mps" if torch.backends.mps.is_available() else "cuda" if torch.cuda.is_available() else "cpu"
        self.device = device
        self.model.to(device)
        self.max_length, self.stride, self.batch_size = max_length, stride, batch_size
        self.inference_config = dict(max_length=max_length,stride=stride,batch_size=batch_size,device=device)
        labels = {v.lower(): k for k, v in self.model.config.id2label.items()}
        self.pos = labels.get("injection", labels.get("label_1", 1))

    def score(self, texts: list[str]) -> list[float]:
        if not texts:
            return []
        torch = self.torch
        enc = self.tok(texts, truncation=True, max_length=self.max_length, stride=self.stride,
                       return_overflowing_tokens=True, padding=True, return_tensors="pt")
        owner = enc.pop("overflow_to_sample_mapping").tolist()
        enc.pop("offset_mapping", None)
        probs: list[float] = []
        with torch.no_grad():
            for i in range(0, len(owner), self.batch_size):
                batch = {k: v[i:i + self.batch_size].to(self.device) for k, v in enc.items()}
                logits = self.model(**batch).logits.float()
                probs += torch.softmax(logits, dim=-1)[:, self.pos].cpu().tolist()
        out = [0.0] * len(texts)
        for o, p in zip(owner, probs):
            out[o] = max(out[o], p)
        return out


def load_detector(name: str = "heuristic", path: str | Path | None = None, **kw) -> Detector:
    """Build a detector.

    ``heuristic``           built-in regex baseline (no dependencies)
    ``tfidf``               a scikit-learn pipeline pickled at ``path`` (must expose predict_proba)
    anything else           a Hugging Face sequence-classification model id or local directory,
                            e.g. one you fine-tuned; needs ``pip install agent-shield[detector]``
    """
    if name == "heuristic":
        return HeuristicDetector()
    if name == "tfidf":
        if path is None:
            raise ValueError("tfidf detector needs path= to a pickled scikit-learn pipeline")
        return TfidfDetector(path)
    return TransformerDetector(path or name, **kw)
