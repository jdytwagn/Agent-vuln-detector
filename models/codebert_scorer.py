from __future__ import annotations

import json
from pathlib import Path

from core.env import get_env
from core.types import CandidateVulnerability, ModelScore
from models.input_builder import build_model_input
from models.mock_scorer import MockScorer
from models.scorer import VulnerabilityScorer


class CodeBERTScorer(VulnerabilityScorer):
    """CodeBERT-compatible sequence-classification scorer.

    Some fine-tuned vulnerability models publish only the classifier weights and
    config, while the tokenizer remains the base CodeBERT/GraphCodeBERT
    tokenizer. In that case we read `_name_or_path` from config.json and load
    the tokenizer from the base model automatically.
    """

    def __init__(self, model_path: str | None = None, strict_model: bool = False) -> None:
        self.model_path = model_path
        self.strict_model = strict_model
        self.fallback = MockScorer(model_name="codebert-placeholder")
        self.available = False
        self._pipeline = None
        configured_positive = get_env("AGENT_DETECTOR_MODEL_POSITIVE_LABEL").strip().lower()
        self._positive_labels: set[str] = {configured_positive} if configured_positive else set()
        self.load_error: str | None = None
        if model_path:
            try:
                from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer, pipeline

                config = AutoConfig.from_pretrained(model_path)
                inferred_labels = self._resolve_positive_labels(getattr(config, "id2label", None))
                self._positive_labels = self._positive_labels or inferred_labels
                if not self._positive_labels:
                    raise ValueError(
                        "Model uses ambiguous class labels. Set AGENT_DETECTOR_MODEL_POSITIVE_LABEL "
                        "to the exact vulnerable-class label."
                    )
                tokenizer_source = self._resolve_tokenizer_source(model_path, getattr(config, "_name_or_path", None))
                tokenizer = AutoTokenizer.from_pretrained(tokenizer_source)
                model = AutoModelForSequenceClassification.from_pretrained(model_path, config=config)
                self._pipeline = pipeline("text-classification", model=model, tokenizer=tokenizer)
                self.available = True
            except Exception as exc:
                self._pipeline = None
                self.available = False
                self.load_error = f"{type(exc).__name__}: {exc}"
                if self.strict_model:
                    raise RuntimeError(f"CodeBERT model failed to load in strict mode: {self.load_error}") from exc
        elif self.strict_model:
            raise RuntimeError("CodeBERT strict mode requires --model-path or a valid model id.")

    def _resolve_tokenizer_source(self, model_path: str, configured_source: str | None) -> str:
        path = Path(model_path)
        if path.exists():
            tokenizer_files = ("tokenizer.json", "vocab.json", "merges.txt", "tokenizer_config.json")
            if any((path / name).exists() for name in tokenizer_files):
                return model_path
            config_path = path / "config.json"
            if config_path.exists():
                data = json.loads(config_path.read_text(encoding="utf-8"))
                if data.get("_name_or_path"):
                    return str(data["_name_or_path"])
        return configured_source or model_path

    def _resolve_positive_labels(self, id2label: object) -> set[str]:
        if not isinstance(id2label, dict):
            return set()
        labels = {str(value).lower() for value in id2label.values()}
        positives = {
            label
            for label in labels
            if any(token in label for token in ("vulner", "unsafe", "buggy", "positive", "security"))
            and not any(token in label for token in ("non_vulner", "not_vulner", "safe", "negative"))
        }
        if positives:
            return positives
        return set()

    def score(self, candidate: CandidateVulnerability) -> ModelScore:
        if self._pipeline:
            try:
                model_input = build_model_input(candidate)
                text = "\n".join([model_input.cwe, model_input.sink, model_input.code, model_input.context])[:2000]
                return self.score_text(text)
            except Exception as exc:
                if self.strict_model:
                    raise RuntimeError(f"CodeBERT scoring failed in strict mode: {type(exc).__name__}: {exc}") from exc
                self.available = False
                self.load_error = f"{type(exc).__name__}: {exc}"
        return self.fallback.score(candidate)

    def score_text(self, text: str) -> ModelScore:
        if not self._pipeline:
            if self.strict_model:
                detail = f" ({self.load_error})" if self.load_error else ""
                raise RuntimeError(f"CodeBERT model is unavailable in strict mode{detail}")
            score = min(0.98, max(0.05, 0.35 + (0.35 if any(sink in text for sink in MockScorer.HIGH_RISK_SINKS) else 0.0)))
            return ModelScore(
                score=round(score, 3),
                label="vulnerable" if score >= 0.55 else "needs_review",
                confidence=round(abs(score - 0.5) * 2, 3),
                model_name=self.fallback.model_name,
            )
        result = self._pipeline(text, truncation=True, max_length=512)[0]
        confidence = float(result.get("score", 0.5))
        label = str(result.get("label", "needs_review")).lower()
        if not self._positive_labels:
            raise RuntimeError(
                "Unable to identify the vulnerable class from model config.id2label; "
                "configure descriptive labels such as vulnerable/safe."
            )
        vulnerable = confidence if label in self._positive_labels else 1.0 - confidence
        return ModelScore(
            score=round(max(0.0, min(1.0, vulnerable)), 3),
            label="vulnerable" if vulnerable >= 0.55 else "needs_review",
            confidence=round(confidence, 3),
            model_name=self.model_path or "codebert",
        )
