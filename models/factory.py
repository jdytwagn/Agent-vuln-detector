from __future__ import annotations

from models.codebert_scorer import CodeBERTScorer
from models.graphcodebert_scorer import GraphCodeBERTScorer
from models.mock_scorer import MockScorer
from models.scorer import VulnerabilityScorer


def build_scorer(
    backend: str,
    model_name: str,
    model_path: str | None = None,
    strict_model: bool = False,
) -> VulnerabilityScorer:
    normalized = backend.lower()
    if normalized == "codebert":
        return CodeBERTScorer(model_path=model_path or model_name, strict_model=strict_model)
    if normalized == "graphcodebert":
        return GraphCodeBERTScorer(model_path=model_path or model_name, strict_model=strict_model)
    if normalized == "mock":
        return MockScorer(model_name=model_name)
    raise ValueError(f"Unsupported model backend: {backend}")
