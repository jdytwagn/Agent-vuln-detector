from __future__ import annotations

from models.codebert_scorer import CodeBERTScorer


class GraphCodeBERTScorer(CodeBERTScorer):
    """Same inference contract as CodeBERT, configured for GraphCodeBERT weights."""

    def __init__(self, model_path: str | None = None, strict_model: bool = False) -> None:
        super().__init__(model_path, strict_model=strict_model)
        self.fallback.model_name = "graphcodebert-placeholder"
