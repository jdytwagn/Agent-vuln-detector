from __future__ import annotations

from core.types import CandidateVulnerability, ModelScore
from models.input_builder import build_model_input
from models.scorer import VulnerabilityScorer


class MockScorer(VulnerabilityScorer):
    """Deterministic stand-in for CodeBERT/GraphCodeBERT style probability scoring."""

    HIGH_RISK_SINKS = {"gets", "system", "popen", "strcpy", "strcat", "sprintf"}

    def __init__(self, model_name: str = "mock-code-model") -> None:
        self.model_name = model_name

    def score(self, candidate: CandidateVulnerability) -> ModelScore:
        model_input = build_model_input(candidate)
        score = 0.35
        if candidate.sink in self.HIGH_RISK_SINKS:
            score += 0.28
        if any(token in model_input.context for token in ("argv", "stdin", "recv", "fgets", "scanf", "getenv")):
            score += 0.2
        if model_input.features.get("dataflow_reachable"):
            score += 0.08
        if any(token in model_input.context for token in ("strlen", "sizeof", "snprintf", "validate", "sanitize", "allowed")):
            score -= 0.18
        score = min(0.98, max(0.05, score))
        return ModelScore(
            score=round(score, 3),
            label="vulnerable" if score >= 0.55 else "needs_review",
            confidence=round(abs(score - 0.5) * 2, 3),
            model_name=self.model_name,
        )
