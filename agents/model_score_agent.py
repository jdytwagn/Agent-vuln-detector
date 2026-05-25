from __future__ import annotations

from core.types import CandidateVulnerability
from models.scorer import VulnerabilityScorer


class ModelScoreAgent:
    def __init__(self, scorer: VulnerabilityScorer) -> None:
        self.scorer = scorer

    def run(self, candidates: list[CandidateVulnerability]) -> list[CandidateVulnerability]:
        for candidate in candidates:
            candidate.model_score = self.scorer.score(candidate)
        return candidates
