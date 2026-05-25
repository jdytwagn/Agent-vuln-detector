from __future__ import annotations

from abc import ABC, abstractmethod

from core.types import CandidateVulnerability, ModelScore


class VulnerabilityScorer(ABC):
    @abstractmethod
    def score(self, candidate: CandidateVulnerability) -> ModelScore:
        raise NotImplementedError
