from __future__ import annotations

from core.types import CandidateVulnerability, Severity


SEVERITY_BASE = {"low": 0.2, "medium": 0.35, "high": 0.55, "critical": 0.7}
MODEL_DISAGREEMENT_SCORE = 0.65


class FusionDecisionAgent:
    def run(self, candidates: list[CandidateVulnerability]) -> list[CandidateVulnerability]:
        for candidate in candidates:
            score = SEVERITY_BASE[candidate.rule_evidence.severity]
            if candidate.model_score:
                score += (candidate.model_score.score - 0.5) * 0.35
            if candidate.dataflow and candidate.dataflow.reachable:
                score += 0.25 if candidate.dataflow.scope == "intra_function" else 0.3
            if candidate.exploitability == "exploitable":
                score += 0.2
            elif candidate.exploitability == "not_exploitable":
                score -= 0.3

            score = min(0.99, max(0.0, score))
            candidate.final_confidence = round(score, 3)
            candidate.final_severity = self._severity(candidate.rule_evidence.severity, score)
            candidate.final_decision = self._decision(candidate, score)
        return candidates

    def _severity(self, rule_severity: Severity, score: float) -> Severity:
        if score >= 0.85:
            return "critical"
        if score >= 0.65:
            return "high"
        if score >= 0.35:
            return "medium"
        return "low" if rule_severity != "critical" else "medium"

    def _decision(self, candidate: CandidateVulnerability, score: float) -> str:
        model_score = candidate.model_score.score if candidate.model_score else 0.0
        if candidate.exploitability == "not_exploitable":
            if model_score >= MODEL_DISAGREEMENT_SCORE:
                return "needs_review"
            return "filtered_false_positive"
        if candidate.exploitability == "uncertain" and candidate.exploitability_reason:
            return "needs_review"
        if score >= 0.7:
            return "vulnerable"
        if score >= 0.35:
            return "needs_review"
        return "low_risk"
