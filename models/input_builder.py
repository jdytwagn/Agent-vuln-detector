from __future__ import annotations

from core.types import CandidateVulnerability, ModelInput


def build_model_input(candidate: CandidateVulnerability) -> ModelInput:
    dataflow = candidate.dataflow
    return ModelInput(
        candidate_id=candidate.candidate_id,
        code=candidate.code,
        context=candidate.context,
        sink=candidate.sink,
        cwe=candidate.rule_evidence.cwe,
        features={
            "rule_id": candidate.rule_evidence.rule_id,
            "severity": candidate.rule_evidence.severity,
            "owasp": candidate.rule_evidence.owasp,
            "arguments": candidate.arguments,
            "dataflow_reachable": bool(dataflow and dataflow.reachable),
            "dataflow_scope": dataflow.scope if dataflow else "none",
            "sanitized": bool(dataflow and dataflow.sanitized),
        },
    )
