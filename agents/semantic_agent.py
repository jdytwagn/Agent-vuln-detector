from __future__ import annotations

from core.types import CandidateVulnerability
from models.deepseek_client import DeepSeekClient


class SemanticAgent:
    def __init__(self, enable_llm: bool = False, llm_client: DeepSeekClient | None = None) -> None:
        self.enable_llm = enable_llm
        self.llm_client = llm_client or DeepSeekClient()

    def run(self, candidates: list[CandidateVulnerability]) -> list[CandidateVulnerability]:
        for candidate in candidates:
            fallback = self._template_explanation(candidate)
            if self.enable_llm and self.llm_client.available:
                try:
                    llm_text = self.llm_client.analyze_candidate(candidate)
                    candidate.semantic_explanation = llm_text or fallback
                    continue
                except Exception as exc:
                    candidate.semantic_explanation = f"{fallback} 大模型语义推理失败，已改用模板解释：{exc}"
                    continue
            candidate.semantic_explanation = fallback
        return candidates

    def _template_explanation(self, candidate: CandidateVulnerability) -> str:
        dataflow = candidate.dataflow
        model = candidate.model_score
        parts = [
            f"规则 `{candidate.rule_evidence.name}` ({candidate.rule_evidence.cwe}) 命中了危险调用 `{candidate.sink}`。",
            candidate.rule_evidence.description,
        ]
        if dataflow and dataflow.reachable:
            parts.append(f"数据流证据显示存在 {dataflow.scope} 路径，来源为 {dataflow.source}，最终到达该 sink。")
            if dataflow.sanitized:
                parts.append(f"同时观察到潜在过滤或缓解逻辑：{dataflow.sanitizer}。")
        else:
            parts.append("当前轻量数据流分析尚未证明攻击者可控输入能够到达该 sink。")
        if model:
            parts.append(f"模型打分智能体输出标签 {model.label}，分数 {model.score}。")
        return " ".join(parts)
