from __future__ import annotations

import json
import urllib.request

from core.env import get_env
from core.types import CandidateVulnerability


class DeepSeekClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None, model: str | None = None, timeout: int = 30) -> None:
        self.api_key = api_key or get_env("DEEPSEEK_API_KEY")
        self.base_url = (base_url or get_env("DEEPSEEK_BASE_URL", "https://api.deepseek.com")).rstrip("/")
        self.model = model or get_env("DEEPSEEK_MODEL", "deepseek-v4-flash")
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.api_key and self.base_url and self.model)

    def analyze_candidate(self, candidate: CandidateVulnerability) -> str:
        if not self.available:
            return ""
        prompt = self._build_prompt(candidate)
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "你是代码漏洞审计智能体。请基于规则证据、模型分数、数据流和可利用性线索，"
                        "用中文给出简洁、结构化、可追溯的漏洞语义分析。不要编造不存在的证据。"
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()

    def _build_prompt(self, candidate: CandidateVulnerability) -> str:
        dataflow = candidate.dataflow
        model = candidate.model_score
        return "\n".join(
            [
                f"候选编号：{candidate.candidate_id}",
                f"位置：{candidate.file_path}:{candidate.line}，函数：{candidate.function_name}",
                f"CWE：{candidate.rule_evidence.cwe}，规则：{candidate.rule_evidence.name}",
                f"危险调用：{candidate.sink}，参数：{', '.join(candidate.arguments)}",
                f"规则证据：{candidate.rule_evidence.description}",
                f"模型分数：{model.score if model else 'N/A'}，标签：{model.label if model else 'N/A'}",
                f"数据流可达：{dataflow.reachable if dataflow else False}",
                f"数据流范围：{dataflow.scope if dataflow else 'none'}",
                f"数据流步骤：{'; '.join(dataflow.steps) if dataflow else 'N/A'}",
                f"是否观察到过滤/缓解：{dataflow.sanitized if dataflow else False} {dataflow.sanitizer if dataflow else ''}",
                "代码上下文：",
                candidate.context[:2400],
                "请输出：1. 漏洞语义判断；2. 证据链；3. 可利用性倾向；4. 修复建议。",
            ]
        )
