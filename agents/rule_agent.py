from __future__ import annotations

import re

from core.types import CandidateVulnerability, CodebaseIR, Rule, RuleEvidence


class RuleAgent:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    def run(self, ir: CodebaseIR) -> list[CandidateVulnerability]:
        candidates: list[CandidateVulnerability] = []
        index = 1
        rules_by_sink = {rule.sink_pattern: rule for rule in self.rules}
        for call in ir.call_sites:
            rule = rules_by_sink.get(call.callee)
            if not rule:
                continue
            context = self._context_for(ir, call.file_path, call.line)
            candidates.append(
                CandidateVulnerability(
                    candidate_id=f"VULN-{index:04d}",
                    file_path=call.file_path,
                    line=call.line,
                    function_name=call.function_name,
                    code=call.code,
                    sink=call.callee,
                    arguments=call.arguments,
                    context=context,
                    rule_evidence=RuleEvidence(
                        rule_id=rule.rule_id,
                        cwe=rule.cwe,
                        owasp=rule.owasp,
                        name=rule.name,
                        severity=rule.severity,
                        description=rule.description,
                        recommendation=rule.recommendation,
                        matched_text=self._matched_text(call.code, call.callee),
                        tags=rule.tags,
                    ),
                )
            )
            index += 1
        return candidates

    def _context_for(self, ir: CodebaseIR, file_path: str, line: int, radius: int = 4) -> str:
        source = next((item for item in ir.files if item.path == file_path), None)
        if not source:
            return ""
        start = max(1, line - radius)
        end = min(len(source.lines), line + radius)
        return "\n".join(f"{n}: {source.lines[n - 1]}" for n in range(start, end + 1))

    def _matched_text(self, code: str, sink: str) -> str:
        match = re.search(rf"\b{re.escape(sink)}\s*\([^;]*\)", code)
        return match.group(0) if match else code
