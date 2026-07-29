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
            if not rule or not self._meets_rule_preconditions(ir, call.file_path, call.line, call.function_name, call.callee, call.arguments):
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

    def _meets_rule_preconditions(
        self,
        ir: CodebaseIR,
        file_path: str,
        line: int,
        function_name: str,
        sink: str,
        arguments: list[str],
    ) -> bool:
        first_argument = arguments[0].strip() if arguments else ""
        is_literal = bool(re.match(r'^(?:u8|u|U|L)?["\']', first_argument))
        if sink in {"printf", "system", "popen", "fopen"} and is_literal:
            return False

        function = next(
            (item for item in ir.functions if item.file_path == file_path and item.name == function_name),
            None,
        )
        if function is None:
            return sink not in {"malloc", "free"}
        following = self._following_code(function.code, function.start_line, line, sink)

        if sink == "malloc":
            source = next((item for item in ir.files if item.path == file_path), None)
            call_line = source.lines[line - 1] if source and line <= len(source.lines) else ""
            assignment = re.search(r"\b(?P<name>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(", call_line)
            if not assignment:
                return False
            name = assignment.group("name")
            dereference = re.search(rf"(?:\*\s*{re.escape(name)}\b|\b{re.escape(name)}\s*(?:->|\[))", following)
            if not dereference:
                return False
            before_dereference = following[: dereference.start()]
            null_check = re.search(
                rf"\bif\s*\([^)]*(?:!\s*{re.escape(name)}\b|\b{re.escape(name)}\s*(?:!=|==)\s*(?:NULL|0|nullptr))",
                before_dereference,
            )
            return null_check is None

        if sink == "free":
            pointer = first_argument.strip("*&() ")
            if not re.fullmatch(r"[A-Za-z_]\w*", pointer):
                return False
            double_free = re.search(rf"\bfree\s*\(\s*{re.escape(pointer)}\s*\)", following)
            use_after_free = re.search(
                rf"(?:\*\s*{re.escape(pointer)}\b|\b{re.escape(pointer)}\s*(?:->|\[))",
                following,
            )
            return bool(double_free or use_after_free)
        return True

    def _following_code(self, code: str, start_line: int, line: int, sink: str) -> str:
        lines = code.splitlines()
        current_index = max(0, line - start_line)
        if current_index >= len(lines):
            return ""
        current = lines[current_index]
        call_start = current.find(sink)
        tail = ""
        if call_start >= 0:
            open_paren = current.find("(", call_start + len(sink))
            if open_paren >= 0:
                depth = 0
                for index in range(open_paren, len(current)):
                    if current[index] == "(":
                        depth += 1
                    elif current[index] == ")":
                        depth -= 1
                        if depth == 0:
                            tail = current[index + 1 :]
                            break
        return "\n".join([tail, *lines[current_index + 1 :]])

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
