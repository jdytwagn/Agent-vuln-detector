from __future__ import annotations

import re

from agents.mitigations import INPUT_CALLS, mitigation_on_line
from core.types import CandidateVulnerability, CodebaseIR, DataFlowPath, FunctionInfo


CALL_RE = re.compile(r"\b(?P<callee>[A-Za-z_]\w*)\s*\((?P<args>[^;{}]*)\)")
SOURCE_PATTERNS = {
    "argv": re.compile(r"\bargv\s*\[|\bargc\b"),
    "stdin": re.compile(r"\b(stdin|scanf|fgets|gets)\b"),
    "file": re.compile(r"\b(fread|read|getline|fscanf)\b"),
    "network": re.compile(r"\b(recv|recvfrom|read_socket|socket_read)\b"),
    "environment": re.compile(r"\bgetenv\s*\("),
}
SANITIZER_RE = re.compile(r"\b(validate|sanitize|escape|is_allowed|whitelist_check|canonicalize_path)\s*\(")
ASSIGNMENT_RE = re.compile(r"\b(?P<dst>[A-Za-z_]\w*)\s*=\s*(?P<src>[^;]+);")


class DataFlowAgent:
    def run(self, ir: CodebaseIR, candidates: list[CandidateVulnerability]) -> list[CandidateVulnerability]:
        cross_file_calls = {(edge.caller, edge.callee, edge.caller_file, edge.line): edge.cross_file for edge in ir.call_edges}
        for candidate in candidates:
            function = self._find_function(ir, candidate.file_path, candidate.function_name)
            candidate.dataflow = self._analyze_candidate(candidate, function, ir.functions, cross_file_calls)
        return candidates

    def _analyze_candidate(
        self,
        candidate: CandidateVulnerability,
        function: FunctionInfo | None,
        functions: list[FunctionInfo],
        cross_file_calls: dict[tuple[str, str, str, int], bool],
    ) -> DataFlowPath:
        if not function:
            return DataFlowPath(reachable=False, sink=candidate.sink)
        sink_vars = self._argument_variables(candidate.arguments)

        if set(sink_vars) & set(function.parameters):
            cross = self._cross_function_path(function, functions, cross_file_calls, candidate)
            if cross:
                return cross

        tainted, source_name, steps = self._tainted_variables(function)
        sanitized, sanitizer = self._sanitizer_for(function, candidate.line, sink_vars, candidate.rule_evidence.filters)

        for var in sink_vars:
            if var in tainted:
                return DataFlowPath(
                    reachable=True,
                    source=source_name,
                    sink=candidate.sink,
                    steps=steps + [f"{var} 在第 {candidate.line} 行到达 {candidate.sink}"],
                    scope="intra_function",
                    sanitized=sanitized,
                    sanitizer=sanitizer,
                )

        direct_source = self._direct_source(candidate.code)
        if direct_source:
            return DataFlowPath(
                reachable=True,
                source=direct_source,
                sink=candidate.sink,
                steps=[f"{direct_source} 在第 {candidate.line} 行直接传入 {candidate.sink}"],
                scope="intra_function",
                sanitized=sanitized,
                sanitizer=sanitizer,
            )

        return DataFlowPath(
            reachable=False,
            sink=candidate.sink,
            steps=["轻量分析没有找到 source 到 sink 的路径。"],
            scope="none",
            sanitized=sanitized,
            sanitizer=sanitizer,
        )

    def _tainted_variables(self, function: FunctionInfo) -> tuple[set[str], str | None, list[str]]:
        tainted: set[str] = set(function.parameters)
        source_name = "function parameter" if function.parameters else None
        steps: list[str] = []
        observed_sources: set[str] = set()
        if function.parameters:
            steps.append(f"函数参数视为外部可控：{', '.join(function.parameters)}")

        for line in function.code.splitlines():
            for name, pattern in SOURCE_PATTERNS.items():
                if not pattern.search(line):
                    continue
                source_name = name
                if name not in observed_sources:
                    observed_sources.add(name)
                    steps.append(f"观察到来源 {name}：{line.strip()}")
                assigned = ASSIGNMENT_RE.search(line)
                if assigned:
                    tainted.add(assigned.group("dst"))
                for call in CALL_RE.finditer(line):
                    if call.group("callee") not in INPUT_CALLS:
                        continue
                    for variable in self._argument_variables([call.group("args")]):
                        tainted.add(variable)
            match = ASSIGNMENT_RE.search(line)
            source_identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", match.group("src"))) if match else set()
            if match and source_identifiers & tainted:
                tainted.add(match.group("dst"))
                steps.append(f"污点传播到 {match.group('dst')}：{line.strip()}")
            if SANITIZER_RE.search(line):
                steps.append(f"观察到可能的校验：{line.strip()}")
        return tainted, source_name, steps

    def _cross_function_path(
        self,
        function: FunctionInfo,
        functions: list[FunctionInfo],
        cross_file_calls: dict[tuple[str, str, str, int], bool],
        candidate: CandidateVulnerability,
    ) -> DataFlowPath | None:
        sink_vars = set(self._argument_variables(candidate.arguments))
        if not sink_vars:
            return None
        for caller in functions:
            if function.name not in caller.calls:
                continue
            tainted, source_name, steps = self._tainted_variables(caller)
            call_lines = [line.strip() for line in caller.code.splitlines() if re.search(rf"\b{function.name}\s*\(", line)]
            for line in call_lines:
                line_identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", line))
                if line_identifiers & tainted:
                    call_line_number = self._line_number_for(caller, line)
                    scope = (
                        "cross_file"
                        if cross_file_calls.get((caller.name, function.name, caller.file_path, call_line_number), False)
                        else "cross_function"
                    )
                    sanitized, sanitizer = self._sanitizer_for(function, candidate.line, sink_vars, candidate.rule_evidence.filters)
                    return DataFlowPath(
                        reachable=True,
                        source=source_name or "caller-controlled argument",
                        sink=candidate.sink,
                        steps=steps + [f"调用方 {caller.name} 把污点数据传给 {function.name}：{line}"],
                        scope=scope,
                        sanitized=sanitized,
                        sanitizer=sanitizer,
                    )
        return None

    def _argument_variables(self, arguments: list[str]) -> list[str]:
        variables: list[str] = []
        for arg in arguments:
            without_literals = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", arg)
            names = [
                name
                for name in re.findall(r"\b[A-Za-z_]\w*\b", without_literals)
                if name not in {"NULL", "nullptr", "sizeof", "const", "char", "int", "long", "unsigned"}
            ]
            variables.extend(names)
        return variables

    def _direct_source(self, code: str) -> str | None:
        for name, pattern in SOURCE_PATTERNS.items():
            if pattern.search(code):
                return name
        return None

    def _find_function(self, ir: CodebaseIR, file_path: str, name: str) -> FunctionInfo | None:
        return next((fn for fn in ir.functions if fn.file_path == file_path and fn.name == name), None)

    def _sanitizer_for(
        self,
        function: FunctionInfo,
        sink_line: int | None = None,
        variables: list[str] | set[str] | None = None,
        filters: list[str] | None = None,
    ) -> tuple[bool, str | None]:
        relevant_variables = {var for var in (variables or []) if var not in {"NULL", "sizeof"}}
        for offset, line in enumerate(function.code.splitlines(), start=function.start_line):
            if sink_line is not None and offset >= sink_line:
                break
            mitigation = mitigation_on_line(line, relevant_variables, filters)
            if mitigation:
                return True, mitigation
        return False, None

    def _line_number_for(self, function: FunctionInfo, stripped_line: str) -> int:
        for offset, line in enumerate(function.code.splitlines(), start=function.start_line):
            if line.strip() == stripped_line:
                return offset
        return function.start_line
