from __future__ import annotations

import hashlib
import re

from core.types import (
    AstNode,
    CallEdge,
    CallSite,
    CodebaseIR,
    ControlFlowEdge,
    ControlFlowNode,
    DataFlowEdge,
    FunctionInfo,
    SourceFile,
    SourceSinkNode,
    VariableRef,
)


FUNCTION_RE = re.compile(
    r"^\s*(?P<ret>(?:static\s+|inline\s+|extern\s+)?(?:[A-Za-z_][\w\s\*\d]*?\s+)+)(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}]*)\)\s*\{"
)
CALL_RE = re.compile(r"\b(?P<callee>[A-Za-z_]\w*)\s*\((?P<args>[^;{}]*)\)")
FUNCTION_DECL_RE = re.compile(
    r"^\s*(?:static\s+|inline\s+|extern\s+)?(?:[A-Za-z_][\w\s\*\d]*?\s+)+[A-Za-z_]\w*\s*\([^;{}]*\)\s*;"
)
ASSIGN_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*=\s*[^;]+;")
DECL_RE = re.compile(r"\b(?:char|int|size_t|long|short|float|double|void|FILE)\s+\*?(?P<name>[A-Za-z_]\w*)")
IDENTIFIER_RE = re.compile(r"\b[A-Za-z_]\w*\b")
CONTROL_WORDS = {"if", "for", "while", "switch", "return", "sizeof"}
TYPE_WORDS = {"char", "int", "size_t", "long", "short", "float", "double", "void", "FILE", "static", "const", "unsigned", "signed", "return"}
SOURCE_NAMES = {"argv", "argc", "stdin", "scanf", "fgets", "gets", "fread", "read", "getline", "fscanf", "recv", "recvfrom", "getenv"}
SINK_NAMES = {"strcpy", "strcat", "sprintf", "gets", "system", "popen", "fopen", "malloc", "free", "printf"}
SANITIZER_NAMES = {"strlen", "sizeof", "snprintf", "strncpy", "strncat", "validate", "sanitize", "allowed", "whitelist", "realpath", "strncmp"}


class PreprocessAgent:
    """Builds a lightweight C/C++ intermediate representation."""

    def __init__(self, parser_backend: str = "lightweight") -> None:
        self.parser_backend = parser_backend

    def run(self, files: list[SourceFile]) -> CodebaseIR:
        functions: list[FunctionInfo] = []
        call_sites: list[CallSite] = []
        for source in files:
            file_functions = self._extract_functions(source)
            functions.extend(file_functions)
            call_sites.extend(self._extract_calls(source, file_functions))
        ast_nodes = self._build_ast_summary(functions)
        parser_backend = self.parser_backend
        if self.parser_backend == "tree-sitter":
            tree_nodes = self._tree_sitter_ast_nodes(files)
            if tree_nodes:
                ast_nodes.extend(tree_nodes)
            else:
                parser_backend = "lightweight"
        call_edges = self._build_call_edges(functions, call_sites)
        variable_refs = self._extract_variable_refs(functions)
        source_sink_nodes = self._extract_source_sink_nodes(call_sites)
        cfg_nodes, cfg_edges = self._build_cfg(functions)
        dfg_edges = self._build_dfg(functions)
        return CodebaseIR(
            files=files,
            functions=functions,
            call_sites=call_sites,
            ast_nodes=ast_nodes,
            call_edges=call_edges,
            variable_refs=variable_refs,
            source_sink_nodes=source_sink_nodes,
            cfg_nodes=cfg_nodes,
            cfg_edges=cfg_edges,
            dfg_edges=dfg_edges,
            parser_backend=parser_backend,
        )

    def _extract_functions(self, source: SourceFile) -> list[FunctionInfo]:
        functions: list[FunctionInfo] = []
        lines = source.lines
        index = 0
        while index < len(lines):
            match = FUNCTION_RE.match(lines[index])
            if not match:
                index += 1
                continue

            start = index
            brace_depth = lines[index].count("{") - lines[index].count("}")
            end = index
            while end + 1 < len(lines) and brace_depth > 0:
                end += 1
                brace_depth += lines[end].count("{") - lines[end].count("}")

            code_lines = lines[start : end + 1]
            parameters = self._parse_parameters(match.group("params"))
            calls = [c for c in self._find_call_names("\n".join(code_lines)) if c not in CONTROL_WORDS]
            functions.append(
                FunctionInfo(
                    name=match.group("name"),
                    file_path=source.path,
                    start_line=start + 1,
                    end_line=end + 1,
                    code="\n".join(code_lines),
                    calls=sorted(set(calls)),
                    parameters=parameters,
                    return_type=" ".join(match.group("ret").split()),
                )
            )
            index = end + 1
        return functions

    def _extract_calls(self, source: SourceFile, functions: list[FunctionInfo]) -> list[CallSite]:
        calls: list[CallSite] = []
        for line_number, line in enumerate(source.lines, start=1):
            if self._looks_like_function_signature(line):
                continue
            function_name = self._function_at_line(functions, source.path, line_number)
            if not function_name:
                function_name = "<global>"
            for match in CALL_RE.finditer(line):
                callee = match.group("callee")
                if callee in CONTROL_WORDS:
                    continue
                calls.append(
                    CallSite(
                        function_name=function_name,
                        callee=callee,
                        file_path=source.path,
                        line=line_number,
                        code=line.strip(),
                        arguments=self._split_arguments(match.group("args")),
                    )
                )
        return calls

    def _function_at_line(self, functions: list[FunctionInfo], file_path: str, line: int) -> str | None:
        for function in functions:
            if function.file_path == file_path and function.start_line <= line <= function.end_line:
                return function.name
        return None

    def _parse_parameters(self, params: str) -> list[str]:
        parsed: list[str] = []
        for param in self._split_arguments(params):
            bits = re.findall(r"[A-Za-z_]\w*", param)
            if bits and bits[-1] != "void":
                parsed.append(bits[-1])
        return parsed

    def _find_call_names(self, code: str) -> list[str]:
        calls: list[str] = []
        for line in code.splitlines():
            if self._looks_like_function_signature(line):
                continue
            calls.extend(match.group("callee") for match in CALL_RE.finditer(line))
        return calls

    def _looks_like_function_signature(self, line: str) -> bool:
        stripped = line.strip()
        return bool(FUNCTION_RE.match(stripped) or FUNCTION_DECL_RE.match(stripped))

    def _split_arguments(self, args: str) -> list[str]:
        if not args.strip():
            return []
        return [arg.strip() for arg in args.split(",") if arg.strip()]

    def _build_ast_summary(self, functions: list[FunctionInfo]) -> list[AstNode]:
        nodes: list[AstNode] = []
        for index, function in enumerate(functions, start=1):
            nodes.append(
                AstNode(
                    node_id=f"fn-{index}",
                    kind="function_definition",
                    file_path=function.file_path,
                    start_line=function.start_line,
                    end_line=function.end_line,
                    name=function.name,
                    summary=f"{function.return_type} {function.name}({', '.join(function.parameters)})",
                )
            )
        return nodes

    def _build_call_edges(self, functions: list[FunctionInfo], call_sites: list[CallSite]) -> list[CallEdge]:
        functions_by_name: dict[str, list[FunctionInfo]] = {}
        for function in functions:
            functions_by_name.setdefault(function.name, []).append(function)
        edges: list[CallEdge] = []
        for call in call_sites:
            callee_function = self._resolve_callee(functions_by_name.get(call.callee, []), call.file_path)
            caller_file = call.file_path
            callee_file = callee_function.file_path if callee_function else None
            edges.append(
                CallEdge(
                    caller=call.function_name,
                    callee=call.callee,
                    caller_file=caller_file,
                    callee_file=callee_file,
                    line=call.line,
                    arguments=call.arguments,
                    cross_file=bool(callee_file and callee_file != caller_file),
                )
            )
        return edges

    def _resolve_callee(self, candidates: list[FunctionInfo], caller_file: str) -> FunctionInfo | None:
        if not candidates:
            return None
        same_file = next((function for function in candidates if function.file_path == caller_file), None)
        return same_file or candidates[0]

    def _extract_variable_refs(self, functions: list[FunctionInfo]) -> list[VariableRef]:
        refs: list[VariableRef] = []
        for function in functions:
            for parameter in function.parameters:
                refs.append(
                    VariableRef(
                        name=parameter,
                        file_path=function.file_path,
                        function_name=function.name,
                        line=function.start_line,
                        access="parameter",
                        code=function.code.splitlines()[0].strip() if function.code else "",
                    )
                )
            for offset, line in enumerate(function.code.splitlines(), start=function.start_line):
                for match in DECL_RE.finditer(line):
                    refs.append(
                        VariableRef(match.group("name"), function.file_path, function.name, offset, "definition", line.strip())
                    )
                for match in ASSIGN_RE.finditer(line):
                    refs.append(
                        VariableRef(match.group("name"), function.file_path, function.name, offset, "assignment", line.strip())
                    )
                for name in self._identifiers(line):
                    if name not in function.calls and name != function.name:
                        refs.append(VariableRef(name, function.file_path, function.name, offset, "use", line.strip()))
        return refs

    def _extract_source_sink_nodes(self, call_sites: list[CallSite]) -> list[SourceSinkNode]:
        nodes: list[SourceSinkNode] = []
        for call in call_sites:
            if call.callee in SOURCE_NAMES:
                nodes.append(SourceSinkNode("source", call.callee, call.file_path, call.function_name, call.line, call.code))
            if call.callee in SINK_NAMES:
                nodes.append(SourceSinkNode("sink", call.callee, call.file_path, call.function_name, call.line, call.code))
            if call.callee in SANITIZER_NAMES:
                nodes.append(SourceSinkNode("sanitizer", call.callee, call.file_path, call.function_name, call.line, call.code))
        return nodes

    def _tree_sitter_ast_nodes(self, files: list[SourceFile]) -> list[AstNode]:
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_cpp

            parser = Parser(Language(tree_sitter_cpp.language()))
        except Exception:
            return []

        interesting = {"function_definition", "call_expression", "declaration", "assignment_expression", "if_statement"}
        nodes: list[AstNode] = []
        for source in files:
            tree = parser.parse(source.content.encode("utf-8", errors="ignore"))
            stack = [tree.root_node]
            while stack:
                node = stack.pop()
                if node.type in interesting:
                    start_line = node.start_point[0] + 1
                    end_line = node.end_point[0] + 1
                    text = source.lines[start_line - 1].strip() if source.lines and start_line <= len(source.lines) else node.type
                    nodes.append(
                        AstNode(
                            node_id=f"ts-{len(nodes) + 1}",
                            kind=node.type,
                            file_path=source.path,
                            start_line=start_line,
                            end_line=end_line,
                            summary=text[:160],
                        )
                    )
                stack.extend(node.children)
        return nodes

    def _build_cfg(self, functions: list[FunctionInfo]) -> tuple[list[ControlFlowNode], list[ControlFlowEdge]]:
        nodes: list[ControlFlowNode] = []
        edges: list[ControlFlowEdge] = []
        for function in functions:
            prefix = f"cfg-{self._file_key(function.file_path)}-{function.name}"
            entry_id = f"{prefix}-{function.start_line}-entry"
            exit_id = f"{prefix}-{function.end_line}-exit"
            nodes.append(ControlFlowNode(entry_id, function.name, function.file_path, function.start_line, "entry", "entry"))
            previous_id = entry_id
            previous_kind = "entry"
            executable_nodes: list[ControlFlowNode] = []
            for line_number, line in enumerate(function.code.splitlines(), start=function.start_line):
                stripped = line.strip()
                if not stripped or stripped in {"{", "}"}:
                    continue
                kind = self._cfg_kind(stripped)
                node = ControlFlowNode(
                    node_id=f"{prefix}-{line_number}",
                    function_name=function.name,
                    file_path=function.file_path,
                    line=line_number,
                    kind=kind,
                    code=stripped,
                )
                nodes.append(node)
                executable_nodes.append(node)
                edges.append(ControlFlowEdge(previous_id, node.node_id, function.name, "entry" if previous_id == entry_id else "next"))
                previous_id = node.node_id
                previous_kind = kind
            nodes.append(ControlFlowNode(exit_id, function.name, function.file_path, function.end_line, "exit", "exit"))
            if previous_id != entry_id:
                edges.append(ControlFlowEdge(previous_id, exit_id, function.name, "return" if previous_kind == "return" else "next"))
            else:
                edges.append(ControlFlowEdge(entry_id, exit_id, function.name, "next"))
            for index, node in enumerate(executable_nodes):
                if node.kind == "condition":
                    next_target = executable_nodes[index + 1].node_id if index + 1 < len(executable_nodes) else exit_id
                    edges.append(ControlFlowEdge(node.node_id, next_target, function.name, "branch_true"))
                    edges.append(ControlFlowEdge(node.node_id, exit_id, function.name, "branch_false"))
        return nodes, edges

    def _build_dfg(self, functions: list[FunctionInfo]) -> list[DataFlowEdge]:
        edges: list[DataFlowEdge] = []
        for function in functions:
            last_defs: dict[str, tuple[int, str]] = {
                param: (function.start_line, function.code.splitlines()[0].strip() if function.code else "")
                for param in function.parameters
            }
            for param, (line_number, code) in last_defs.items():
                edges.append(
                    DataFlowEdge(param, param, line_number, line_number, function.name, function.file_path, "parameter", code)
                )
            for line_number, line in enumerate(function.code.splitlines(), start=function.start_line):
                stripped = line.strip()
                assignment = ASSIGN_RE.search(stripped)
                identifiers = self._identifiers(stripped)
                for name in identifiers:
                    if name in last_defs and not (assignment and assignment.group("name") == name):
                        source_line, _ = last_defs[name]
                        edges.append(
                            DataFlowEdge(name, name, source_line, line_number, function.name, function.file_path, "definition_use", stripped)
                        )
                if assignment:
                    target = assignment.group("name")
                    for source in self._identifiers(assignment.group(0).split("=", 1)[1]):
                        if source in last_defs:
                            source_line, _ = last_defs[source]
                            edges.append(
                                DataFlowEdge(source, target, source_line, line_number, function.name, function.file_path, "assignment", stripped)
                            )
                    last_defs[target] = (line_number, stripped)
                for declaration in DECL_RE.finditer(stripped):
                    last_defs[declaration.group("name")] = (line_number, stripped)
        return edges

    def _cfg_kind(self, stripped: str) -> str:
        if stripped.startswith(("if", "while", "for", "switch")):
            return "condition"
        if stripped.startswith("return"):
            return "return"
        if CALL_RE.search(stripped):
            return "call"
        return "statement"

    def _identifiers(self, text: str) -> list[str]:
        return [
            name
            for name in IDENTIFIER_RE.findall(text)
            if name not in CONTROL_WORDS and name not in TYPE_WORDS and name not in SOURCE_NAMES and name not in SINK_NAMES
        ]

    def _file_key(self, file_path: str) -> str:
        return hashlib.sha1(file_path.encode("utf-8", errors="ignore")).hexdigest()[:10]
