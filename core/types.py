from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


Severity = Literal["low", "medium", "high", "critical"]
Exploitability = Literal["exploitable", "uncertain", "not_exploitable"]
TaskStatus = Literal["pending", "running", "completed", "failed"]


@dataclass
class SourceFile:
    path: str
    language: str
    content: str
    lines: list[str]


@dataclass
class FunctionInfo:
    name: str
    file_path: str
    start_line: int
    end_line: int
    code: str
    calls: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    return_type: str = "unknown"


@dataclass
class CallSite:
    function_name: str
    callee: str
    file_path: str
    line: int
    code: str
    arguments: list[str] = field(default_factory=list)


@dataclass
class AstNode:
    node_id: str
    kind: str
    file_path: str
    start_line: int
    end_line: int
    name: str = ""
    summary: str = ""


@dataclass
class CallEdge:
    caller: str
    callee: str
    caller_file: str
    callee_file: str | None
    line: int
    arguments: list[str] = field(default_factory=list)
    cross_file: bool = False


@dataclass
class VariableRef:
    name: str
    file_path: str
    function_name: str
    line: int
    access: Literal["definition", "assignment", "use", "parameter"]
    code: str


@dataclass
class SourceSinkNode:
    kind: Literal["source", "sink", "sanitizer"]
    name: str
    file_path: str
    function_name: str
    line: int
    code: str


@dataclass
class ControlFlowNode:
    node_id: str
    function_name: str
    file_path: str
    line: int
    kind: Literal["entry", "exit", "statement", "condition", "return", "call"]
    code: str = ""


@dataclass
class ControlFlowEdge:
    source_id: str
    target_id: str
    function_name: str
    edge_type: Literal["entry", "next", "branch_true", "branch_false", "return"]


@dataclass
class DataFlowEdge:
    source_var: str
    target_var: str
    source_line: int
    target_line: int
    function_name: str
    file_path: str
    edge_type: Literal["parameter", "definition_use", "assignment_use", "assignment"]
    code: str = ""


@dataclass
class CodebaseIR:
    files: list[SourceFile]
    functions: list[FunctionInfo]
    call_sites: list[CallSite]
    ast_nodes: list[AstNode] = field(default_factory=list)
    call_edges: list[CallEdge] = field(default_factory=list)
    variable_refs: list[VariableRef] = field(default_factory=list)
    source_sink_nodes: list[SourceSinkNode] = field(default_factory=list)
    cfg_nodes: list[ControlFlowNode] = field(default_factory=list)
    cfg_edges: list[ControlFlowEdge] = field(default_factory=list)
    dfg_edges: list[DataFlowEdge] = field(default_factory=list)
    parser_backend: str = "lightweight"


@dataclass
class Rule:
    rule_id: str
    cwe: str
    name: str
    severity: Severity
    sink_pattern: str
    description: str
    recommendation: str
    owasp: str = ""
    source_types: list[str] = field(default_factory=list)
    sink_types: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    filters: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class RuleEvidence:
    rule_id: str
    cwe: str
    owasp: str
    name: str
    severity: Severity
    description: str
    recommendation: str
    matched_text: str
    filters: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class ModelScore:
    score: float
    label: str
    confidence: float
    model_name: str


@dataclass
class ModelInput:
    candidate_id: str
    code: str
    context: str
    sink: str
    cwe: str
    features: dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlowPath:
    reachable: bool
    source: str | None = None
    sink: str | None = None
    steps: list[str] = field(default_factory=list)
    scope: Literal["none", "intra_function", "cross_function", "cross_file"] = "none"
    sanitized: bool = False
    sanitizer: str | None = None


@dataclass
class CandidateVulnerability:
    candidate_id: str
    file_path: str
    line: int
    function_name: str
    code: str
    sink: str
    arguments: list[str]
    context: str
    rule_evidence: RuleEvidence
    model_score: ModelScore | None = None
    dataflow: DataFlowPath | None = None
    semantic_explanation: str = ""
    exploitability: Exploitability = "uncertain"
    exploitability_reason: str = ""
    final_confidence: float = 0.0
    final_severity: Severity = "medium"
    final_decision: str = "candidate"


@dataclass
class ScanReport:
    source_path: str
    summary: dict[str, Any]
    vulnerabilities: list[CandidateVulnerability]
    engine: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationMetrics:
    dataset: str
    samples: int
    auc: float
    f1: float
    fpr: float
    alerts_per_kloc: float
    valid_ratio: float
    cross_file_recall: float
    exploitability_recall: float
    non_exploit_filter: float
    method: str = "Proposed Agent"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
