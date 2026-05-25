from __future__ import annotations

from agents.dataflow_agent import DataFlowAgent
from agents.exploitability_agent import ExploitabilityAgent
from agents.fusion_agent import FusionDecisionAgent
from agents.model_score_agent import ModelScoreAgent
from agents.preprocess_agent import PreprocessAgent
from agents.rule_agent import RuleAgent
from agents.semantic_agent import SemanticAgent
from core.config import DEFAULT_AGENT_CHAIN, ScanConfig
from core.scanner import SourceScanner
from core.types import CandidateVulnerability, CodebaseIR, ScanReport
from models.factory import build_scorer
from rules.rule_loader import load_rules


class VulnerabilityDetectionPipeline:
    REQUIRED_ORDER = {name: index for index, name in enumerate(DEFAULT_AGENT_CHAIN)}

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.agent_chain = tuple(self.config.agent_chain or DEFAULT_AGENT_CHAIN)
        self._validate_agent_chain(self.agent_chain)
        rules = load_rules(self.config.rules_path)
        self.scanner = SourceScanner(
            max_files=self.config.max_scan_files,
            max_total_bytes=self.config.max_scan_bytes,
            max_file_bytes=self.config.max_file_bytes,
        )
        self.preprocess_agent = PreprocessAgent(self.config.parser_backend)
        self.rule_agent = RuleAgent(rules)
        self.model_score_agent = (
            ModelScoreAgent(
                build_scorer(
                    self.config.model_backend,
                    self.config.model_name,
                    self.config.model_path,
                    strict_model=self.config.strict_model,
                )
            )
            if "model_scoring" in self.agent_chain
            else None
        )
        self.dataflow_agent = DataFlowAgent()
        self.semantic_agent = SemanticAgent(enable_llm=self.config.enable_llm_semantics)
        self.exploitability_agent = ExploitabilityAgent()
        self.fusion_agent = FusionDecisionAgent()

    def run(self, source_path: str) -> ScanReport:
        files = self.scanner.collect(source_path)
        ir: CodebaseIR | None = None
        candidates: list[CandidateVulnerability] = []
        executed_agents: list[str] = []
        for agent_name in self.agent_chain:
            if agent_name == "preprocess":
                ir = self.preprocess_agent.run(files)
            elif agent_name == "rule_reasoning":
                candidates = self.rule_agent.run(self._require_ir(ir, agent_name))
            elif agent_name == "model_scoring":
                candidates = self._require_model_agent().run(candidates)
            elif agent_name == "dataflow_analysis":
                candidates = self.dataflow_agent.run(self._require_ir(ir, agent_name), candidates)
            elif agent_name == "semantic_reasoning":
                candidates = self.semantic_agent.run(candidates)
            elif agent_name == "exploitability_validation":
                candidates = self.exploitability_agent.run(candidates)
            elif agent_name == "fusion_decision":
                candidates = self.fusion_agent.run(candidates)
            executed_agents.append(agent_name)
        ir = self._require_ir(ir, "report_generation")
        reported = [item for item in candidates if item.final_confidence >= self.config.min_report_confidence]
        return ScanReport(
            source_path=source_path,
            summary={
                "files_scanned": len(files),
                "functions_discovered": len(ir.functions),
                "call_sites_discovered": len(ir.call_sites),
                "candidate_count": len(candidates),
                "reported_count": len(reported),
                "parser_backend": ir.parser_backend,
                "ast_nodes": len(ir.ast_nodes),
                "call_edges": len(ir.call_edges),
                "variable_refs": len(ir.variable_refs),
                "source_sink_nodes": len(ir.source_sink_nodes),
                "cfg_nodes": len(ir.cfg_nodes),
                "cfg_edges": len(ir.cfg_edges),
                "dfg_edges": len(ir.dfg_edges),
                "executed_agents": executed_agents,
            },
            vulnerabilities=reported,
            engine={
                "agents": executed_agents,
                "model_backend": self.config.model_backend,
                "model_name": self.config.model_name,
                "strict_model": self.config.strict_model,
                "llm_semantics": self.config.enable_llm_semantics,
                "rules_path": self.config.rules_path,
            },
        )

    def _validate_agent_chain(self, agent_chain: tuple[str, ...]) -> None:
        unknown = [name for name in agent_chain if name not in self.REQUIRED_ORDER]
        if unknown:
            raise ValueError(f"Unknown agent(s) in chain: {', '.join(unknown)}")
        if not agent_chain or agent_chain[0] != "preprocess":
            raise ValueError("Agent chain must start with preprocess")
        if "rule_reasoning" not in agent_chain:
            raise ValueError("Agent chain must include rule_reasoning")
        if "fusion_decision" not in agent_chain:
            raise ValueError("Agent chain must include fusion_decision")
        positions = [self.REQUIRED_ORDER[name] for name in agent_chain]
        if positions != sorted(positions):
            raise ValueError("Agent chain order must follow the documented detection flow")

    def _require_ir(self, ir: CodebaseIR | None, agent_name: str) -> CodebaseIR:
        if ir is None:
            raise RuntimeError(f"{agent_name} requires preprocess output")
        return ir

    def _require_model_agent(self) -> ModelScoreAgent:
        if self.model_score_agent is None:
            raise RuntimeError("model_scoring agent is not configured")
        return self.model_score_agent
