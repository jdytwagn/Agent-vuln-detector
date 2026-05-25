from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


DEFAULT_AGENT_CHAIN = (
    "preprocess",
    "rule_reasoning",
    "model_scoring",
    "dataflow_analysis",
    "semantic_reasoning",
    "exploitability_validation",
    "fusion_decision",
)


@dataclass
class ScanConfig:
    rules_path: str = str(Path(__file__).resolve().parents[1] / "rules" / "cwe_rules.yaml")
    model_backend: str = "mock"
    model_name: str = "mock-code-model"
    model_path: str | None = None
    strict_model: bool = False
    parser_backend: str = "tree-sitter"
    agent_chain: tuple[str, ...] = DEFAULT_AGENT_CHAIN
    min_report_confidence: float = 0.25
    storage_dir: str = str(Path(__file__).resolve().parents[1] / "storage")
    enable_llm_semantics: bool = False
    max_scan_files: int = 5000
    max_scan_bytes: int = 50 * 1024 * 1024
    max_file_bytes: int = 2 * 1024 * 1024
