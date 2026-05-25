from __future__ import annotations

from pathlib import Path

from agents.preprocess_agent import PreprocessAgent
from core.scanner import SourceScanner


SAMPLES = Path(__file__).parent / "samples"


def test_function_signatures_are_not_call_sites_and_cross_file_edges_are_preserved() -> None:
    ir = PreprocessAgent().run(SourceScanner().collect(str(SAMPLES)))

    self_signature_calls = [
        call
        for call in ir.call_sites
        if call.callee == call.function_name and call.code.strip().endswith("{")
    ]
    assert not self_signature_calls

    cross_file_edges = [
        edge
        for edge in ir.call_edges
        if edge.caller == "main" and edge.callee == "run_command" and edge.cross_file
    ]
    assert cross_file_edges
    assert cross_file_edges[0].caller_file.endswith("cross_file_a.c")

    cfg_ids = [node.node_id for node in ir.cfg_nodes]
    assert len(cfg_ids) == len(set(cfg_ids))
