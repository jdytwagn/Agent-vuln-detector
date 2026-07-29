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


def test_tree_sitter_handles_multiline_functions_nested_calls_and_comments(tmp_path: Path) -> None:
    source = tmp_path / "multiline.c"
    source.write_text(
        "void\ncopy_value(char *input)\n{\n"
        "  char buffer[8];\n"
        "  // strcpy(buffer, input);\n"
        "  if (input) { strcpy(buffer, input); }\n"
        "}\n",
        encoding="utf-8",
    )

    ir = PreprocessAgent("tree-sitter").run(SourceScanner().collect(str(source)))

    assert [(function.name, function.parameters) for function in ir.functions] == [("copy_value", ["input"])]
    strcpy_calls = [call for call in ir.call_sites if call.callee == "strcpy"]
    assert len(strcpy_calls) == 1
    assert strcpy_calls[0].function_name == "copy_value"
    assert strcpy_calls[0].arguments == ["buffer", "input"]
