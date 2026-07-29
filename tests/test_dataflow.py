from __future__ import annotations

from pathlib import Path

from core.pipeline import VulnerabilityDetectionPipeline


SAMPLES = Path(__file__).parent / "samples"


def test_intra_function_and_cross_function_dataflow_are_reported() -> None:
    report = VulnerabilityDetectionPipeline().run(str(SAMPLES))
    system_findings = [item for item in report.vulnerabilities if item.sink == "system"]
    assert system_findings
    assert any(item.dataflow and item.dataflow.reachable for item in system_findings)
    assert any(item.dataflow and item.dataflow.scope in {"cross_function", "cross_file"} for item in system_findings)


def test_strlen_observation_alone_does_not_sanitize_copy(tmp_path: Path) -> None:
    source = tmp_path / "not_sanitized.c"
    source.write_text(
        "void f(char *input) {\n"
        "  char buffer[8];\n"
        "  strlen(input);\n"
        "  strcpy(buffer, input);\n"
        "}\n",
        encoding="utf-8",
    )

    report = VulnerabilityDetectionPipeline().run(str(source))
    finding = next(item for item in report.vulnerabilities if item.sink == "strcpy")

    assert finding.dataflow and finding.dataflow.reachable
    assert not finding.dataflow.sanitized
    assert finding.model_score and finding.model_score.score == 0.71
    assert finding.exploitability == "exploitable"
    assert finding.final_decision == "vulnerable"
