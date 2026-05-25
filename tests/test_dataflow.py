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
