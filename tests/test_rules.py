from __future__ import annotations

from pathlib import Path

from core.pipeline import VulnerabilityDetectionPipeline


SAMPLES = Path(__file__).parent / "samples"


def test_rule_agent_finds_dangerous_sinks() -> None:
    report = VulnerabilityDetectionPipeline().run(str(SAMPLES / "vulnerable.c"))
    sinks = {item.sink for item in report.vulnerabilities}
    assert "strcpy" in sinks
    assert "system" in sinks
    assert report.summary["candidate_count"] >= 2


def test_mitigated_case_is_filtered_or_lower_risk() -> None:
    report = VulnerabilityDetectionPipeline().run(str(SAMPLES / "mitigated.c"))
    strcpy = next(item for item in report.vulnerabilities if item.sink == "strcpy")
    assert strcpy.exploitability in {"not_exploitable", "uncertain"}
    assert strcpy.final_decision in {"filtered_false_positive", "needs_review", "low_risk"}
