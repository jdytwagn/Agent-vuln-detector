from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.config import ScanConfig
from core.pipeline import VulnerabilityDetectionPipeline
from reports.json_reporter import JsonReporter
from reports.markdown_reporter import MarkdownReporter


SAMPLES = Path(__file__).parent / "samples"


def test_pipeline_generates_json_and_markdown_reports(tmp_path: Path) -> None:
    report = VulnerabilityDetectionPipeline().run(str(SAMPLES / "vulnerable.c"))
    json_path = JsonReporter().write(report, str(tmp_path / "report.json"))
    md_path = MarkdownReporter().write(report, str(tmp_path / "report.md"))

    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    markdown = Path(md_path).read_text(encoding="utf-8")

    assert data["summary"]["reported_count"] >= 2
    assert "Agent Vulnerability Detection Report" in markdown
    assert "Semantic explanation" in markdown


def test_pipeline_supports_configurable_agent_chain() -> None:
    config = ScanConfig(agent_chain=("preprocess", "rule_reasoning", "fusion_decision"))
    report = VulnerabilityDetectionPipeline(config).run(str(SAMPLES / "vulnerable.c"))

    assert report.engine["agents"] == ["preprocess", "rule_reasoning", "fusion_decision"]
    assert report.summary["executed_agents"] == ["preprocess", "rule_reasoning", "fusion_decision"]
    assert report.summary["reported_count"] >= 1


def test_pipeline_rejects_invalid_agent_chain() -> None:
    config = ScanConfig(agent_chain=("rule_reasoning", "preprocess", "fusion_decision"))

    with pytest.raises(ValueError):
        VulnerabilityDetectionPipeline(config)
