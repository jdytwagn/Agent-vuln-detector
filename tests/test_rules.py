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


def test_high_model_score_cannot_confirm_mitigated_sink(monkeypatch) -> None:
    from core.types import ModelScore
    from models.mock_scorer import MockScorer

    def score(self, candidate):
        return ModelScore(score=0.95, label="vulnerable", confidence=0.9, model_name="stub-high")

    monkeypatch.setattr(MockScorer, "score", score)
    report = VulnerabilityDetectionPipeline().run(str(SAMPLES / "mitigated.c"))
    strcpy = next(item for item in report.vulnerabilities if item.sink == "strcpy")

    assert strcpy.exploitability == "not_exploitable"
    assert strcpy.final_decision == "needs_review"
    assert report.summary["confirmed_count"] == 0
    assert report.summary["review_count"] == 1
    assert report.summary["filtered_count"] == 0


def test_mitigated_case_is_filtered_or_lower_risk() -> None:
    report = VulnerabilityDetectionPipeline().run(str(SAMPLES / "mitigated.c"))
    strcpy = next(item for item in report.vulnerabilities if item.sink == "strcpy")
    assert strcpy.exploitability in {"not_exploitable", "uncertain"}
    assert strcpy.final_decision in {"filtered_false_positive", "needs_review", "low_risk"}
    if strcpy.final_decision == "filtered_false_positive":
        assert report.summary["reported_count"] == 0
        assert report.summary["filtered_count"] == 1


def test_literal_copy_is_not_reported_and_unbounded_copies_are(tmp_path: Path) -> None:
    source = tmp_path / "copies.c"
    source.write_text(
        "void literal_copy(void) {\n"
        "  char buffer[16];\n"
        "  strcpy(buffer, \"hello\");\n"
        "}\n"
        "void raw_copy(char *input) {\n"
        "  char buffer[8];\n"
        "  memcpy(buffer, input, 64);\n"
        "  scanf(\"%s\", buffer);\n"
        "  scanf(\"%10s\", buffer);\n"
        "}\n",
        encoding="utf-8",
    )

    report = VulnerabilityDetectionPipeline().run(str(source))
    sinks = [item.sink for item in report.vulnerabilities]

    assert "strcpy" not in sinks
    assert sinks.count("memcpy") == 1
    assert sinks.count("scanf") == 1


def test_literal_printf_and_checked_allocation_are_not_vulnerabilities(tmp_path: Path) -> None:
    source = tmp_path / "safe_calls.c"
    source.write_text(
        '#include <stdio.h>\n#include <stdlib.h>\n'
        'void f(char *input) {\n'
        '  printf("%s", input);\n'
        '  char *value = malloc(8);\n'
        '  if (value != NULL) free(value);\n'
        '}\n',
        encoding="utf-8",
    )

    report = VulnerabilityDetectionPipeline().run(str(source))

    assert not {item.sink for item in report.vulnerabilities} & {"printf", "malloc", "free"}


def test_nonliteral_printf_is_still_reported(tmp_path: Path) -> None:
    source = tmp_path / "format.c"
    source.write_text("void f(char *input) { printf(input); }\n", encoding="utf-8")

    report = VulnerabilityDetectionPipeline().run(str(source))

    assert any(item.sink == "printf" for item in report.vulnerabilities)
