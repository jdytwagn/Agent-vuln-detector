from __future__ import annotations

import json
from pathlib import Path

from core.types import ModelScore
from evaluation.model_baselines import ModelBaselineEvaluator


class FakeTextScorer:
    def score_text(self, text: str) -> ModelScore:
        score = 0.9 if "strcpy" in text else 0.1
        return ModelScore(score=score, label="vulnerable" if score > 0.5 else "safe", confidence=0.9, model_name="fake")


def test_model_baseline_scores_whole_sample_without_rule_pipeline(tmp_path: Path) -> None:
    vulnerable = tmp_path / "vulnerable.c"
    safe = tmp_path / "safe.c"
    vulnerable.write_text("void f(char *x) { char b[8]; strcpy(b, x); }", encoding="utf-8")
    safe.write_text("int add(int a, int b) { return a + b; }", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "dataset": "unit",
                "samples": [
                    {"sample_id": "v", "path": str(vulnerable), "label": 1, "loc": 1},
                    {"sample_id": "s", "path": str(safe), "label": 0, "loc": 1},
                ],
            }
        ),
        encoding="utf-8",
    )

    evaluator = ModelBaselineEvaluator.__new__(ModelBaselineEvaluator)
    evaluator.model_backend = "fake"
    evaluator.scorer = FakeTextScorer()

    result = evaluator.evaluate(str(manifest), threshold=0.5)

    assert result["metrics"]["auc"] == 1.0
    assert result["metrics"]["f1"] == 1.0
    assert result["metrics"]["alerts_per_kloc"] == 500.0
