from __future__ import annotations

import json
from pathlib import Path

import pytest

from evaluation.gnn_baseline import GnnBaselineEvaluator
from evaluation.suite import EvaluationSuite


pytest.importorskip("torch")


def _write_manifest(tmp_path: Path) -> Path:
    root = Path(__file__).resolve().parents[1] / "samples"
    manifest = {
        "dataset": "Tiny GNN Test",
        "samples": [
            {
                "sample_id": "vulnerable",
                "path": str(root / "vulnerable.c"),
                "label": 1,
                "loc": 16,
                "exploitable": True,
            },
            {
                "sample_id": "mitigated",
                "path": str(root / "mitigated.c"),
                "label": 0,
                "loc": 20,
                "non_exploitable": True,
            },
        ],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_gnn_baseline_runs_on_manifest(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    result = GnnBaselineEvaluator(epochs=1, hidden_dim=8, max_nodes=32).evaluate(str(manifest))

    assert result["metrics"]["method"] == "GNN Baseline"
    assert result["metrics"]["samples"] >= 1
    assert result["training"]["total_samples"] == 2
    assert result["training"]["epochs"] == 1
    assert 0 <= result["threshold"] <= 1


def test_evaluation_suite_can_skip_heavy_code_models(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    result = EvaluationSuite().run(str(manifest), include_code_models=False, gnn_epochs=1)

    assert "proposed_agent" in result["runs"]
    assert "graph_feature_baseline" in result["runs"]
    assert "gnn_baseline" in result["runs"]
    assert result["skipped"]["codebert"] == "disabled by --skip-code-models"
