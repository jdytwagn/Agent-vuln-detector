from __future__ import annotations

from evaluation.evaluator import DatasetEvaluator
from evaluation.metrics import auc_score, compute_metrics, f1_score, false_positive_rate


def test_metric_helpers() -> None:
    labels = [1, 0, 1, 0]
    scores = [0.9, 0.2, 0.7, 0.4]
    predictions = [1, 0, 1, 1]
    assert auc_score(labels, scores) == 1.0
    assert f1_score(labels, predictions) > 0.7
    assert false_positive_rate(labels, predictions) == 0.5


def test_valid_ratio_is_sample_precision() -> None:
    metrics = compute_metrics(
        dataset="precision",
        labels=[1, 0, 1, 0],
        scores=[0.9, 0.8, 0.2, 0.1],
        predictions=[1, 1, 0, 0],
        alerts=10,
        total_loc=1000,
        cross_file_mask=[False, False, False, False],
        exploitable_mask=[True, False, True, False],
        non_exploit_mask=[False, True, False, True],
        filtered_non_exploit=1,
    )

    assert metrics.valid_ratio == 0.5


def test_sample_manifest_evaluation_runs() -> None:
    metrics = DatasetEvaluator().evaluate("evaluation/sample_manifest.json")
    assert metrics.samples == 3
    assert metrics.alerts_per_kloc > 0
