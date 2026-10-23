from __future__ import annotations

from core.types import EvaluationMetrics


def auc_score(labels: list[int], scores: list[float]) -> float:
    positives = [(score, label) for score, label in zip(scores, labels) if label == 1]
    negatives = [(score, label) for score, label in zip(scores, labels) if label == 0]
    if not positives or not negatives:
        return 0.0
    wins = 0.0
    for pos_score, _ in positives:
        for neg_score, _ in negatives:
            if pos_score > neg_score:
                wins += 1
            elif pos_score == neg_score:
                wins += 0.5
    return round(wins / (len(positives) * len(negatives)), 4)


def f1_score(labels: list[int], predictions: list[int]) -> float:
    tp = sum(1 for label, pred in zip(labels, predictions) if label == 1 and pred == 1)
    fp = sum(1 for label, pred in zip(labels, predictions) if label == 0 and pred == 1)
    fn = sum(1 for label, pred in zip(labels, predictions) if label == 1 and pred == 0)
    if tp == 0:
        return 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0


def false_positive_rate(labels: list[int], predictions: list[int]) -> float:
    fp = sum(1 for label, pred in zip(labels, predictions) if label == 0 and pred == 1)
    tn = sum(1 for label, pred in zip(labels, predictions) if label == 0 and pred == 0)
    return round(fp / (fp + tn), 4) if fp + tn else 0.0


def precision_score(labels: list[int], predictions: list[int]) -> float:
    tp = sum(1 for label, pred in zip(labels, predictions) if label == 1 and pred == 1)
    fp = sum(1 for label, pred in zip(labels, predictions) if label == 0 and pred == 1)
    return round(tp / (tp + fp), 4) if tp + fp else 0.0


def recall_for_mask(labels: list[int], predictions: list[int], mask: list[bool]) -> float:
    selected = [(label, pred) for label, pred, keep in zip(labels, predictions, mask) if keep and label == 1]
    if not selected:
        return 0.0
    hits = sum(1 for _, pred in selected if pred == 1)
    return round(hits / len(selected), 4)


def compute_metrics(
    dataset: str,
    labels: list[int],
    scores: list[float],
    predictions: list[int],
    alerts: int,
    total_loc: int,
    cross_file_mask: list[bool],
    exploitable_mask: list[bool],
    non_exploit_mask: list[bool],
    filtered_non_exploit: int,
) -> EvaluationMetrics:
    kloc = max(total_loc / 1000, 0.001)
    return EvaluationMetrics(
        dataset=dataset,
        samples=len(labels),
        auc=auc_score(labels, scores),
        f1=f1_score(labels, predictions),
        fpr=false_positive_rate(labels, predictions),
        alerts_per_kloc=round(alerts / kloc, 4),
        valid_ratio=precision_score(labels, predictions),
        cross_file_recall=recall_for_mask(labels, predictions, cross_file_mask),
        exploitability_recall=recall_for_mask(labels, predictions, exploitable_mask),
        non_exploit_filter=round(filtered_non_exploit / max(sum(non_exploit_mask), 1), 4),
    )
