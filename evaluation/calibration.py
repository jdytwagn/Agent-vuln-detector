from __future__ import annotations

from dataclasses import asdict, dataclass

from evaluation.metrics import f1_score


@dataclass
class CalibrationResult:
    threshold: float
    f1: float
    positives: int
    samples: int

    def to_dict(self) -> dict:
        return asdict(self)


def calibrate_threshold(labels: list[int], scores: list[float]) -> CalibrationResult:
    if not labels or not scores:
        return CalibrationResult(threshold=0.5, f1=0.0, positives=0, samples=0)
    candidates = sorted({0.0, 0.25, 0.35, 0.45, 0.5, 0.55, 0.65, 0.75, 0.85, 1.0, *scores})
    best = CalibrationResult(threshold=0.5, f1=-1.0, positives=sum(labels), samples=len(labels))
    for threshold in candidates:
        predictions = [1 if score >= threshold else 0 for score in scores]
        current = f1_score(labels, predictions)
        if current > best.f1:
            best = CalibrationResult(round(threshold, 4), current, sum(labels), len(labels))
    return best
