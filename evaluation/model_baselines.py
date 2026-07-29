from __future__ import annotations

import random
from pathlib import Path

from evaluation.calibration import CalibrationResult, calibrate_threshold
from evaluation.dataset import load_manifest
from evaluation.metrics import compute_metrics
from models.factory import build_scorer


class ModelBaselineEvaluator:
    """Pure model baseline over whole samples.

    Unlike the proposed multi-agent pipeline, this evaluator does not require a
    rule hit before scoring. It reads each manifest sample, sends the code text
    directly to CodeBERT/GraphCodeBERT, calibrates a threshold, and computes the
    same metrics. This matches the document's baseline comparison intent.
    """

    def __init__(self, model_backend: str, model_path: str | None = None, strict_model: bool = False, seed: int = 7) -> None:
        self.model_backend = model_backend
        self.seed = seed
        self.scorer = build_scorer(model_backend, model_backend, model_path, strict_model=strict_model)

    def evaluate(self, manifest_path: str, threshold: float | None = None) -> dict:
        dataset_name, samples = load_manifest(manifest_path)
        labels: list[int] = []
        scores: list[float] = []
        cross_file_mask: list[bool] = []
        exploitable_mask: list[bool] = []
        non_exploit_mask: list[bool] = []

        for sample in samples:
            code = self._read_sample_code(sample.path)
            score = self._score_code(code, sample.cwe)
            labels.append(sample.label)
            scores.append(score)
            cross_file_mask.append(sample.cross_file)
            exploitable_mask.append(sample.exploitable)
            non_exploit_mask.append(sample.non_exploitable)

        calibration_indices: list[int] = []
        evaluation_indices = list(range(len(samples)))
        if threshold is None:
            calibration_indices, evaluation_indices = self._calibration_split(labels)
            if calibration_indices:
                calibration = calibrate_threshold(
                    [labels[index] for index in calibration_indices],
                    [scores[index] for index in calibration_indices],
                )
                selected_threshold = calibration.threshold
            else:
                calibration = CalibrationResult(0.5, 0.0, 0, 0)
                selected_threshold = 0.5
        else:
            calibration = CalibrationResult(float(threshold), 0.0, 0, 0)
            selected_threshold = threshold

        eval_labels = [labels[index] for index in evaluation_indices]
        eval_scores = [scores[index] for index in evaluation_indices]
        predictions = [1 if score >= selected_threshold else 0 for score in eval_scores]
        eval_cross_file = [cross_file_mask[index] for index in evaluation_indices]
        eval_exploitable = [exploitable_mask[index] for index in evaluation_indices]
        eval_non_exploit = [non_exploit_mask[index] for index in evaluation_indices]
        alerts = sum(predictions)
        metrics = compute_metrics(
            dataset=dataset_name,
            labels=eval_labels,
            scores=eval_scores,
            predictions=predictions,
            alerts=alerts,
            total_loc=sum(samples[index].loc or self._count_loc(samples[index].path) for index in evaluation_indices),
            valid_findings=sum(1 for label, pred in zip(eval_labels, predictions) if label == 1 and pred == 1),
            cross_file_mask=eval_cross_file,
            exploitable_mask=eval_exploitable,
            non_exploit_mask=eval_non_exploit,
            filtered_non_exploit=sum(1 for non_exploit, pred in zip(eval_non_exploit, predictions) if non_exploit and pred == 0),
        )
        metrics.method = self.model_backend
        return {
            "metrics": metrics.to_dict(),
            "calibration": calibration.to_dict(),
            "threshold": selected_threshold,
            "split": {
                "calibration_samples": len(calibration_indices),
                "evaluation_samples": len(evaluation_indices),
                "overlap_samples": len(set(calibration_indices) & set(evaluation_indices)),
                "seed": getattr(self, "seed", 7),
            },
        }

    def _score_code(self, code: str, cwe: str = "") -> float:
        text = "\n".join(part for part in (cwe, code) if part)[:4000]
        if hasattr(self.scorer, "score_text"):
            return float(self.scorer.score_text(text).score)  # type: ignore[attr-defined]
        return 0.0

    def _read_sample_code(self, sample_path: str) -> str:
        root = Path(sample_path)
        if root.is_file():
            return root.read_text(encoding="utf-8", errors="ignore")
        snippets: list[str] = []
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
                snippets.append(path.read_text(encoding="utf-8", errors="ignore"))
        return "\n\n".join(snippets)

    def _count_loc(self, sample_path: str) -> int:
        root = Path(sample_path)
        paths = [root] if root.is_file() else list(root.rglob("*"))
        return max(
            1,
            sum(
                len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
                for path in paths
                if path.is_file() and path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
            ),
        )

    def _calibration_split(self, labels: list[int]) -> tuple[list[int], list[int]]:
        positives = [index for index, label in enumerate(labels) if label == 1]
        negatives = [index for index, label in enumerate(labels) if label == 0]
        if len(positives) < 2 or len(negatives) < 2:
            return [], list(range(len(labels)))
        rng = random.Random(getattr(self, "seed", 7))
        rng.shuffle(positives)
        rng.shuffle(negatives)

        def take_calibration(indices: list[int]) -> tuple[list[int], list[int]]:
            count = max(1, int(len(indices) * 0.3))
            return indices[:count], indices[count:]

        positive_calibration, positive_eval = take_calibration(positives)
        negative_calibration, negative_eval = take_calibration(negatives)
        return positive_calibration + negative_calibration, positive_eval + negative_eval
