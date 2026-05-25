from __future__ import annotations

from evaluation.calibration import calibrate_threshold
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

    def __init__(self, model_backend: str, model_path: str | None = None, strict_model: bool = False) -> None:
        self.model_backend = model_backend
        self.scorer = build_scorer(model_backend, model_backend, model_path, strict_model=strict_model)

    def evaluate(self, manifest_path: str, threshold: float | None = None) -> dict:
        dataset_name, samples = load_manifest(manifest_path)
        labels: list[int] = []
        scores: list[float] = []
        cross_file_mask: list[bool] = []
        exploitable_mask: list[bool] = []
        non_exploit_mask: list[bool] = []
        total_loc = 0

        for sample in samples:
            code = self._read_sample_code(sample.path)
            score = self._score_code(code, sample.cwe)
            labels.append(sample.label)
            scores.append(score)
            cross_file_mask.append(sample.cross_file)
            exploitable_mask.append(sample.exploitable)
            non_exploit_mask.append(sample.non_exploitable)
            total_loc += sample.loc or 1

        calibration = calibrate_threshold(labels, scores)
        selected_threshold = calibration.threshold if threshold is None else threshold
        predictions = [1 if score >= selected_threshold else 0 for score in scores]
        alerts = sum(predictions)
        metrics = compute_metrics(
            dataset=dataset_name,
            labels=labels,
            scores=scores,
            predictions=predictions,
            alerts=alerts,
            total_loc=total_loc,
            valid_findings=sum(1 for label, pred in zip(labels, predictions) if label == 1 and pred == 1),
            cross_file_mask=cross_file_mask,
            exploitable_mask=exploitable_mask,
            non_exploit_mask=non_exploit_mask,
            filtered_non_exploit=sum(1 for non_exploit, pred in zip(non_exploit_mask, predictions) if non_exploit and pred == 0),
        )
        metrics.method = self.model_backend
        return {"metrics": metrics.to_dict(), "calibration": calibration.to_dict(), "threshold": selected_threshold}

    def _score_code(self, code: str, cwe: str = "") -> float:
        text = "\n".join(part for part in (cwe, code) if part)[:4000]
        if hasattr(self.scorer, "score_text"):
            return float(self.scorer.score_text(text).score)  # type: ignore[attr-defined]
        return 0.0

    def _read_sample_code(self, sample_path: str) -> str:
        from pathlib import Path

        root = Path(sample_path)
        if root.is_file():
            return root.read_text(encoding="utf-8", errors="ignore")
        snippets: list[str] = []
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
                snippets.append(path.read_text(encoding="utf-8", errors="ignore"))
        return "\n\n".join(snippets)
