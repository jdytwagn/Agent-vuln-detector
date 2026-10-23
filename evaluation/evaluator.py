from __future__ import annotations

from pathlib import Path

from core.config import ScanConfig
from core.pipeline import VulnerabilityDetectionPipeline
from core.types import EvaluationMetrics
from evaluation.dataset import load_manifest
from evaluation.metrics import compute_metrics


class DatasetEvaluator:
    def __init__(self, config: ScanConfig | None = None) -> None:
        self.pipeline = VulnerabilityDetectionPipeline(config)

    def evaluate(self, manifest_path: str) -> EvaluationMetrics:
        dataset_name, samples = load_manifest(manifest_path)
        labels: list[int] = []
        scores: list[float] = []
        predictions: list[int] = []
        cross_file_mask: list[bool] = []
        exploitable_mask: list[bool] = []
        non_exploit_mask: list[bool] = []
        alerts = 0
        filtered_non_exploit = 0
        total_loc = 0

        for sample in samples:
            report = self.pipeline.run(sample.path)
            actionable = [item for item in report.vulnerabilities if item.final_decision != "filtered_false_positive"]
            finding_scores = [item.final_confidence for item in actionable]
            max_score = max(finding_scores, default=0.0)
            predicted = 1 if any(item.final_decision in {"vulnerable", "needs_review"} for item in actionable) else 0
            labels.append(sample.label)
            scores.append(max_score)
            predictions.append(predicted)
            cross_file_mask.append(sample.cross_file)
            exploitable_mask.append(sample.exploitable)
            non_exploit_mask.append(sample.non_exploitable)
            alerts += len(actionable)
            if sample.non_exploitable and any(item.final_decision == "filtered_false_positive" for item in report.vulnerabilities):
                filtered_non_exploit += 1
            total_loc += sample.loc or self._count_loc(sample.path)

        return compute_metrics(
            dataset=dataset_name,
            labels=labels,
            scores=scores,
            predictions=predictions,
            alerts=alerts,
            total_loc=total_loc,
            cross_file_mask=cross_file_mask,
            exploitable_mask=exploitable_mask,
            non_exploit_mask=non_exploit_mask,
            filtered_non_exploit=filtered_non_exploit,
        )

    def _count_loc(self, sample_path: str) -> int:
        root = Path(sample_path)
        files = [root] if root.is_file() else list(root.rglob("*"))
        total = 0
        for file in files:
            if file.is_file() and file.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
                total += len(file.read_text(encoding="utf-8", errors="ignore").splitlines())
        return total
