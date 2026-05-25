from __future__ import annotations

from core.config import ScanConfig
from core.pipeline import VulnerabilityDetectionPipeline
from evaluation.dataset import load_manifest
from evaluation.metrics import compute_metrics


class GraphFeatureBaseline:
    """A lightweight graph-feature baseline shaped like a future GNN evaluator.

    It does not claim to be a trained GNN. It scores samples from call graph,
    CFG/DFG, source/sink, and rule-hit graph features so the project has a
    stable baseline interface before a real GNN model is provided.
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.pipeline = VulnerabilityDetectionPipeline(config)

    def evaluate(self, manifest_path: str):
        dataset_name, samples = load_manifest(manifest_path)
        labels: list[int] = []
        scores: list[float] = []
        predictions: list[int] = []
        cross_file_mask: list[bool] = []
        exploitable_mask: list[bool] = []
        non_exploit_mask: list[bool] = []
        total_loc = 0
        alerts = 0
        valid_findings = 0
        filtered_non_exploit = 0

        for sample in samples:
            report = self.pipeline.run(sample.path)
            summary = report.summary
            score = self._score_summary(summary)
            prediction = 1 if score >= 0.5 else 0
            labels.append(sample.label)
            scores.append(score)
            predictions.append(prediction)
            cross_file_mask.append(sample.cross_file)
            exploitable_mask.append(sample.exploitable)
            non_exploit_mask.append(sample.non_exploitable)
            alerts += int(summary.get("candidate_count", 0))
            valid_findings += 1 if sample.label == 1 and prediction == 1 else 0
            filtered_non_exploit += 1 if sample.non_exploitable and prediction == 0 else 0
            total_loc += sample.loc or 1

        metrics = compute_metrics(
            dataset=dataset_name,
            labels=labels,
            scores=scores,
            predictions=predictions,
            alerts=alerts,
            total_loc=total_loc,
            valid_findings=valid_findings,
            cross_file_mask=cross_file_mask,
            exploitable_mask=exploitable_mask,
            non_exploit_mask=non_exploit_mask,
            filtered_non_exploit=filtered_non_exploit,
        )
        metrics.method = "Graph Feature Baseline"
        return metrics

    def _score_summary(self, summary: dict) -> float:
        candidates = float(summary.get("candidate_count", 0))
        source_sinks = float(summary.get("source_sink_nodes", 0))
        call_edges = float(summary.get("call_edges", 0))
        dfg_edges = float(summary.get("dfg_edges", 0))
        cfg_edges = float(summary.get("cfg_edges", 0))
        raw = 0.18 * candidates + 0.08 * source_sinks + 0.01 * call_edges + 0.004 * dfg_edges + 0.002 * cfg_edges
        return round(max(0.0, min(0.99, raw)), 4)
