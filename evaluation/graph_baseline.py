from __future__ import annotations

from pathlib import Path

from agents.preprocess_agent import PreprocessAgent
from core.scanner import SourceScanner
from core.types import CodebaseIR
from evaluation.dataset import load_manifest
from evaluation.metrics import compute_metrics


class GraphFeatureBaseline:
    """Score samples from the preprocess IR without running the agent pipeline.

    Sink, source, sanitizer and cross-file call counts come from the same
    intermediate representation the GNN baseline consumes. Rule fusion and
    model scores are intentionally not inputs.
    """

    def __init__(self) -> None:
        self.scanner = SourceScanner()
        self.preprocess = PreprocessAgent()

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
        filtered_non_exploit = 0

        for sample in samples:
            ir = self.preprocess.run(self.scanner.collect(sample.path))
            score = self._score_ir(ir)
            prediction = 1 if score >= 0.5 else 0
            labels.append(sample.label)
            scores.append(score)
            predictions.append(prediction)
            cross_file_mask.append(sample.cross_file)
            exploitable_mask.append(sample.exploitable)
            non_exploit_mask.append(sample.non_exploitable)
            alerts += sum(1 for node in ir.source_sink_nodes if node.kind == "sink")
            filtered_non_exploit += 1 if sample.non_exploitable and prediction == 0 else 0
            total_loc += sample.loc or self._count_loc(sample.path)

        metrics = compute_metrics(
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
        metrics.method = "Graph Feature Baseline"
        return metrics

    def _score_ir(self, ir: CodebaseIR) -> float:
        sinks = sum(1 for node in ir.source_sink_nodes if node.kind == "sink")
        sanitizers = sum(
            1
            for node in ir.source_sink_nodes
            if node.kind == "sanitizer" and node.name not in {"strlen", "sizeof"}
        )
        cross = sum(1 for edge in ir.call_edges if edge.cross_file)
        raw = 0.35 * sinks + 0.2 * cross - 0.2 * sanitizers
        return round(max(0.0, min(0.99, raw)), 4)

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
