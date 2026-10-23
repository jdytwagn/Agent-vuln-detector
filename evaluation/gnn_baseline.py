from __future__ import annotations

import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from agents.preprocess_agent import PreprocessAgent
from core.scanner import SourceScanner
from evaluation.calibration import calibrate_threshold
from evaluation.dataset import EvaluationSample, load_manifest
from evaluation.metrics import compute_metrics


@dataclass
class GnnTrainingSummary:
    epochs: int
    total_samples: int
    train_samples: int
    eval_samples: int
    overlap_samples: int
    held_out: bool
    seed: int
    loss: float
    device: str
    graph_feature_dim: int
    max_nodes: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GnnBaselineEvaluator:
    """A small trainable GCN baseline without external graph libraries.

    This is intentionally compact: it builds per-sample graphs from the current
    IR, trains a two-layer GCN, then evaluates probabilities with the same
    metric contract as the other baselines. It is not a replacement for a
    full Devign/Joern pipeline, but it is a real trainable GNN baseline rather
    than the earlier static graph-feature score.
    """

    FEATURE_DIM = 10

    def __init__(self, epochs: int = 20, hidden_dim: int = 32, max_nodes: int = 96, seed: int = 7) -> None:
        self.epochs = max(1, epochs)
        self.hidden_dim = max(4, hidden_dim)
        self.max_nodes = max(8, max_nodes)
        self.seed = seed
        self.scanner = SourceScanner()
        self.preprocess = PreprocessAgent()

    def evaluate(self, manifest_path: str, threshold: float | None = None) -> dict[str, Any]:
        torch = self._torch()
        dataset_name, manifest_samples = load_manifest(manifest_path)
        samples: list[EvaluationSample] = []
        graphs = []
        skipped: list[dict[str, str]] = []
        for sample in manifest_samples:
            try:
                graphs.append(self._build_graph(sample, torch))
            except Exception as exc:
                skipped.append({"sample_id": sample.sample_id, "error": f"{type(exc).__name__}: {exc}"})
                continue
            samples.append(sample)
        if not samples:
            raise RuntimeError("GNN baseline could not build a graph for any manifest sample")
        labels = [sample.label for sample in samples]
        train_indices, eval_indices, held_out = self._split(labels)
        if not held_out:
            train_indices = list(range(len(samples)))
            eval_indices = list(range(len(samples)))

        random.seed(self.seed)
        torch.manual_seed(self.seed)
        model = _TinyGcn(self.FEATURE_DIM, self.hidden_dim)
        optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=1e-4)
        loss_fn = torch.nn.BCEWithLogitsLoss()
        last_loss = 0.0

        model.train()
        for _ in range(self.epochs):
            random.shuffle(train_indices)
            for index in train_indices:
                features, adjacency = graphs[index]
                target = torch.tensor([float(labels[index])], dtype=torch.float32)
                optimizer.zero_grad()
                logit = model(features, adjacency)
                loss = loss_fn(logit.view(1), target)
                loss.backward()
                optimizer.step()
                last_loss = float(loss.detach().cpu())

        scores: list[float] = []
        model.eval()
        with torch.no_grad():
            for index in range(len(samples)):
                features, adjacency = graphs[index]
                score = torch.sigmoid(model(features, adjacency)).item()
                scores.append(round(float(score), 4))

        calibration = calibrate_threshold([labels[index] for index in train_indices], [scores[index] for index in train_indices])
        selected_threshold = calibration.threshold if threshold is None else threshold
        eval_labels = [labels[index] for index in eval_indices]
        eval_scores = [scores[index] for index in eval_indices]
        eval_predictions = [1 if score >= selected_threshold else 0 for score in eval_scores]
        alerts = sum(eval_predictions)
        metrics = compute_metrics(
            dataset=dataset_name,
            labels=eval_labels,
            scores=eval_scores,
            predictions=eval_predictions,
            alerts=alerts,
            total_loc=sum(samples[index].loc or self._count_loc(samples[index].path) for index in eval_indices),
            cross_file_mask=[samples[index].cross_file for index in eval_indices],
            exploitable_mask=[samples[index].exploitable for index in eval_indices],
            non_exploit_mask=[samples[index].non_exploitable for index in eval_indices],
            filtered_non_exploit=sum(
                1 for index, pred in zip(eval_indices, eval_predictions) if samples[index].non_exploitable and pred == 0
            ),
        )
        metrics.method = "GNN Baseline"
        training = GnnTrainingSummary(
            epochs=self.epochs,
            total_samples=len(samples),
            train_samples=len(train_indices),
            eval_samples=len(eval_indices),
            overlap_samples=len(set(train_indices) & set(eval_indices)),
            held_out=held_out,
            seed=self.seed,
            loss=round(last_loss, 4),
            device="cpu",
            graph_feature_dim=self.FEATURE_DIM,
            max_nodes=self.max_nodes,
        )
        return {
            "metrics": metrics.to_dict(),
            "calibration": calibration.to_dict(),
            "threshold": selected_threshold,
            "training": training.to_dict(),
            "skipped_samples": skipped,
        }

    def _build_graph(self, sample: EvaluationSample, torch: Any) -> tuple[Any, Any]:
        ir = self.preprocess.run(self.scanner.collect(sample.path))

        nodes: list[tuple[str, list[float]]] = []
        node_index: dict[str, int] = {}

        def add_node(node_id: str, feature: list[float]) -> None:
            if node_id in node_index or len(nodes) >= self.max_nodes:
                return
            node_index[node_id] = len(nodes)
            nodes.append((node_id, feature))

        for function in ir.functions:
            add_node(
                f"fn:{function.file_path}:{function.name}:{function.start_line}",
                [1, 0, 0, 0, 0, min(len(function.calls) / 10, 1), min(len(function.parameters) / 8, 1), 0, 0, 0],
            )
        for call in ir.call_sites:
            is_sink = 1.0 if any(node.kind == "sink" and node.file_path == call.file_path and node.line == call.line for node in ir.source_sink_nodes) else 0.0
            is_source = 1.0 if any(node.kind == "source" and node.file_path == call.file_path and node.line == call.line for node in ir.source_sink_nodes) else 0.0
            is_sanitizer = 1.0 if any(node.kind == "sanitizer" and node.file_path == call.file_path and node.line == call.line for node in ir.source_sink_nodes) else 0.0
            add_node(
                f"call:{call.file_path}:{call.line}:{call.callee}",
                [0, 1, is_source, is_sink, is_sanitizer, min(len(call.arguments) / 6, 1), 0, min(call.line / 1000, 1), 0, 0],
            )
        for cfg in ir.cfg_nodes:
            add_node(
                cfg.node_id,
                [0, 0, 0, 0, 0, 0, 0, min(cfg.line / 1000, 1), 1 if cfg.kind == "condition" else 0, 1 if cfg.kind == "return" else 0],
            )
        for edge in ir.dfg_edges:
            add_node(
                self._dfg_node_id(edge.file_path, edge.function_name, edge.source_var, edge.source_line),
                [0, 0, 0, 0, 0, 0, 0, min(edge.source_line / 1000, 1), 1, 0],
            )
            add_node(
                self._dfg_node_id(edge.file_path, edge.function_name, edge.target_var, edge.target_line),
                [0, 0, 0, 0, 0, 0, 0, min(edge.target_line / 1000, 1), 0, 1],
            )

        if not nodes:
            add_node("empty", [0.0] * self.FEATURE_DIM)

        n_nodes = len(nodes)
        adjacency = torch.eye(n_nodes, dtype=torch.float32)

        def connect(source_id: str, target_id: str) -> None:
            source = node_index.get(source_id)
            target = node_index.get(target_id)
            if source is None or target is None:
                return
            adjacency[source, target] = 1.0
            adjacency[target, source] = 1.0

        functions_by_key = {(function.file_path, function.name): function for function in ir.functions}
        functions_by_name: dict[str, list[Any]] = {}
        for function in ir.functions:
            functions_by_name.setdefault(function.name, []).append(function)

        def find_function(file_path: str | None, name: str) -> Any | None:
            if file_path:
                by_key = functions_by_key.get((file_path, name))
                if by_key:
                    return by_key
            matches = functions_by_name.get(name, [])
            return matches[0] if len(matches) == 1 else None

        for edge in ir.call_edges:
            caller_fn = find_function(edge.caller_file, edge.caller)
            callee_fn = find_function(edge.callee_file, edge.callee)
            if caller_fn and callee_fn:
                connect(
                    f"fn:{caller_fn.file_path}:{caller_fn.name}:{caller_fn.start_line}",
                    f"fn:{callee_fn.file_path}:{callee_fn.name}:{callee_fn.start_line}",
                )
        for call in ir.call_sites:
            function = next(
                (item for item in ir.functions if item.file_path == call.file_path and item.name == call.function_name),
                None,
            )
            if function:
                connect(
                    f"fn:{function.file_path}:{function.name}:{function.start_line}",
                    f"call:{call.file_path}:{call.line}:{call.callee}",
                )
        for edge in ir.cfg_edges:
            connect(edge.source_id, edge.target_id)
        for edge in ir.dfg_edges:
            connect(
                self._dfg_node_id(edge.file_path, edge.function_name, edge.source_var, edge.source_line),
                self._dfg_node_id(edge.file_path, edge.function_name, edge.target_var, edge.target_line),
            )

        features = torch.tensor([feature for _, feature in nodes], dtype=torch.float32)
        return features, adjacency

    def _dfg_node_id(self, file_path: str, function_name: str, var_name: str, line: int) -> str:
        return f"dfg:{file_path}:{function_name}:{var_name}:{line}"

    def _split(self, labels: list[int]) -> tuple[list[int], list[int], bool]:
        positives = [index for index, label in enumerate(labels) if label == 1]
        negatives = [index for index, label in enumerate(labels) if label == 0]
        if len(positives) < 2 or len(negatives) < 2:
            indices = list(range(len(labels)))
            return indices, indices, False
        rng = random.Random(self.seed)
        rng.shuffle(positives)
        rng.shuffle(negatives)

        def split_class(indices: list[int]) -> tuple[list[int], list[int]]:
            cutoff = max(1, int(len(indices) * 0.7))
            if cutoff >= len(indices):
                cutoff = len(indices) - 1
            return indices[:cutoff], indices[cutoff:]

        pos_train, pos_eval = split_class(positives)
        neg_train, neg_eval = split_class(negatives)
        return pos_train + neg_train, pos_eval + neg_eval, True

    def _count_loc(self, sample_path: str) -> int:
        root = Path(sample_path)
        if root.is_file():
            return len(root.read_text(encoding="utf-8", errors="ignore").splitlines())
        total = 0
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
                total += len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
        return total or 1

    def _torch(self) -> Any:
        try:
            import torch
        except Exception as exc:  # pragma: no cover - depends on local environment
            raise RuntimeError("GNN baseline requires PyTorch. Install the project model dependencies first.") from exc
        return torch


class _TinyGcn:
    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        import torch

        class Module(torch.nn.Module):
            def __init__(self, input_dim: int, hidden_dim: int) -> None:
                super().__init__()
                self.linear1 = torch.nn.Linear(input_dim, hidden_dim)
                self.linear2 = torch.nn.Linear(hidden_dim, hidden_dim)
                self.classifier = torch.nn.Linear(hidden_dim, 1)

            def forward(self, features: Any, adjacency: Any) -> Any:
                degree = adjacency.sum(dim=1).clamp(min=1.0)
                norm = adjacency / degree.unsqueeze(1)
                hidden = torch.relu(self.linear1(norm @ features))
                hidden = torch.relu(self.linear2(norm @ hidden))
                pooled = hidden.mean(dim=0)
                return self.classifier(pooled).squeeze(-1)

        return Module(*args, **kwargs)
