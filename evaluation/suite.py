from __future__ import annotations

from pathlib import Path
from typing import Any

from core.config import ScanConfig
from evaluation.evaluator import DatasetEvaluator
from evaluation.gnn_baseline import GnnBaselineEvaluator
from evaluation.graph_baseline import GraphFeatureBaseline
from evaluation.model_baselines import ModelBaselineEvaluator


class EvaluationSuite:
    """Run the document-aligned experiment bundle on one manifest.

    The suite keeps the proposed multi-agent framework separate from the
    comparison baselines:
    - proposed_agent: full pipeline with the selected scoring backend.
    - codebert / graphcodebert: pure model classification baselines.
    - graph_feature_baseline: deterministic graph-feature baseline.
    - gnn_baseline: trainable lightweight GCN baseline over current IR graphs.
    """

    DEFAULT_CODEBERT_PATH = "storage/models/codebert-devign-code-vulnerability-detector-git"
    DEFAULT_GRAPHCODEBERT_PATH = "storage/models/graphcodebert-devign-code-vulnerability-detector-git"

    def run(
        self,
        manifest_path: str,
        *,
        proposed_model_backend: str = "mock",
        proposed_model_path: str | None = None,
        codebert_model_path: str | None = None,
        graphcodebert_model_path: str | None = None,
        include_code_models: bool = True,
        gnn_epochs: int = 20,
        threshold: float | None = None,
        enable_llm_semantics: bool = False,
        strict_model: bool = False,
        agent_chain: tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        config = ScanConfig(
            model_backend=proposed_model_backend,
            model_name=proposed_model_backend,
            model_path=proposed_model_path,
            enable_llm_semantics=enable_llm_semantics,
            strict_model=strict_model,
            agent_chain=agent_chain or ScanConfig().agent_chain,
        )
        payload: dict[str, Any] = {
            "manifest": str(Path(manifest_path).resolve()),
            "runs": {},
            "skipped": {},
            "failed": {},
        }

        payload["runs"]["proposed_agent"] = DatasetEvaluator(config).evaluate(manifest_path).to_dict()
        self._safe_run(
            payload,
            "graph_feature_baseline",
            lambda: GraphFeatureBaseline().evaluate(manifest_path).to_dict(),
        )
        self._safe_run(
            payload,
            "gnn_baseline",
            lambda: GnnBaselineEvaluator(epochs=gnn_epochs).evaluate(manifest_path, threshold=threshold),
        )

        if include_code_models:
            self._maybe_run_model_baseline(
                payload,
                "codebert",
                codebert_model_path or self.DEFAULT_CODEBERT_PATH,
                manifest_path,
                threshold,
            )
            self._maybe_run_model_baseline(
                payload,
                "graphcodebert",
                graphcodebert_model_path or self.DEFAULT_GRAPHCODEBERT_PATH,
                manifest_path,
                threshold,
            )
        else:
            payload["skipped"]["codebert"] = "disabled by --skip-code-models"
            payload["skipped"]["graphcodebert"] = "disabled by --skip-code-models"

        return payload

    def _maybe_run_model_baseline(
        self,
        payload: dict[str, Any],
        backend: str,
        model_path: str,
        manifest_path: str,
        threshold: float | None,
    ) -> None:
        if not Path(model_path).exists():
            payload["skipped"][backend] = f"model path not found: {model_path}"
            return
        self._safe_run(
            payload,
            backend,
            lambda: ModelBaselineEvaluator(backend, model_path, strict_model=True).evaluate(manifest_path, threshold=threshold),
        )

    def _safe_run(self, payload: dict[str, Any], name: str, runner: Any) -> None:
        try:
            payload["runs"][name] = runner()
        except Exception as exc:
            payload["failed"][name] = f"{type(exc).__name__}: {exc}"
