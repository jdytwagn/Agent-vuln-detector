from __future__ import annotations

import json
import os
from pathlib import Path

from backend.storage.repository import TaskRepository, utc_now
from core.config import ScanConfig
from evaluation.baselines import DOCUMENT_BASELINES
from evaluation.evaluator import DatasetEvaluator
from evaluation.suite import EvaluationSuite


class EvaluationService:
    def __init__(self, repository: TaskRepository, storage_dir: str = "storage") -> None:
        self.repository = repository
        self.output_dir = Path(storage_dir) / "evaluations"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.workspace_root = Path.cwd().resolve()

    def create_evaluation(self, manifest_path: str, model_backend: str = "mock") -> dict:
        stored_path = str(self._resolve_allowed_manifest(manifest_path))
        return self.repository.create_evaluation(stored_path, model_backend)

    def run_evaluation(
        self,
        task_id: str,
        manifest_path: str,
        model_backend: str = "mock",
        model_path: str | None = None,
        strict_model: bool = False,
        agent_chain: tuple[str, ...] | None = None,
        enable_llm_semantics: bool = False,
        run_baseline_suite: bool = False,
        codebert_model_path: str | None = None,
        graphcodebert_model_path: str | None = None,
        skip_code_models: bool = False,
        gnn_epochs: int = 20,
        threshold: float | None = None,
    ) -> None:
        try:
            self.repository.update_evaluation(task_id, status="running")
            if run_baseline_suite:
                payload = EvaluationSuite().run(
                    manifest_path,
                    proposed_model_backend=model_backend,
                    proposed_model_path=model_path,
                    strict_model=strict_model,
                    agent_chain=agent_chain,
                    codebert_model_path=codebert_model_path,
                    graphcodebert_model_path=graphcodebert_model_path,
                    include_code_models=not skip_code_models,
                    gnn_epochs=gnn_epochs,
                    threshold=threshold,
                    enable_llm_semantics=enable_llm_semantics,
                )
            else:
                metrics = DatasetEvaluator(
                    ScanConfig(
                        model_backend=model_backend,
                        model_name=model_backend,
                        model_path=model_path,
                        strict_model=strict_model,
                        agent_chain=agent_chain or ScanConfig().agent_chain,
                        enable_llm_semantics=enable_llm_semantics,
                    )
                ).evaluate(manifest_path)
                payload = {"proposed_agent": metrics.to_dict(), "document_baselines": DOCUMENT_BASELINES}
            output_path = self.output_dir / f"{task_id}.json"
            output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            self.repository.update_evaluation(
                task_id,
                status="completed",
                completed_at=utc_now(),
                metrics_json=payload,
                output_path=str(output_path.resolve()),
            )
        except Exception as exc:
            self.repository.update_evaluation(task_id, status="failed", completed_at=utc_now(), error=str(exc))

    def _resolve_allowed_manifest(self, manifest_path: str) -> Path:
        resolved = Path(manifest_path).expanduser().resolve()
        if not resolved.exists():
            raise ValueError(f"Manifest path does not exist: {manifest_path}")
        if resolved.suffix.lower() != ".json":
            raise ValueError("Evaluation manifest must be a JSON file.")
        if os.environ.get("AGENT_DETECTOR_ALLOW_ANY_PATH", "").lower() in {"1", "true", "yes"}:
            return resolved
        if not self._is_relative_to(resolved, self.workspace_root):
            raise ValueError(
                "Evaluation manifests through the API are restricted to the project workspace. "
                "Set AGENT_DETECTOR_ALLOW_ANY_PATH=true only in a trusted local environment."
            )
        return resolved

    def _is_relative_to(self, path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False
