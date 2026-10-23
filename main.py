from __future__ import annotations

import argparse
import json
from pathlib import Path

from core.config import ScanConfig
from core.pipeline import VulnerabilityDetectionPipeline
from backend.storage.repository import TaskRepository
from evaluation.adapters import prepare_dataset
from evaluation.baselines import evaluation_payload
from evaluation.evaluator import DatasetEvaluator
from evaluation.gnn_baseline import GnnBaselineEvaluator
from evaluation.graph_baseline import GraphFeatureBaseline
from evaluation.model_baselines import ModelBaselineEvaluator
from evaluation.suite import EvaluationSuite
from reports.json_reporter import JsonReporter
from reports.markdown_reporter import MarkdownReporter


def parse_agent_chain(value: str | None) -> tuple[str, ...] | None:
    if not value:
        return None
    return tuple(part.strip() for part in value.split(",") if part.strip())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agent-based C/C++ vulnerability detector")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Scan a C/C++ file or directory")
    scan.add_argument("source_path", help="Source file or directory to scan")
    scan.add_argument("--output", default="report.json", help="JSON report output path")
    scan.add_argument("--markdown", help="Optional Markdown report output path")
    scan.add_argument("--model-backend", default="mock", choices=["mock", "codebert", "graphcodebert"], help="Model scoring backend")
    scan.add_argument("--model-path", help="Optional local model path or Hugging Face model id")
    scan.add_argument("--strict-model", action="store_true", help="Fail instead of falling back to mock if a real model cannot load")
    scan.add_argument("--agent-chain", help="Comma-separated agent chain following the documented flow")
    scan.add_argument("--min-confidence", type=float, default=0.25, help="Minimum confidence required in reports")
    scan.add_argument("--enable-llm-semantics", action="store_true", help="Use DeepSeek LLM for semantic reasoning when .env is configured")
    scan.add_argument("--max-scan-files", type=int, default=5000, help="Maximum C/C++ files allowed in one scan")
    scan.add_argument("--max-scan-bytes", type=int, default=50 * 1024 * 1024, help="Maximum total bytes allowed in one scan")
    scan.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024, help="Maximum bytes allowed for one source file")

    evaluate = subparsers.add_parser("evaluate", help="Evaluate a dataset manifest")
    evaluate.add_argument("manifest", help="JSON manifest describing evaluation samples")
    evaluate.add_argument("--output", default="out/evaluation.json", help="Evaluation metrics output path")
    evaluate.add_argument("--model-backend", default="mock", choices=["mock", "codebert", "graphcodebert"])
    evaluate.add_argument("--model-path")
    evaluate.add_argument("--strict-model", action="store_true", help="Fail instead of falling back to mock if a real model cannot load")
    evaluate.add_argument("--agent-chain", help="Comma-separated agent chain following the documented flow")
    evaluate.add_argument("--enable-llm-semantics", action="store_true")

    baseline = subparsers.add_parser("evaluate-baseline", help="Evaluate pure model, graph-feature, or GNN baseline")
    baseline.add_argument("manifest")
    baseline.add_argument("--backend", default="codebert", choices=["codebert", "graphcodebert", "graph-feature", "gnn"])
    baseline.add_argument("--model-path")
    baseline.add_argument("--strict-model", action="store_true", help="Fail instead of falling back to mock if a real model cannot load")
    baseline.add_argument("--threshold", type=float)
    baseline.add_argument("--epochs", type=int, default=20, help="Training epochs for the GNN baseline")
    baseline.add_argument("--output", default="out/baseline_evaluation.json")

    suite = subparsers.add_parser("evaluate-suite", help="Run proposed agent and document baselines together")
    suite.add_argument("manifest", help="JSON manifest describing evaluation samples")
    suite.add_argument("--output", default="out/evaluation_suite.json", help="Suite output path")
    suite.add_argument("--model-backend", default="mock", choices=["mock", "codebert", "graphcodebert"])
    suite.add_argument("--model-path")
    suite.add_argument("--strict-model", action="store_true", help="Fail proposed-agent model loading instead of falling back to mock")
    suite.add_argument("--agent-chain", help="Comma-separated proposed-agent chain following the documented flow")
    suite.add_argument("--codebert-model-path", default=EvaluationSuite.DEFAULT_CODEBERT_PATH)
    suite.add_argument("--graphcodebert-model-path", default=EvaluationSuite.DEFAULT_GRAPHCODEBERT_PATH)
    suite.add_argument("--skip-code-models", action="store_true", help="Skip CodeBERT and GraphCodeBERT pure baselines")
    suite.add_argument("--gnn-epochs", type=int, default=20, help="Training epochs for the GNN baseline")
    suite.add_argument("--threshold", type=float, help="Optional shared decision threshold for model/GNN baselines")
    suite.add_argument("--enable-llm-semantics", action="store_true")

    prepare = subparsers.add_parser("prepare-dataset", help="Prepare Juliet/Devign/Big-Vul data into evaluation manifest")
    prepare.add_argument("dataset_type", choices=["juliet-c", "juliet", "devign", "big-vul", "bigvul", "msr", "juliet-java"])
    prepare.add_argument("input_path", help="Dataset root, CSV, JSON, or JSONL path")
    prepare.add_argument("--output", required=True, help="Manifest JSON output path")
    prepare.add_argument("--materialize-dir", default="storage/datasets", help="Directory for materialized function code")
    prepare.add_argument("--limit", type=int, help="Optional maximum number of samples")

    migrate = subparsers.add_parser("migrate-db", help="Initialize or migrate the local task database")
    migrate.add_argument("--db-path", default=None, help="Optional SQLite database path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "scan":
        try:
            pipeline = VulnerabilityDetectionPipeline(
                ScanConfig(
                    model_backend=args.model_backend,
                    model_name=args.model_backend,
                    model_path=args.model_path,
                    strict_model=args.strict_model,
                    agent_chain=parse_agent_chain(args.agent_chain) or ScanConfig().agent_chain,
                    min_report_confidence=args.min_confidence,
                    enable_llm_semantics=args.enable_llm_semantics,
                    max_scan_files=args.max_scan_files,
                    max_scan_bytes=args.max_scan_bytes,
                    max_file_bytes=args.max_file_bytes,
                )
            )
            report = pipeline.run(args.source_path)
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            print(f"Scan failed: {exc}")
            return 2
        json_path = JsonReporter().write(report, args.output)
        markdown_target = args.markdown or str(Path(args.output).with_suffix(".md"))
        md_path = MarkdownReporter().write(report, markdown_target)
        print(f"JSON report: {json_path}")
        print(f"Markdown report: {md_path}")
        print(f"Reported findings: {report.summary['reported_count']}")
        return 0
    if args.command == "evaluate":
        config = ScanConfig(
            model_backend=args.model_backend,
            model_name=args.model_backend,
            model_path=args.model_path,
            strict_model=args.strict_model,
            agent_chain=parse_agent_chain(args.agent_chain) or ScanConfig().agent_chain,
            enable_llm_semantics=args.enable_llm_semantics,
        )
        try:
            metrics = DatasetEvaluator(config).evaluate(args.manifest)
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            print(f"Evaluation failed: {exc}")
            return 2
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = evaluation_payload(metrics.to_dict())
        output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Evaluation metrics: {output.resolve()}")
        return 0
    if args.command == "evaluate-baseline":
        try:
            if args.backend == "graph-feature":
                result = {"graph_feature_baseline": GraphFeatureBaseline().evaluate(args.manifest).to_dict()}
            elif args.backend == "gnn":
                result = {"gnn": GnnBaselineEvaluator(epochs=args.epochs).evaluate(args.manifest, threshold=args.threshold)}
            else:
                result = {
                    args.backend: ModelBaselineEvaluator(args.backend, args.model_path, strict_model=args.strict_model).evaluate(
                        args.manifest, threshold=args.threshold
                    )
                }
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            print(f"Baseline evaluation failed: {exc}")
            return 2
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Baseline evaluation: {output.resolve()}")
        return 0
    if args.command == "evaluate-suite":
        try:
            result = EvaluationSuite().run(
                args.manifest,
                proposed_model_backend=args.model_backend,
                proposed_model_path=args.model_path,
                strict_model=args.strict_model,
                agent_chain=parse_agent_chain(args.agent_chain),
                codebert_model_path=args.codebert_model_path,
                graphcodebert_model_path=args.graphcodebert_model_path,
                include_code_models=not args.skip_code_models,
                gnn_epochs=args.gnn_epochs,
                threshold=args.threshold,
                enable_llm_semantics=args.enable_llm_semantics,
            )
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            print(f"Evaluation suite failed: {exc}")
            return 2
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Evaluation suite: {output.resolve()}")
        for name, reason in result.get("skipped", {}).items():
            print(f"Skipped {name}: {reason}")
        if result.get("failed"):
            for name, reason in result["failed"].items():
                print(f"Failed {name}: {reason}")
            return 2
        return 0
    if args.command == "prepare-dataset":
        try:
            result = prepare_dataset(
                dataset_type=args.dataset_type,
                input_path=args.input_path,
                output_path=args.output,
                materialize_dir=args.materialize_dir,
                limit=args.limit,
            )
        except ValueError as exc:
            print(f"Dataset preparation failed: {exc}")
            return 2
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    if args.command == "migrate-db":
        repository = TaskRepository(args.db_path)
        print(json.dumps(repository.schema_info(), indent=2, ensure_ascii=False))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
