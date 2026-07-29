from __future__ import annotations

import json
import zipfile
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool

from backend.api.schemas import DatasetPrepareCreate, EvaluationCreate, ModelBackend, ScanCreate
from backend.api.security import require_api_key, resolve_api_path
from backend.services.evaluation_service import EvaluationService
from backend.services.scan_service import ScanService
from backend.storage.repository import TaskRepository
from core.config import ScanConfig
from core.env import get_env
from evaluation.adapters import prepare_dataset
from rules.rule_loader import load_rules


app = FastAPI(title="多智能体代码漏洞检测平台", version="0.2.0")
cors_origins = [
    origin.strip()
    for origin in get_env("AGENT_DETECTOR_CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins or ["http://127.0.0.1:5173"],
    allow_credentials="*" not in cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

repository = TaskRepository()
scan_service = ScanService(repository)
evaluation_service = EvaluationService(repository)


def _safe_get_scan(scan_id: str) -> dict:
    try:
        return repository.get_scan(scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="scan not found") from exc


def _safe_get_evaluation(evaluation_id: str) -> dict:
    try:
        return repository.get_evaluation(evaluation_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="evaluation not found") from exc


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "agent-vuln-detector"}


@app.post("/api/scans", dependencies=[Depends(require_api_key)])
def create_scan(payload: ScanCreate, background_tasks: BackgroundTasks) -> dict:
    try:
        task = scan_service.create_path_scan(payload.source_path, payload.model_backend)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    background_tasks.add_task(
        scan_service.run_scan,
        task["id"],
        task["source_path"],
        payload.model_backend,
        payload.model_path,
        payload.strict_model,
        tuple(payload.agent_chain) if payload.agent_chain else None,
        payload.enable_llm_semantics,
        payload.max_scan_files,
        payload.max_scan_bytes,
        payload.max_file_bytes,
    )
    return task


@app.post("/api/scans/upload", dependencies=[Depends(require_api_key)])
async def upload_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    model_backend: ModelBackend = Form("mock"),
    model_path: str | None = Form(None),
    strict_model: bool = Form(False),
    agent_chain: str | None = Form(None),
    enable_llm_semantics: bool = Form(False),
) -> dict:
    task = scan_service.create_path_scan(file.filename or "upload", model_backend, validate_path=False)
    try:
        source_path = await run_in_threadpool(
            scan_service.prepare_upload_stream,
            task["id"],
            file.filename or "upload.zip",
            file.file,
        )
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        repository.update_scan(task["id"], status="failed", error=str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    chain = tuple(part.strip() for part in agent_chain.split(",") if part.strip()) if agent_chain else None
    background_tasks.add_task(scan_service.run_scan, task["id"], source_path, model_backend, model_path, strict_model, chain, enable_llm_semantics)
    return repository.get_scan(task["id"])


@app.get("/api/scans", dependencies=[Depends(require_api_key)])
def list_scans() -> list[dict]:
    return repository.list_scans()


@app.get("/api/scans/{scan_id}", dependencies=[Depends(require_api_key)])
def get_scan(scan_id: str) -> dict:
    return _safe_get_scan(scan_id)


@app.get("/api/scans/{scan_id}/findings", dependencies=[Depends(require_api_key)])
def get_findings(scan_id: str) -> list[dict]:
    scan = _safe_get_scan(scan_id)
    report_path = scan.get("report_json_path")
    if not report_path or not Path(report_path).exists():
        return []
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    return report.get("vulnerabilities", [])


@app.get("/api/scans/{scan_id}/report", dependencies=[Depends(require_api_key)])
def download_report(scan_id: str, format: str = "json") -> FileResponse:
    scan = _safe_get_scan(scan_id)
    key = "report_md_path" if format == "md" else "report_json_path"
    path = scan.get(key)
    if not path or not Path(path).exists():
        raise HTTPException(status_code=404, detail="report not available")
    media_type = "text/markdown" if format == "md" else "application/json"
    return FileResponse(path, media_type=media_type, filename=Path(path).name)


@app.get("/api/rules", dependencies=[Depends(require_api_key)])
def get_rules() -> list[dict]:
    return [rule.__dict__ for rule in load_rules(ScanConfig().rules_path)]


@app.post("/api/datasets/prepare", dependencies=[Depends(require_api_key)])
def prepare_dataset_manifest(payload: DatasetPrepareCreate) -> dict:
    try:
        input_path = resolve_api_path(payload.input_path, must_exist=True)
        dataset_root = Path("storage/datasets").resolve()
        output_path = resolve_api_path(payload.output_path, workspace_root=dataset_root)
        materialize_dir = resolve_api_path(payload.materialize_dir, workspace_root=dataset_root)
        return prepare_dataset(
            dataset_type=payload.dataset_type,
            input_path=str(input_path),
            output_path=str(output_path),
            materialize_dir=str(materialize_dir),
            limit=payload.limit,
        )
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/evaluations", dependencies=[Depends(require_api_key)])
def create_evaluation(payload: EvaluationCreate, background_tasks: BackgroundTasks) -> dict:
    try:
        task = evaluation_service.create_evaluation(payload.manifest_path, payload.model_backend)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    background_tasks.add_task(
        evaluation_service.run_evaluation,
        task["id"],
        task["manifest_path"],
        payload.model_backend,
        payload.model_path,
        payload.strict_model,
        tuple(payload.agent_chain) if payload.agent_chain else None,
        payload.enable_llm_semantics,
        payload.run_baseline_suite,
        payload.codebert_model_path,
        payload.graphcodebert_model_path,
        payload.skip_code_models,
        payload.gnn_epochs,
        payload.threshold,
    )
    return task


@app.get("/api/evaluations", dependencies=[Depends(require_api_key)])
def list_evaluations() -> list[dict]:
    return repository.list_evaluations()


@app.get("/api/evaluations/{evaluation_id}", dependencies=[Depends(require_api_key)])
def get_evaluation(evaluation_id: str) -> dict:
    return _safe_get_evaluation(evaluation_id)
