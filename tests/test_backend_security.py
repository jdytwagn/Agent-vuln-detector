from __future__ import annotations

from io import BytesIO
from pathlib import Path
import zipfile

import pytest
from fastapi.testclient import TestClient

from backend.api.app import app
from backend.api.security import resolve_api_path
from backend.services.evaluation_service import EvaluationService
from backend.services.scan_service import ScanService
from backend.storage.repository import TaskRepository
from core.scanner import SourceScanner


def _service(tmp_path: Path) -> ScanService:
    return ScanService(TaskRepository(str(tmp_path / "tasks.db")), storage_dir=str(tmp_path / "storage"))


def _evaluation_service(tmp_path: Path) -> EvaluationService:
    return EvaluationService(TaskRepository(str(tmp_path / "eval_tasks.db")), storage_dir=str(tmp_path / "storage"))


def test_api_path_scan_rejects_paths_outside_workspace(tmp_path: Path) -> None:
    service = _service(tmp_path)

    with pytest.raises(ValueError):
        service.create_path_scan(str(Path("C:/Windows")), "mock")


def test_zip_upload_rejects_path_traversal(tmp_path: Path) -> None:
    service = _service(tmp_path)
    payload = BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("../evil.c", "int main(void) { return 0; }")

    with pytest.raises(ValueError):
        service.prepare_upload("task-1", "sample.zip", payload.getvalue())


def test_api_evaluation_rejects_manifest_outside_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_DETECTOR_ALLOW_ANY_PATH", raising=False)
    service = _evaluation_service(tmp_path)
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"dataset": "outside", "samples": []}', encoding="utf-8")

    with pytest.raises(ValueError):
        service.create_evaluation(str(manifest), "mock")


def test_scanner_rejects_resource_limit_excess(tmp_path: Path) -> None:
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

    with pytest.raises(ValueError):
        SourceScanner(max_files=0).collect(str(source))

    with pytest.raises(ValueError):
        SourceScanner(max_file_bytes=8).collect(str(source))


def test_optional_api_key_protects_api(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_DETECTOR_API_KEY", "unit-secret")
    client = TestClient(app)

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/rules").status_code == 401
    assert client.get("/api/rules", headers={"X-API-Key": "unit-secret"}).status_code == 200


def test_repository_records_schema_version(tmp_path: Path) -> None:
    repository = TaskRepository(str(tmp_path / "tasks.db"))
    info = repository.schema_info()

    assert info["schema_version"] >= 2
    assert "scans" in info["tables"]
    assert "evaluations" in info["tables"]


def test_dataset_api_paths_are_restricted_to_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_DETECTOR_ALLOW_ANY_PATH", raising=False)

    with pytest.raises(ValueError):
        resolve_api_path(str(tmp_path / "outside.json"))

    workspace_file = Path.cwd() / "evaluation" / "sample_manifest.json"
    with pytest.raises(ValueError):
        resolve_api_path(str(workspace_file), workspace_root=Path.cwd() / "storage" / "datasets")


def test_api_rejects_invalid_agent_chain_before_running() -> None:
    client = TestClient(app)
    response = client.post("/api/scans", json={"source_path": "tests/samples", "agent_chain": ["fusion_decision", "preprocess"]})

    assert response.status_code == 400
    assert "preprocess" in response.json()["detail"]


def test_upload_rejects_non_source_file(tmp_path: Path) -> None:
    del tmp_path
    client = TestClient(app)
    response = client.post("/api/scans/upload", files={"file": ("notes.txt", b"hello", "text/plain")})

    assert response.status_code == 400
    assert "不支持的上传文件" in response.json()["detail"]


def test_streaming_upload_rejects_limit_without_retaining_file(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.MAX_UPLOAD_BYTES = 8

    with pytest.raises(ValueError):
        service.prepare_upload("task-stream", "large.c", b"0123456789")

    assert not (tmp_path / "storage" / "uploads" / "task-stream" / "large.c").exists()
