from __future__ import annotations

import os
import shutil
import zipfile
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

from backend.storage.repository import TaskRepository, utc_now
from core.config import ScanConfig
from core.pipeline import VulnerabilityDetectionPipeline
from reports.json_reporter import JsonReporter
from reports.markdown_reporter import MarkdownReporter


class ScanService:
    MAX_UPLOAD_BYTES = 200 * 1024 * 1024
    MAX_ARCHIVE_BYTES = 500 * 1024 * 1024
    MAX_ARCHIVE_FILES = 10000

    def __init__(self, repository: TaskRepository, storage_dir: str = "storage") -> None:
        self.repository = repository
        self.storage_dir = Path(storage_dir)
        self.workspace_root = Path.cwd().resolve()
        self.uploads_dir = self.storage_dir / "uploads"
        self.reports_dir = self.storage_dir / "reports"
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def create_path_scan(self, source_path: str, model_backend: str = "mock", validate_path: bool = True) -> dict:
        stored_path = str(self._resolve_allowed_path(source_path)) if validate_path else source_path
        return self.repository.create_scan(stored_path, model_backend)

    def prepare_upload(self, task_id: str, filename: str, content: bytes) -> str:
        return self.prepare_upload_stream(task_id, filename, BytesIO(content))

    def prepare_upload_stream(self, task_id: str, filename: str, source: BinaryIO) -> str:
        target_dir = self.uploads_dir / task_id
        target_dir.mkdir(parents=True, exist_ok=True)
        upload_path = target_dir / self._safe_filename(filename)
        written = 0
        try:
            with upload_path.open("wb") as destination:
                while chunk := source.read(1024 * 1024):
                    written += len(chunk)
                    if written > self.MAX_UPLOAD_BYTES:
                        raise ValueError(f"Uploaded file is too large: more than {self.MAX_UPLOAD_BYTES} bytes")
                    destination.write(chunk)
        except Exception:
            upload_path.unlink(missing_ok=True)
            raise
        if zipfile.is_zipfile(upload_path):
            extract_dir = target_dir / "extracted"
            extract_dir.mkdir(parents=True, exist_ok=True)
            try:
                with zipfile.ZipFile(upload_path) as archive:
                    self._safe_extract(archive, extract_dir)
            except Exception:
                shutil.rmtree(extract_dir, ignore_errors=True)
                raise
            return str(extract_dir.resolve())
        return str(upload_path.resolve())

    def run_scan(
        self,
        task_id: str,
        source_path: str,
        model_backend: str = "mock",
        model_path: str | None = None,
        strict_model: bool = False,
        agent_chain: tuple[str, ...] | None = None,
        enable_llm_semantics: bool = False,
        max_scan_files: int | None = None,
        max_scan_bytes: int | None = None,
        max_file_bytes: int | None = None,
    ) -> None:
        try:
            self.repository.update_scan(task_id, status="running")
            config = ScanConfig(
                model_backend=model_backend,
                model_name=model_backend,
                model_path=model_path,
                strict_model=strict_model,
                agent_chain=agent_chain or ScanConfig().agent_chain,
                enable_llm_semantics=enable_llm_semantics,
            )
            if max_scan_files is not None:
                config.max_scan_files = max_scan_files
            if max_scan_bytes is not None:
                config.max_scan_bytes = max_scan_bytes
            if max_file_bytes is not None:
                config.max_file_bytes = max_file_bytes
            report = VulnerabilityDetectionPipeline(config).run(source_path)
            json_path = self.reports_dir / f"{task_id}.json"
            md_path = self.reports_dir / f"{task_id}.md"
            JsonReporter().write(report, str(json_path))
            MarkdownReporter().write(report, str(md_path))
            self.repository.update_scan(
                task_id,
                source_path=source_path,
                status="completed",
                completed_at=utc_now(),
                summary_json=report.summary,
                report_json_path=str(json_path.resolve()),
                report_md_path=str(md_path.resolve()),
            )
        except Exception as exc:
            self.repository.update_scan(task_id, status="failed", completed_at=utc_now(), error=str(exc))

    def _resolve_allowed_path(self, source_path: str) -> Path:
        resolved = Path(source_path).expanduser().resolve()
        if not resolved.exists():
            raise ValueError(f"Source path does not exist: {source_path}")
        if os.environ.get("AGENT_DETECTOR_ALLOW_ANY_PATH", "").lower() in {"1", "true", "yes"}:
            return resolved
        allowed_roots = [self.workspace_root, self.uploads_dir.resolve()]
        if not any(self._is_relative_to(resolved, root) for root in allowed_roots):
            raise ValueError(
                "Path scans through the API are restricted to the project workspace. "
                "Set AGENT_DETECTOR_ALLOW_ANY_PATH=true only in a trusted local environment."
            )
        return resolved

    def _safe_filename(self, filename: str) -> str:
        name = Path(filename or "upload").name
        return name or "upload"

    def _safe_extract(self, archive: zipfile.ZipFile, extract_dir: Path) -> None:
        root = extract_dir.resolve()
        infos = [info for info in archive.infolist() if not info.is_dir()]
        if len(infos) > self.MAX_ARCHIVE_FILES:
            raise ValueError(f"Archive contains too many files: {len(infos)}")
        declared_size = sum(max(info.file_size, 0) for info in infos)
        if declared_size > self.MAX_ARCHIVE_BYTES:
            raise ValueError(f"Archive uncompressed size is too large: {declared_size} bytes")
        extracted_size = 0
        for info in infos:
            member_name = info.filename.replace("\\", "/")
            member_path = Path(member_name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError(f"Unsafe archive member path: {info.filename}")
            target = (root / member_path).resolve()
            if not self._is_relative_to(target, root):
                raise ValueError(f"Archive member escapes upload directory: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as destination:
                while chunk := source.read(1024 * 1024):
                    extracted_size += len(chunk)
                    if extracted_size > self.MAX_ARCHIVE_BYTES:
                        raise ValueError(f"Archive expands beyond {self.MAX_ARCHIVE_BYTES} bytes")
                    destination.write(chunk)

    def _is_relative_to(self, path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False
