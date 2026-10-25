from __future__ import annotations

from pathlib import Path

from core.types import SourceFile


SUPPORTED_EXTENSIONS = {".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".h": "c/cpp", ".hpp": "cpp"}
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "dist",
    "node_modules",
    "third_party",
    "vendor",
}


class SourceScanner:
    def __init__(self, max_files: int = 5000, max_total_bytes: int = 50 * 1024 * 1024, max_file_bytes: int = 2 * 1024 * 1024) -> None:
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_file_bytes = max_file_bytes

    def collect(self, source_path: str) -> list[SourceFile]:
        root = Path(source_path).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Source path does not exist: {source_path}")
        if root.is_file() and root.suffix.lower() not in SUPPORTED_EXTENSIONS:
            supported = ", ".join(sorted(SUPPORTED_EXTENSIONS))
            raise ValueError(f"不支持的源码类型：{root.name}。支持的扩展名：{supported}")

        paths = [root] if root.is_file() else self._walk(root)
        if len(paths) > self.max_files:
            raise ValueError(f"Scan file limit exceeded: {len(paths)} files > {self.max_files}")
        files: list[SourceFile] = []
        total_bytes = 0
        for path in paths:
            resolved_path = path.resolve()
            if root.is_dir() and not resolved_path.is_relative_to(root):
                raise ValueError(f"Source entry escapes scan root through a link: {path}")
            language = SUPPORTED_EXTENSIONS.get(path.suffix.lower())
            if not language:
                continue
            file_size = path.stat().st_size
            if file_size > self.max_file_bytes:
                raise ValueError(f"Source file is too large: {path} ({file_size} bytes > {self.max_file_bytes})")
            total_bytes += file_size
            if total_bytes > self.max_total_bytes:
                raise ValueError(f"Scan byte limit exceeded: {total_bytes} bytes > {self.max_total_bytes}")
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                content = path.read_text(encoding="gbk", errors="ignore")
            if not content.strip():
                continue
            files.append(
                SourceFile(
                    path=str(resolved_path),
                    language=language,
                    content=content,
                    lines=content.splitlines(),
                )
            )
        if not files:
            supported = ", ".join(sorted(SUPPORTED_EXTENSIONS))
            raise ValueError(f"没有找到可扫描的 C/C++ 源码。支持的扩展名：{supported}")
        return files

    def _walk(self, root: Path) -> list[Path]:
        results: list[Path] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            if path.suffix.lower() in SUPPORTED_EXTENSIONS:
                results.append(path)
        return sorted(results)
