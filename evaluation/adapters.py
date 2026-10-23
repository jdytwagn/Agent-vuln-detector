from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

from agents.preprocess_agent import PreprocessAgent
from core.types import FunctionInfo, SourceFile


C_CPP_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}


def prepare_dataset(
    dataset_type: str,
    input_path: str,
    output_path: str,
    materialize_dir: str = "storage/datasets",
    limit: int | None = None,
) -> dict[str, Any]:
    normalized = dataset_type.lower()
    if normalized in {"juliet-c", "juliet-cpp", "juliet"}:
        manifest = build_juliet_c_manifest(input_path, limit, materialize_dir=str(Path(materialize_dir) / "juliet"))
    elif normalized == "devign":
        manifest = build_function_dataset_manifest(
            dataset_name="Devign",
            input_path=input_path,
            output_dir=str(Path(materialize_dir) / "devign"),
            limit=limit,
            code_fields=("func", "function", "code", "source", "contents"),
            label_fields=("target", "label", "vul", "vulnerable"),
        )
    elif normalized in {"big-vul", "bigvul", "msr"}:
        manifest = build_function_dataset_manifest(
            dataset_name="Big-Vul / MSR",
            input_path=input_path,
            output_dir=str(Path(materialize_dir) / "big_vul"),
            limit=limit,
            code_fields=("func_before", "function_before", "code", "func", "source"),
            after_code_fields=("func_after", "function_after", "fixed_func", "patched_func", "code_after", "after"),
            label_fields=("vul", "target", "label", "vulnerable"),
            cwe_fields=("cwe_id", "cwe", "CWE ID"),
            project_fields=("project", "repo", "project_name"),
            patch_fields=("files_changed",),
            default_label=1,
        )
    elif normalized in {"juliet-java", "find-sec-bugs"}:
        raise ValueError("当前检测引擎只支持 C/C++；find-sec-bugs Juliet 是 Java 数据集，需要先扩展 Java 扫描器和规则。")
    else:
        raise ValueError(f"Unsupported dataset type: {dataset_type}")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"output": str(output.resolve()), "dataset": manifest["dataset"], "samples": len(manifest["samples"])}


def build_juliet_c_manifest(input_path: str, limit: int | None = None, materialize_dir: str | None = None) -> dict[str, Any]:
    root = Path(input_path).resolve()
    testcases = root / "testcases" if (root / "testcases").exists() else root
    output_dir = Path(materialize_dir or "storage/datasets/materialized/juliet").resolve()
    samples: list[dict[str, Any]] = []
    parser = PreprocessAgent()
    files = sorted(path for path in testcases.rglob("*") if path.is_file() and path.suffix.lower() in C_CPP_EXTENSIONS)
    for path in files:
        rel = path.relative_to(root)
        if "testcasesupport" in rel.parts:
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        cwe = next((part for part in rel.parts if part.startswith("CWE")), "")
        emitted = _juliet_samples_for_file(path, rel, content, cwe, output_dir, parser)
        for sample in emitted:
            samples.append(sample)
            if limit and len(samples) >= limit:
                return {"dataset": "Juliet Test Suite C/C++", "source": str(root), "samples": samples}
    return {"dataset": "Juliet Test Suite C/C++", "source": str(root), "samples": samples}


def _juliet_samples_for_file(
    path: Path,
    rel: Path,
    content: str,
    cwe: str,
    output_dir: Path,
    parser: PreprocessAgent,
) -> list[dict[str, Any]]:
    language = "cpp" if path.suffix.lower() in {".cc", ".cpp", ".cxx", ".hpp"} else "c"
    functions = parser.run([SourceFile(str(path), language, content, content.splitlines())]).functions
    bad = [function for function in functions if _is_bad_function(function.name)]
    good = [function for function in functions if _is_good_function(function.name)]
    helpers = [function for function in functions if function not in bad and function not in good]
    sample_id = str(rel).replace("\\", "/")
    cross_file = bool(re.search(r"_[a-e]$", path.stem))
    if bad and good:
        return [
            _write_juliet_split(output_dir, sample_id, content, path.suffix, bad, helpers, 1, cwe, cross_file),
            _write_juliet_split(output_dir, sample_id, content, path.suffix, good, helpers, 0, cwe, cross_file),
        ]
    label = 1 if bad else 0 if good else _fallback_juliet_label(content)
    return [_juliet_record(sample_id, str(path), content, label, cwe, cross_file)]


def _write_juliet_split(
    output_dir: Path,
    sample_id: str,
    content: str,
    suffix: str,
    functions: list[FunctionInfo],
    helpers: list[FunctionInfo],
    label: int,
    cwe: str,
    cross_file: bool,
) -> dict[str, Any]:
    role = "bad" if label == 1 else "good"
    safe_id = _safe_id(f"{sample_id}_{role}")
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / f"{safe_id}{suffix}"
    header = "\n".join(line for line in content.splitlines() if line.strip().startswith("#"))
    bodies = "\n\n".join(function.code for function in [*helpers, *functions] if function.code.strip())
    rendered = "\n\n".join(part for part in (header, bodies) if part)
    destination.write_text(rendered + "\n", encoding="utf-8")
    return _juliet_record(f"{sample_id}#{role}", str(destination), rendered, label, cwe, cross_file)


def _juliet_record(sample_id: str, path: str, content: str, label: int, cwe: str, cross_file: bool) -> dict[str, Any]:
    return {
        "sample_id": sample_id,
        "path": path,
        "label": label,
        "loc": _count_loc_text(content),
        "cross_file": cross_file,
        "exploitable": label == 1,
        "non_exploitable": label == 0,
        "cwe": cwe,
        "project": "juliet-test-suite-c",
    }


def _fallback_juliet_label(content: str) -> int:
    has_bad = bool(re.search(r"\bbad(?:Sink|Source)?\s*\(", content))
    has_good = bool(re.search(r"\bgood\w*\s*\(", content))
    if has_bad and not has_good:
        return 1
    return 0


def _is_bad_function(name: str) -> bool:
    lowered = name.lower()
    return lowered in {"bad", "badsink", "badsource"} or lowered.endswith(("_bad", "badsink", "badsource")) or "_bad_" in lowered


def _is_good_function(name: str) -> bool:
    if _is_bad_function(name):
        return False
    lowered = name.lower()
    return lowered == "good" or lowered.startswith("good") or lowered.endswith("_good") or "_good_" in lowered


def build_function_dataset_manifest(
    dataset_name: str,
    input_path: str,
    output_dir: str,
    limit: int | None,
    code_fields: tuple[str, ...],
    label_fields: tuple[str, ...],
    after_code_fields: tuple[str, ...] = (),
    cwe_fields: tuple[str, ...] = ("cwe", "cwe_id"),
    project_fields: tuple[str, ...] = ("project", "repo"),
    patch_fields: tuple[str, ...] = (),
    default_label: int = 0,
) -> dict[str, Any]:
    source = Path(input_path).resolve()
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    samples: list[dict[str, Any]] = []
    used_sample_ids: set[str] = set()
    for index, row in enumerate(_load_rows(source), start=1):
        code = _first_value(row, code_fields)
        patch_value = _first_value(row, patch_fields) if patch_fields else ""
        if not code.strip() and patch_fields:
            code = _code_from_patch_metadata(patch_value, mode="before")
        if not code.strip():
            continue
        label_value = _first_value(row, label_fields)
        label = _parse_label(label_value) if label_value != "" else default_label
        cwe = _first_value(row, cwe_fields)
        project = _first_value(row, project_fields)
        raw_sample_id = str(row.get("id") or row.get("idx") or row.get("commit_id") or f"sample_{index}")
        samples.append(
            _materialize_sample(
                out_dir=out_dir,
                used_sample_ids=used_sample_ids,
                raw_sample_id=raw_sample_id,
                code=code,
                label=label,
                cwe=cwe,
                project=project,
            )
        )
        if limit and len(samples) >= limit:
            break
        after_code = _first_value(row, after_code_fields) if after_code_fields else ""
        if not after_code.strip() and patch_value:
            after_code = _code_from_patch_metadata(patch_value, mode="after")
        if label == 1 and after_code.strip() and _normalize_code(after_code) != _normalize_code(code):
            samples.append(
                _materialize_sample(
                    out_dir=out_dir,
                    used_sample_ids=used_sample_ids,
                    raw_sample_id=f"{raw_sample_id}_fixed",
                    code=after_code,
                    label=0,
                    cwe=cwe,
                    project=project,
                    paired_with=_safe_id(raw_sample_id),
                )
            )
            if limit and len(samples) >= limit:
                break
    return {"dataset": dataset_name, "source": str(source), "materialized_dir": str(out_dir), "samples": samples}


def _materialize_sample(
    out_dir: Path,
    used_sample_ids: set[str],
    raw_sample_id: str,
    code: str,
    label: int,
    cwe: str,
    project: str,
    paired_with: str = "",
) -> dict[str, Any]:
    sample_id = _unique_id(_safe_id(raw_sample_id), used_sample_ids)
    code_path = out_dir / f"{sample_id}.c"
    code_path.write_text(_wrap_code_if_needed(code), encoding="utf-8")
    sample = {
        "sample_id": sample_id,
        "path": str(code_path),
        "label": label,
        "loc": _count_loc_text(code),
        "cross_file": False,
        "exploitable": label == 1,
        "non_exploitable": label == 0,
        "cwe": cwe,
        "project": project,
    }
    if paired_with:
        sample["paired_with"] = paired_with
    return sample


def _load_rows(path: Path) -> Iterable[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
        with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            yield from csv.DictReader(handle)
        return
    if suffix in {".jsonl", ".ndjson"}:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if line.strip():
                    yield json.loads(line)
        return
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        rows = data if isinstance(data, list) else data.get("data") or data.get("samples") or []
        for row in rows:
            if isinstance(row, dict):
                yield row
        return
    raise ValueError(f"Unsupported dataset file format: {path.suffix}")


def _first_value(row: dict[str, Any], candidates: tuple[str, ...]) -> str:
    lowered = {key.lower(): key for key in row}
    for candidate in candidates:
        key = lowered.get(candidate.lower())
        if key is not None and row.get(key) is not None:
            return str(row[key])
    return ""


def _parse_label(value: str) -> int:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "vulnerable", "bad"}:
        return 1
    return 0


def _safe_id(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return value[:80] or "sample"


def _unique_id(base: str, used: set[str]) -> str:
    candidate = base
    index = 2
    while candidate in used:
        suffix = f"_{index}"
        candidate = f"{base[: 80 - len(suffix)]}{suffix}"
        index += 1
    used.add(candidate)
    return candidate


def _wrap_code_if_needed(code: str) -> str:
    if re.search(r"\b[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*\{", code):
        return code
    return "void dataset_function(char *input) {\n" + code + "\n}\n"


def _normalize_code(code: str) -> str:
    return re.sub(r"\s+", "", code)


def _code_from_patch_metadata(value: str, mode: str = "before") -> str:
    if not value.strip():
        return ""
    try:
        data = json.loads(value)
    except Exception:
        return ""
    items = data if isinstance(data, list) else [data]
    chunks: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        patch = str(item.get("patch") or "")
        for line in patch.splitlines():
            if line.startswith("@@") or line.startswith("+++"):
                continue
            if mode == "before" and line.startswith("-") and not line.startswith("---"):
                chunks.append(line[1:])
            elif mode == "after" and line.startswith("+") and not line.startswith("+++"):
                chunks.append(line[1:])
            elif line.startswith(" "):
                chunks.append(line[1:])
        if chunks:
            break
    return "\n".join(chunks)


def _count_loc_text(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip())
