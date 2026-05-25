from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class EvaluationSample:
    sample_id: str
    path: str
    label: int
    loc: int = 0
    cross_file: bool = False
    exploitable: bool = False
    non_exploitable: bool = False
    cwe: str = ""
    project: str = ""


def load_manifest(path: str) -> tuple[str, list[EvaluationSample]]:
    manifest_path = Path(path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    dataset_name = data.get("dataset", manifest_path.stem)
    samples: list[EvaluationSample] = []
    for item in data.get("samples", []):
        sample_path = Path(item["path"])
        if not sample_path.is_absolute():
            sample_path = (manifest_path.parent / sample_path).resolve()
        samples.append(
            EvaluationSample(
                sample_id=str(item.get("sample_id", sample_path.stem)),
                path=str(sample_path),
                label=int(item.get("label", 0)),
                loc=int(item.get("loc", 0)),
                cross_file=bool(item.get("cross_file", False)),
                exploitable=bool(item.get("exploitable", False)),
                non_exploitable=bool(item.get("non_exploitable", False)),
                cwe=str(item.get("cwe", "")),
                project=str(item.get("project", "")),
            )
        )
    return dataset_name, samples
