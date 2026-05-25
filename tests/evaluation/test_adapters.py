from __future__ import annotations

import csv
import json
from pathlib import Path

from evaluation.adapters import prepare_dataset


def test_devign_csv_adapter_materializes_code(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    csv_path = tmp_path / "devign.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "func", "target"])
        writer.writeheader()
        writer.writerow({"id": "d1", "func": "void f(char *x){ char b[8]; strcpy(b, x); }", "target": "1"})
    output = tmp_path / "devign_manifest.json"
    result = prepare_dataset("devign", str(csv_path), str(output), str(tmp_path / "materialized"))

    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert result["samples"] == 1
    assert manifest["samples"][0]["label"] == 1
    assert Path(manifest["samples"][0]["path"]).exists()


def test_big_vul_csv_adapter_reads_func_before_and_vul(tmp_path: Path) -> None:
    tmp_path.mkdir(parents=True, exist_ok=True)
    csv_path = tmp_path / "bigvul.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["commit_id", "func_before", "vul", "cwe_id", "project"])
        writer.writeheader()
        writer.writerow({"commit_id": "abc", "func_before": "int f(){ return 0; }", "vul": "0", "cwe_id": "CWE-20", "project": "demo"})
    output = tmp_path / "big_vul_manifest.json"
    prepare_dataset("big-vul", str(csv_path), str(output), str(tmp_path / "materialized"))

    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["dataset"] == "Big-Vul / MSR"
    assert manifest["samples"][0]["label"] == 0
    assert manifest["samples"][0]["cwe"] == "CWE-20"


def test_big_vul_adapter_materializes_fixed_function_as_negative_pair(tmp_path: Path) -> None:
    csv_path = tmp_path / "bigvul_pair.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["commit_id", "func_before", "func_after", "cwe_id", "project"])
        writer.writeheader()
        writer.writerow(
            {
                "commit_id": "pair-1",
                "func_before": "void f(char *x){ char b[8]; strcpy(b, x); }",
                "func_after": "void f(char *x){ char b[8]; strncpy(b, x, sizeof(b)-1); }",
                "cwe_id": "CWE-120",
                "project": "demo",
            }
        )
    output = tmp_path / "big_vul_pair_manifest.json"
    prepare_dataset("big-vul", str(csv_path), str(output), str(tmp_path / "materialized"))

    manifest = json.loads(output.read_text(encoding="utf-8"))
    labels = [sample["label"] for sample in manifest["samples"]]
    assert labels == [1, 0]
    assert manifest["samples"][1]["paired_with"] == "pair-1"


def test_big_vul_adapter_uses_patch_additions_as_negative_pair(tmp_path: Path) -> None:
    csv_path = tmp_path / "bigvul_patch_pair.csv"
    patch = json.dumps(
        [
            {
                "patch": "\n".join(
                    [
                        "@@ -1,3 +1,3 @@",
                        " void f(char *x) {",
                        "-  strcpy(buf, x);",
                        "+  strncpy(buf, x, sizeof(buf)-1);",
                        " }",
                    ]
                )
            }
        ]
    )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["commit_id", "files_changed", "cwe_id", "project"])
        writer.writeheader()
        writer.writerow({"commit_id": "patch-1", "files_changed": patch, "cwe_id": "CWE-120", "project": "demo"})
    output = tmp_path / "big_vul_patch_manifest.json"
    prepare_dataset("big-vul", str(csv_path), str(output), str(tmp_path / "materialized"))

    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert [sample["label"] for sample in manifest["samples"]] == [1, 0]
    assert "strncpy" in Path(manifest["samples"][1]["path"]).read_text(encoding="utf-8")
