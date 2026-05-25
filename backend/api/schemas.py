from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


ModelBackend = Literal["mock", "codebert", "graphcodebert"]
DatasetType = Literal[
    "juliet-c",
    "juliet-cpp",
    "juliet",
    "devign",
    "big-vul",
    "bigvul",
    "msr",
    "juliet-java",
    "find-sec-bugs",
]


class ScanCreate(BaseModel):
    source_path: str = Field(..., min_length=1, description="C/C++ source file or directory")
    model_backend: ModelBackend = "mock"
    model_path: str | None = None
    strict_model: bool = False
    agent_chain: list[str] | None = None
    enable_llm_semantics: bool = False
    max_scan_files: int | None = Field(None, ge=1, le=100000)
    max_scan_bytes: int | None = Field(None, ge=1024, le=2_000_000_000)
    max_file_bytes: int | None = Field(None, ge=1024, le=200_000_000)


class EvaluationCreate(BaseModel):
    manifest_path: str = Field(..., min_length=1)
    model_backend: ModelBackend = "mock"
    model_path: str | None = None
    strict_model: bool = False
    agent_chain: list[str] | None = None
    enable_llm_semantics: bool = False
    run_baseline_suite: bool = False
    codebert_model_path: str | None = None
    graphcodebert_model_path: str | None = None
    skip_code_models: bool = False
    gnn_epochs: int = Field(20, ge=1, le=200)
    threshold: float | None = Field(None, ge=0.0, le=1.0)


class DatasetPrepareCreate(BaseModel):
    dataset_type: DatasetType
    input_path: str = Field(..., min_length=1)
    output_path: str = Field(..., min_length=1)
    materialize_dir: str = "storage/datasets"
    limit: int | None = Field(None, ge=1)
