# 后端接口文档

默认地址：`http://127.0.0.1:8000`

## 健康检查

`GET /api/health`

## 扫描任务

`POST /api/scans`

```json
{
  "source_path": "tests/samples",
  "model_backend": "mock",
  "model_path": null,
  "strict_model": false,
  "agent_chain": null,
  "enable_llm_semantics": false
}
```

说明：

- `model_backend` 支持 `mock`、`codebert`、`graphcodebert`。
- 使用真实模型时，`model_path` 可以传本地模型目录，例如 `storage/models/codebert-devign-code-vulnerability-detector-git`。
- `strict_model=true` 时，真实模型加载或推理失败会让任务失败，不会降级到 mock。
- `agent_chain` 可以传智能体名称数组，例如 `["preprocess","rule_reasoning","fusion_decision"]`，用于消融实验；不传时使用完整默认链。
- 出于安全考虑，API 路径扫描默认只允许扫描当前项目工作区内的路径。仅在可信本地环境中可设置 `AGENT_DETECTOR_ALLOW_ANY_PATH=true` 放开限制。
- CORS 默认只允许本地前端 `http://127.0.0.1:5173` 和 `http://localhost:5173`。如需调整，可设置 `AGENT_DETECTOR_CORS_ORIGINS`，多个地址用英文逗号分隔。
- 如果设置了 `AGENT_DETECTOR_API_KEY`，除健康检查外的 API 都需要 `X-API-Key` 请求头或 `Authorization: Bearer <key>`。
- 可选资源限制字段：`max_scan_files`、`max_scan_bytes`、`max_file_bytes`。默认分别为 5000、50 MB、2 MB。

`POST /api/scans/upload`

上传 `.zip`、`.c`、`.cc`、`.cpp`、`.cxx`、`.h`、`.hpp` 文件，后端会保存到 `storage/uploads` 并异步扫描。
上传压缩包会做路径穿越、文件数量和解压后大小检查。

`GET /api/scans`

返回扫描任务列表。

`GET /api/scans/{id}`

返回单个扫描任务状态。

`GET /api/scans/{id}/findings`

返回漏洞详情列表。

`GET /api/scans/{id}/report?format=json`

下载 JSON 报告。`format=md` 下载 Markdown 报告。

## 规则库

`GET /api/rules`

返回 CWE/OWASP 规则列表。

## 数据集适配

`POST /api/datasets/prepare`

将 Juliet C/C++、Devign、Big-Vul/MSR 本地数据转换为统一评测 manifest。

```json
{
  "dataset_type": "big-vul",
  "input_path": "D:/datasets/MSR_20/all_c_cpp_release2.0.csv",
  "output_path": "evaluation/big_vul_manifest.json",
  "materialize_dir": "storage/datasets",
  "limit": 1000
}
```

支持的 `dataset_type`：

- `juliet-c` / `juliet`：Juliet Test Suite C/C++ 源码目录。
- `devign`：Devign CSV、JSON 或 JSONL。
- `big-vul` / `bigvul` / `msr`：Big-Vul/MSR CSV、JSON 或 JSONL。

`juliet-java` 暂不支持评测，因为当前检测引擎只支持 C/C++。

## 评测任务

`POST /api/evaluations`

```json
{
  "manifest_path": "evaluation/sample_manifest.json",
  "model_backend": "mock",
  "model_path": null,
  "strict_model": false,
  "agent_chain": null,
  "enable_llm_semantics": false,
  "run_baseline_suite": false
}
```

真实模型评测示例：

```json
{
  "manifest_path": "storage/datasets/manifests/devign_1000.json",
  "model_backend": "codebert",
  "model_path": "storage/models/codebert-devign-code-vulnerability-detector-git",
  "strict_model": true,
  "enable_llm_semantics": false
}
```

完整基线套件示例：

```json
{
  "manifest_path": "storage/datasets/manifests/devign_1000.json",
  "model_backend": "mock",
  "model_path": null,
  "enable_llm_semantics": false,
  "run_baseline_suite": true,
  "codebert_model_path": "storage/models/codebert-devign-code-vulnerability-detector-git",
  "graphcodebert_model_path": "storage/models/graphcodebert-devign-code-vulnerability-detector-git",
  "skip_code_models": false,
  "gnn_epochs": 20,
  "threshold": null
}
```

`run_baseline_suite=true` 时，后端会输出 `proposed_agent`、`graph_feature_baseline`、`gnn_baseline`，并在模型路径存在时运行 CodeBERT / GraphCodeBERT 纯模型 baseline。
如果某个 baseline 缺少依赖或运行失败，结果会进入 `failed` 字段；如果模型路径不存在，结果会进入 `skipped` 字段。API 评测 manifest 默认同样限制在当前项目工作区内。

`GET /api/evaluations`

返回评测任务列表。

`GET /api/evaluations/{id}`

返回评测状态和指标结果。
