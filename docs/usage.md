# 使用说明

项目概览、架构、界面和这次 Devign 实测见仓库根目录 [README.md](../README.md)。本页保留安装、命令行、接口、评测和部署步骤。

## 环境要求

- Python `>= 3.10`
- Node.js 和 npm
- Git
- 可选：Docker / Docker Compose
- 可选：支持真实模型推理的 PyTorch 环境

Python 基础依赖见 [pyproject.toml](../pyproject.toml)，前端依赖见 [frontend/package.json](../frontend/package.json)。

## 五分钟快速开始

### 1. 克隆项目

```powershell
git clone https://github.com/jdytwagn/agent-vuln-detector.git
cd agent-vuln-detector
```

### 2. 创建虚拟环境并安装 Python 依赖

Windows PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
```

Linux / macOS：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
```

基础安装已经可以运行完整规则、Tree-sitter、数据流、报告、CLI 和 Web 后端，不要求模型权重或 API Key。

如果要运行 CodeBERT、GraphCodeBERT 或 GNN baseline，再安装模型依赖：

```powershell
python -m pip install -e ".[model,test]"
```

验证安装：

```powershell
python main.py scan tests/samples --output out/report.json --markdown out/report.md
```

### 3. 安装前端依赖

```powershell
cd frontend
npm ci
cd ..
```

### 4. 启动后端和前端

一键启动：

```powershell
.\scripts\start_all.ps1
```

Linux / macOS 请分别启动两个终端：

```bash
python -m backend.run
```

```bash
cd frontend
npm run dev
```

也可以分开启动：

```powershell
python -m backend.run
```

```powershell
cd frontend
npm run dev
```

访问地址：

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:8000`
- 健康检查：`http://127.0.0.1:8000/api/health`

## 使用方式

### Web 前端

打开：

```text
http://127.0.0.1:5173
```

推荐演示流程：

1. 进入“扫描”页面。
2. 点击“扫描内置样例”。
3. 系统会扫描 `tests/samples`。
4. 扫描提交后自动跳转到“漏洞详情”。
5. 查看 CWE、文件位置、规则证据、模型分数、数据流路径、语义解释和修复建议。
6. 下载 JSON 或 Markdown 报告。

前端页面包括：

- 仪表盘
- 扫描任务
- 漏洞详情
- 规则库
- 实验评测

### CLI 扫描

扫描内置样例：

```powershell
python main.py scan tests/samples --output out/report.json --markdown out/report.md
```

扫描自己的 C/C++ 项目：

```powershell
python main.py scan D:\your_cpp_project --output out/your_report.json --markdown out/your_report.md
```

使用完整智能体链：

```powershell
python main.py scan tests/samples --agent-chain preprocess,rule_reasoning,dataflow_analysis,model_scoring,semantic_reasoning,exploitability_validation,fusion_decision --output out/full_chain_report.json
```

只跑规则和融合，用于消融实验：

```powershell
python main.py scan tests/samples --agent-chain preprocess,rule_reasoning,fusion_decision --output out/rule_only_report.json
```

启用 DeepSeek 语义推理：

```powershell
python main.py scan tests/samples --enable-llm-semantics --output out/llm_report.json --markdown out/llm_report.md
```

### 真实模型扫描

CodeBERT：

```powershell
python main.py scan tests/samples --model-backend codebert --model-path storage/models/codebert-devign-code-vulnerability-detector-git --strict-model --output out/codebert_report.json
```

GraphCodeBERT：

```powershell
python main.py scan tests/samples --model-backend graphcodebert --model-path storage/models/graphcodebert-devign-code-vulnerability-detector-git --strict-model --output out/graphcodebert_report.json
```

说明：

- `--strict-model` 用于正式实验。开启后，如果真实模型加载失败，系统会直接报错。
- 不开启 `--strict-model` 时，模型不可用会降级为 mock scorer，适合演示和离线联调。降级会写入报告和任务摘要的 `model_fallback`，Web 任务详情会提示，不会显示成真实模型已经跑完。
- 如果模型的 `id2label` 只有 `LABEL_0/LABEL_1` 而没有明确语义，请在 `.env` 中设置 `AGENT_DETECTOR_MODEL_POSITIVE_LABEL`，例如 `LABEL_1`；系统不会再盲猜正类方向。

## 后端 API

主要接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/health` | 健康检查 |
| `POST` | `/api/scans` | 提交路径扫描任务 |
| `POST` | `/api/scans/upload` | 上传源码或压缩包扫描 |
| `GET` | `/api/scans` | 查看扫描任务列表 |
| `GET` | `/api/scans/{id}` | 查看扫描任务状态 |
| `GET` | `/api/scans/{id}/findings` | 查看漏洞详情 |
| `GET` | `/api/scans/{id}/report` | 下载 JSON 或 Markdown 报告 |
| `GET` | `/api/rules` | 查看规则库 |
| `POST` | `/api/datasets/prepare` | 转换 Juliet、Devign、Big-Vul 数据集 |
| `POST` | `/api/evaluations` | 启动评测任务 |
| `GET` | `/api/evaluations` | 查看评测任务列表 |
| `GET` | `/api/evaluations/{id}` | 查看评测结果 |

完整接口说明见 [docs/api.md](api.md)。

## 数据集与评测

项目支持统一 manifest 格式。manifest 用来描述数据集样本路径、标签和元数据。

内置小样例评测：

```powershell
python main.py evaluate evaluation/sample_manifest.json --output out/evaluation.json
```

完整评测套件：

```powershell
python main.py evaluate-suite evaluation/sample_manifest.json --skip-code-models --gnn-epochs 1 --output out/evaluation_suite_sample.json
```

缺少 PyTorch 时，GNN 基线记为跳过，命令仍成功。某个基线真正失败时，命令以退出码 2 结束，并在输出 JSON 的 `failed` 字段写明原因。

模型 baseline：

```powershell
python main.py evaluate-baseline evaluation/sample_manifest.json --backend codebert --model-path storage/models/codebert-devign-code-vulnerability-detector-git --strict-model --output out/codebert_baseline.json
python main.py evaluate-baseline evaluation/sample_manifest.json --backend graphcodebert --model-path storage/models/graphcodebert-devign-code-vulnerability-detector-git --strict-model --output out/graphcodebert_baseline.json
python main.py evaluate-baseline evaluation/sample_manifest.json --backend graph-feature --output out/graph_feature_baseline.json
python main.py evaluate-baseline evaluation/sample_manifest.json --backend gnn --epochs 20 --output out/gnn_baseline.json
```

准备真实数据集 manifest：

```powershell
python main.py prepare-dataset juliet-c storage/datasets/raw/juliet-test-suite-c --output storage/datasets/manifests/juliet_c_1000.json --limit 1000
python main.py prepare-dataset devign storage/datasets/raw/devign_zenodo/data_C_Devign_test.csv --output storage/datasets/manifests/devign_1000.json --materialize-dir storage/datasets/materialized --limit 1000
python main.py prepare-dataset big-vul storage/datasets/raw/MSR_20_Code_vulnerability_CSV_Dataset/all_c_cpp_release2.0.csv --output storage/datasets/manifests/big_vul_1000.json --materialize-dir storage/datasets/materialized --limit 1000
```

数据集说明见 [docs/datasets.md](datasets.md)，评测说明见 [docs/evaluation.md](evaluation.md)。

## 配置

本地私密配置使用 `.env`，请不要提交真实 `.env`。

复制示例文件：

```powershell
copy .env.example .env
```

常用环境变量：

```env
DEEPSEEK_API_KEY=
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
AGENT_DETECTOR_MODEL_POSITIVE_LABEL=
AGENT_DETECTOR_CORS_ORIGINS=http://127.0.0.1:5173,http://localhost:5173
AGENT_DETECTOR_API_KEY=
AGENT_DETECTOR_DB_PATH=storage/app.db
```

说明：

- `DEEPSEEK_API_KEY`：可选。填写后配合 `--enable-llm-semantics` 启用 DeepSeek 语义解释；不填写时使用本地模板解释。
- `DEEPSEEK_BASE_URL`、`DEEPSEEK_MODEL`：模型服务地址和模型名，应以你的服务商控制台为准。
- `AGENT_DETECTOR_MODEL_POSITIVE_LABEL`：仅当本地分类模型使用含糊的 `LABEL_0/LABEL_1` 时填写，例如 `LABEL_1`。
- `AGENT_DETECTOR_API_KEY`：可选 API Key。设置后，除健康检查外的 API 需要 `X-API-Key` 或 `Authorization: Bearer <key>`。
- `AGENT_DETECTOR_ALLOW_ANY_PATH=true`：允许 API 扫描工作区外路径。仅建议在可信本地环境使用。

### 三种运行模式

| 模式 | 需要配置 | 适用场景 |
| --- | --- | --- |
| 默认本地模式 | 无需 API、无需模型权重 | 首次运行、规则和数据流扫描、功能演示 |
| LLM 语义模式 | `DEEPSEEK_API_KEY`、`DEEPSEEK_BASE_URL`、`DEEPSEEK_MODEL` | 生成更丰富的中文漏洞解释 |
| 真实代码模型模式 | 安装 `.[model]` 并提供本地目录或 Hugging Face 模型 ID | CodeBERT/GraphCodeBERT 正式实验 |

模型权重、原始数据集和 `.env` 不会提交到 Git。用户拉取项目后只需安装依赖；如果需要 LLM 或真实代码模型，再按上述变量和命令配置即可。

## 规则库

规则文件位于 [rules/cwe_rules.yaml](../rules/cwe_rules.yaml)，当前覆盖：

| 类型 | 典型 API |
| --- | --- |
| 缓冲区复制 | `strcpy` |
| 缓冲区拼接 | `strcat` |
| 格式化输出 | `sprintf` |
| 危险输入 | `gets` |
| 命令执行 | `system`、`popen` |
| 路径访问 | `fopen` |
| 内存分配检查 | `malloc` |
| Use-after-free 前置风险 | `free` |
| 格式化字符串 | `printf` |

## 报告格式

每条漏洞结果包含：

- CWE / OWASP 信息
- 文件路径和行号
- 命中的危险 sink
- 规则证据
- 模型分数
- source-to-sink 数据流路径
- 语义解释
- 可利用性判断
- 最终置信度和风险等级
- 修复建议

示例输出：

```powershell
python main.py scan tests/samples --output out/report.json --markdown out/report.md
```

## 测试

运行全部测试：

```powershell
python -m pytest
```

前端构建检查：

```powershell
cd frontend
npm run build
```

端到端快速检查：

```powershell
python main.py scan tests/samples --output out/report.json --markdown out/report.md
python main.py evaluate evaluation/sample_manifest.json --output out/evaluation.json
```

初始化或迁移本地 SQLite 数据库：

```powershell
python main.py migrate-db
```

## Docker 部署

本地 Docker Compose 启动：

```powershell
docker compose up --build
```

访问：

- 前端：`http://127.0.0.1:5173`
- 后端：`http://127.0.0.1:8000`

详细部署说明见 [docs/deployment.md](deployment.md)。

## 安全说明

本仓库默认不提交以下内容：

- `.env`
- `storage/`
- `out/`
- `frontend/node_modules/`
- `frontend/dist/`
- 模型权重
- 原始数据集
- 扫描报告输出

提交前建议检查：

```powershell
git status
git grep "sk-"
git grep "API_KEY"
git grep "TOKEN"
```

如果 API Key 曾经暴露，请立即到对应平台重置。

## 文档索引

- [小白使用和设计说明](beginner_guide.md)
- [系统架构说明](architecture.md)
- [后端接口文档](api.md)
- [部署说明](deployment.md)
- [实验评测说明](evaluation.md)
- [真实模型接入说明](models.md)
- [本地数据集说明](datasets.md)
- [文档对齐矩阵](document_alignment.md)
- [任务完成度审计](task_completion_audit.md)
- [生产环境缺口清单](production_readiness.md)

## 当前限制

- 当前预处理使用 Tree-sitter 提取函数、参数和调用，并构建轻量 CFG/DFG，尚不是 Clang/LLVM 级精确分析。
- 当前数据流是轻量 source-to-sink 分析，仍缺少完整指针别名、结构体字段和复杂控制流证明。
- 当前 GNN baseline 是项目内置轻量 GCN，不是完整 Devign/Joern CPG 复现。
- 当前后端任务使用 FastAPI BackgroundTasks，生产环境建议替换为 Redis/Celery/RQ。
- 当前数据库默认 SQLite，生产环境建议替换为 PostgreSQL/MySQL 并接入正式迁移工具。

## 路线图

- 使用 Clang/LLVM 增强宏展开、类型解析和编译单元级分析。
- 增强跨文件调用图、def-use、alias 和指针分析。
- 增加更完整的 CPG/Joern 风格 GNN baseline。
- 跑完 Devign、Juliet、Big-Vul 子集的正式评测并保存阈值校准结果。
- 引入正式认证、项目空间隔离、任务队列、资源限制和监控。
- 增加 CI/CD、发布镜像和生产部署配置。

## License

本项目采用 [MIT License](../LICENSE) 开源。你可以在保留版权与许可声明的前提下使用、复制、修改和分发本项目，完整条款请参阅 `LICENSE` 文件。
