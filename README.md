# 多智能体代码漏洞检测平台

这是一个完整化的代码漏洞检测项目，基于文档《基于智能体的代码漏洞检测框架研究》的思路实现：

```text
源码输入 -> 代码预处理 -> 规则初筛 -> 模型打分 -> 数据流验证
-> 语义推理 -> 可利用性判断 -> 融合决策 -> 输出漏洞报告
```

项目不把深度学习模型作为唯一决策者，而是把模型作为“概率打分模块”，再结合 CWE/OWASP 规则、source-to-sink 数据流、语义解释、可利用性验证和融合决策，输出更适合工程安全审计的结果。

## 当前项目形态

项目已经从 CLI 原型升级为四层结构：

- 检测引擎层：`agents/`、`core/`、`rules/`、`models/`、`reports/`
- 后端服务层：`backend/`，基于 FastAPI，提供扫描任务、报告、规则库和评测接口
- 前端展示层：`frontend/`，基于 React + TypeScript + Vite
- 实验评测层：`evaluation/`，输出 AUC、F1、FPR、Alerts/KLOC、跨文件召回率、可利用性召回率等指标

## 快速运行

### 1. 命令行扫描

安装基础依赖：

```powershell
python -m pip install -e .[test]
```

如果要运行 CodeBERT、GraphCodeBERT 或 GNN baseline：

```powershell
python -m pip install -e .[model,test]
```

```powershell
python main.py scan tests/samples --output out/report.json --markdown out/report.md
```

显式指定完整智能体链：

```powershell
python main.py scan tests/samples --agent-chain preprocess,rule_reasoning,model_scoring,dataflow_analysis,semantic_reasoning,exploitability_validation,fusion_decision --output out/report.json
```

启用 DeepSeek 语义推理：

```powershell
python main.py scan tests/samples --output out/report.json --markdown out/report.md --enable-llm-semantics
```

正式实验中使用真实模型时，建议开启严格模型模式，避免模型加载失败后静默降级为 mock：

```powershell
python main.py scan tests/samples --model-backend codebert --model-path storage/models/codebert-devign-code-vulnerability-detector-git --strict-model --output out/codebert_report.json
```

### 2. 命令行评测

```powershell
python main.py evaluate evaluation/sample_manifest.json --output out/evaluation.json
```

模型 baseline / 图特征 baseline：

```powershell
python main.py evaluate-baseline evaluation/sample_manifest.json --backend codebert --model-path D:\models\codebert-vuln --output out/codebert_baseline.json
python main.py evaluate-baseline evaluation/sample_manifest.json --backend graph-feature --output out/graph_feature_baseline.json
python main.py evaluate-baseline evaluation/sample_manifest.json --backend gnn --epochs 20 --output out/gnn_baseline.json
python main.py evaluate-suite evaluation/sample_manifest.json --skip-code-models --gnn-epochs 1 --output out/evaluation_suite_sample.json
```

### 3. 准备真实测试集

Juliet C/C++：

```powershell
python main.py prepare-dataset juliet-c D:\datasets\juliet-test-suite-c --output evaluation/juliet_c_manifest.json --limit 1000
```

Devign：

```powershell
python main.py prepare-dataset devign D:\datasets\devign\devign.csv --output evaluation/devign_manifest.json --materialize-dir storage/datasets --limit 1000
```

Big-Vul/MSR：

```powershell
python main.py prepare-dataset big-vul D:\datasets\MSR_20_Code_vulnerability_CSV_Dataset\all_c_cpp_release2.0.csv --output evaluation/big_vul_manifest.json --materialize-dir storage/datasets --limit 1000
```

### 4. 启动后端

```powershell
python -m backend.run
```

后端地址：

```text
http://127.0.0.1:8000
```

### 5. 启动前端

```powershell
cd frontend
npm install
npm run dev
```

前端地址：

```text
http://127.0.0.1:5173
```

### 6. 一键启动

```powershell
.\scripts\start_all.ps1
```

## 已实现能力

- 支持 CLI、API、Web 三种方式触发扫描。
- 支持扫描单个 C/C++ 文件或源码目录。
- 支持上传源码压缩包并异步扫描。
- 支持 `.c`、`.cc`、`.cpp`、`.cxx`、`.h`、`.hpp` 文件。
- 支持 JSON 和 Markdown 报告。
- 支持 SQLite 保存扫描任务和评测任务状态，并提供 schema 版本记录和 `migrate-db` 初始化入口。
- 支持 mock、CodeBERT、GraphCodeBERT 三类模型后端接口。
- 支持 DeepSeek API 语义推理，未配置时自动降级到模板解释。
- 支持严格模型模式，避免真实模型实验时静默降级为 mock。
- 支持可配置智能体链，默认按文档流程执行七个智能体。
- 支持基础 CFG/DFG 统计、图特征 baseline 和可训练轻量 GNN baseline。
- 支持本地 manifest 数据集评测。
- 支持 Juliet C/C++、Devign、Big-Vul/MSR 数据集适配为统一 manifest。

本机已经准备好的数据集路径、manifest 和评测命令见 [本地数据集说明](docs/datasets.md)。

真实 CodeBERT / GraphCodeBERT 模型路径和运行命令见 [真实模型接入说明](docs/models.md)。

如果使用本机已经下载好的模型，可以直接运行：

```powershell
python main.py evaluate-baseline evaluation/sample_manifest.json --backend codebert --model-path storage/models/codebert-devign-code-vulnerability-detector-git --output out/codebert_baseline.json
python main.py evaluate-baseline evaluation/sample_manifest.json --backend graphcodebert --model-path storage/models/graphcodebert-devign-code-vulnerability-detector-git --output out/graphcodebert_baseline.json
```

## 七个智能体

- 预处理智能体：提取函数、调用点、AST 摘要、调用边、变量引用、source/sink 节点。
- 规则推理智能体：基于 CWE/OWASP 规则发现候选漏洞。
- 深度学习打分智能体：输出候选漏洞概率、标签和置信度。
- 数据流分析智能体：追踪函数内、跨函数、跨文件 source-to-sink 路径。
- 语义推理智能体：生成漏洞解释文本。
- 可利用性验证智能体：判断输入可控性、路径可达性、过滤和缓解逻辑。
- 融合决策智能体：综合规则、模型、数据流、语义和可利用性，生成最终结论。

## 后端接口

主要接口：

- `POST /api/scans`：提交路径扫描任务
- `POST /api/scans/upload`：上传源码或压缩包扫描
- `GET /api/health`：服务健康检查
- `GET /api/scans`：查看扫描任务
- `GET /api/scans/{id}`：查看任务状态
- `GET /api/scans/{id}/findings`：查看漏洞详情
- `GET /api/scans/{id}/report`：下载报告
- `GET /api/rules`：查看规则库
- `POST /api/datasets/prepare`：将 Juliet、Devign、Big-Vul 转换为统一 manifest
- `POST /api/evaluations`：启动评测任务
- `GET /api/evaluations`：查看评测任务列表
- `GET /api/evaluations/{id}`：查看评测指标

更多说明见 [接口文档](docs/api.md)。

## 前端页面

前端提供：

- 仪表盘：扫描数量、完成状态、漏洞数量、误报过滤统计、严重等级分布
- 扫描页面：内置样例一键扫描、路径扫描、压缩包上传、模型后端选择、严格模型模式
- 漏洞详情页：CWE、位置、代码片段、规则证据、模型分数、数据流路径、语义解释、修复建议
- 规则库页面：CWE/OWASP 规则列表
- 评测页面：AUC、F1、FPR、Alerts/KLOC、Cross-file Recall、Exploitability Recall
- 扫描和评测页面可以选择是否启用 DeepSeek 语义推理。

## 当前规则库

规则文件位于 `rules/cwe_rules.yaml`，当前覆盖：

- 缓冲区复制：`strcpy`
- 缓冲区拼接：`strcat`
- 格式化输出：`sprintf`
- 危险输入：`gets`
- 命令执行：`system`、`popen`
- 路径访问：`fopen`
- 内存分配：`malloc`
- 内存释放：`free`
- 格式化字符串：`printf`

## 实验评测

评测模块对应文档中的实验设计：

- 数据集：支持本地 manifest、Juliet C/C++、Devign、Big-Vul/MSR
- 基线：支持 CodeBERT、GraphCodeBERT、图特征 baseline 和 GNN baseline
- 指标：AUC、F1、FPR、Alerts/KLOC、Valid Ratio、Cross-file Recall、Exploitability Recall、Non-exploit Filter

示例：

```powershell
python main.py evaluate evaluation/sample_manifest.json --output out/evaluation.json
python main.py evaluate-suite evaluation/sample_manifest.json --skip-code-models --gnn-epochs 1 --output out/evaluation_suite_sample.json
```

## 项目结构

```text
agent-vuln-detector/
  agents/          # 七个智能体
  backend/         # FastAPI 后端
  core/            # 数据结构、扫描器、流水线、配置
  docs/            # 架构、接口、评测文档
  evaluation/      # 数据集评测与指标计算
  frontend/        # React + TypeScript 前端
  models/          # mock / CodeBERT / GraphCodeBERT 模型接口
  reports/         # JSON / Markdown 报告生成
  rules/           # CWE/OWASP 规则库
  scripts/         # 启动脚本
  storage/         # SQLite、上传文件、报告输出
  tests/           # 测试样例与测试代码
  main.py          # CLI 入口
```

## 测试

如果安装了 `pytest`：

```powershell
python -m pytest
```

如果没有安装，也可以用以下命令做端到端验证：

```powershell
python main.py scan tests/samples --output out/report.json --markdown out/report.md
python main.py evaluate evaluation/sample_manifest.json --output out/evaluation.json
```

初始化或迁移本地数据库：

```powershell
python main.py migrate-db
```

## 文档

- [系统架构说明](docs/architecture.md)
- [小白使用和设计说明](docs/beginner_guide.md)
- [后端接口文档](docs/api.md)
- [部署说明](docs/deployment.md)
- [实验评测说明](docs/evaluation.md)
- [文档对齐矩阵](docs/document_alignment.md)
- [任务完成度审计](docs/task_completion_audit.md)
- [生产环境缺口清单](docs/production_readiness.md)

## 环境变量

本地 `.env` 用于保存私密配置，不要提交：

```env
DEEPSEEK_API_KEY=你的新key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
AGENT_DETECTOR_CORS_ORIGINS=http://127.0.0.1:5173,http://localhost:5173
# 可选：开启后 API 请求需要 X-API-Key 或 Bearer Token
AGENT_DETECTOR_API_KEY=
```

## 后续可继续增强

- 在 Tree-sitter AST 基础上继续补充 Clang 级 CFG/DFG 和更精确的类型信息。
- 跑完 Devign、Juliet、Big-Vul 子集的正式评测，并保存阈值校准结果。
- 为 Big-Vul 增加固定数据切分和 commit 前后完整函数还原。
- 增强跨文件调用图、别名分析和更精确的数据流。
- 将当前轻量 GNN baseline 升级为 Devign/Joern 风格代码属性图训练流程。
