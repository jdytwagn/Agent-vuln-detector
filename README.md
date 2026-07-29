# Agent Vulnerability Detector

面向 C/C++ 源代码的多智能体漏洞检测与实验评测平台。

它将规则检测、Tree-sitter 代码解析、source-to-sink 数据流分析、代码模型评分、LLM 语义解释和可利用性判断组合成一条检测链，输出带有 CWE、代码位置、证据链、风险等级和修复建议的报告。


## 有什么用

- 扫描单个 C/C++ 文件或完整源码目录，发现常见危险调用和潜在漏洞。
- 追踪用户输入到危险函数的传播路径，辅助判断告警是否真实可达。
- 使用本地代码模型或 LLM 为告警补充评分、中文解释和修复建议。
- 通过 Web 页面查看任务、漏洞详情、规则证据和评测结果。
- 使用 Juliet C/C++、Devign、Big-Vul 等带标签数据集评估检测效果。
- 自定义智能体执行链，开展规则、模型、数据流等模块的消融实验。

## 核心功能

| 功能 | 说明 |
| --- | --- |
| C/C++ 扫描 | 支持 `.c`、`.cc`、`.cpp`、`.cxx`、`.h`、`.hpp` 文件和源码目录 |
| 多智能体检测 | 协同执行预处理、规则推理、数据流、模型评分、语义分析、可利用性验证和融合决策 |
| 漏洞规则 | 内置 CWE/OWASP 规则，覆盖危险输入、缓冲区操作、命令执行、路径访问、格式化字符串和内存风险等场景 |
| 数据流分析 | 支持函数内、跨函数和跨文件的轻量 source-to-sink 追踪 |
| 模型增强 | 支持 mock、CodeBERT、GraphCodeBERT，以及 DeepSeek 兼容的 LLM 接口 |
| 报告输出 | 生成 JSON 和 Markdown 报告，包含位置、证据、置信度、风险等级与修复建议 |
| Web 与 API | 提供 React Web 界面、FastAPI 后端、源码上传和任务记录 |
| 实验评测 | 支持数据集转换、AUC、F1、FPR、Alerts/KLOC 等指标和多种 baseline |

## 检测流程

```text
C/C++ 源代码
  → 代码解析
  → 规则初筛
  → 数据流验证
  → 模型评分
  → 语义解释
  → 可利用性判断
  → 融合决策
  → 漏洞报告
```

## 快速开始

### 环境要求

- Python 3.10 或更高版本
- Git
- Web 界面额外需要 Node.js 20.19+ 或 22.12+，以及 npm
- Docker 部署额外需要 Docker Compose

### 1. 克隆并安装

```bash
git clone https://github.com/jdytwagn/agent-vuln-detector.git
cd agent-vuln-detector
python -m venv .venv
```

激活虚拟环境：

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# Linux / macOS
source .venv/bin/activate
```

安装基础依赖：

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

基础模式不需要模型权重或 API Key，安装完成后即可扫描。

### 2. 运行第一次扫描

扫描仓库内置样例：

```bash
python main.py scan tests/samples --output out/report.json --markdown out/report.md
```

扫描自己的 C/C++ 文件或项目：

```bash
python main.py scan /path/to/your/cpp-project --output out/report.json --markdown out/report.md
```

扫描结束后可以查看：

- `out/report.json`：适合程序处理或实验统计。
- `out/report.md`：适合直接阅读和保存。

运行 `python main.py scan --help` 可以查看阈值、扫描规模和智能体链等全部参数。

## 使用 Web 界面

先安装前端依赖：

```bash
cd frontend
npm ci
cd ..
```

Windows PowerShell 可以一键启动前后端：

```powershell
.\scripts\start_all.ps1
```

Linux、macOS 或希望分别查看日志时，请打开两个终端：

```bash
# 终端 1：项目根目录
python -m backend.run
```

```bash
# 终端 2：项目根目录
cd frontend
npm run dev
```

启动后访问：

- Web 页面：<http://127.0.0.1:5173>
- 后端 API：<http://127.0.0.1:8000>
- API 文档：<http://127.0.0.1:8000/docs>

在 Web 页面中可以扫描内置样例、上传源码或 ZIP 项目、查看漏洞详情，并下载 JSON 或 Markdown 报告。

## 配置 LLM 语义解释

LLM 是可选功能。未配置时，系统仍然可以完成规则、数据流和报告分析，并使用本地模板生成说明。

复制环境变量示例：

```powershell
# Windows PowerShell
Copy-Item .env.example .env
```

```bash
# Linux / macOS
cp .env.example .env
```

编辑 `.env`：

```env
DEEPSEEK_API_KEY=你的_API_Key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=你的模型名称
```

然后启用语义分析：

```bash
python main.py scan tests/samples --enable-llm-semantics --output out/llm-report.json --markdown out/llm-report.md
```

`DEEPSEEK_BASE_URL` 需要提供 `/chat/completions` 兼容接口。请以实际模型服务商提供的地址和模型名称为准，不要把真实 `.env` 或 API Key 提交到 Git。

## 使用 CodeBERT 或 GraphCodeBERT

安装可选模型依赖：

```bash
python -m pip install -e ".[model]"
```

使用 CodeBERT：

```bash
python main.py scan tests/samples \
  --model-backend codebert \
  --model-path /path/to/codebert-model \
  --strict-model \
  --output out/codebert-report.json
```

使用 GraphCodeBERT：

```bash
python main.py scan tests/samples \
  --model-backend graphcodebert \
  --model-path /path/to/graphcodebert-model \
  --strict-model \
  --output out/graphcodebert-report.json
```

`--model-path` 可以是本地模型目录或 Hugging Face 模型 ID。正式实验建议始终使用 `--strict-model`，这样模型加载失败时会直接报错，不会静默降级为 mock。

如果模型标签只有 `LABEL_0`、`LABEL_1` 且没有说明哪个代表漏洞，请在 `.env` 中明确设置，例如：

```env
AGENT_DETECTOR_MODEL_POSITIVE_LABEL=LABEL_1
```

## 使用真实数据集评测

项目使用统一 manifest 描述样本路径、漏洞标签和元数据。可以先运行内置小样例确认评测流程：

```bash
python main.py evaluate evaluation/sample_manifest.json --output out/evaluation.json
```

将真实数据集转换为 manifest：

```bash
# Juliet C/C++
python main.py prepare-dataset juliet-c /path/to/juliet \
  --output storage/datasets/manifests/juliet.json

# Devign
python main.py prepare-dataset devign /path/to/devign.csv \
  --output storage/datasets/manifests/devign.json \
  --materialize-dir storage/datasets/materialized

# Big-Vul / MSR
python main.py prepare-dataset big-vul /path/to/big-vul.csv \
  --output storage/datasets/manifests/big-vul.json \
  --materialize-dir storage/datasets/materialized
```

然后运行评测：

```bash
python main.py evaluate storage/datasets/manifests/juliet.json --output out/juliet-evaluation.json
```

数据集字段、baseline 和论文实验建议见 [数据集说明](docs/datasets.md) 与 [实验评测说明](docs/evaluation.md)。

## Docker 启动

如果已经安装 Docker，可以直接启动完整 Web 服务：

```bash
docker compose up --build
```

启动完成后访问 <http://127.0.0.1:5173>。Docker 模式也会读取项目根目录中的 `.env` 配置。

## 报告包含什么

每条漏洞结果通常包含：

- CWE / OWASP 分类
- 文件路径、函数名和代码行号
- 命中的危险调用及规则证据
- source-to-sink 数据流路径
- 模型评分和最终置信度
- 可利用性判断和风险等级
- 中文语义解释与修复建议

报告用于辅助安全审计，不应将单次自动检测结果直接视为已经确认的漏洞。建议结合人工复核、编译环境和动态测试进一步验证。

## 更多文档

- [新手使用说明](docs/beginner_guide.md)
- [数据集说明](docs/datasets.md)
- [实验评测说明](docs/evaluation.md)
- [真实模型接入](docs/models.md)
- [API 文档](docs/api.md)
- [部署说明](docs/deployment.md)
- [系统架构](docs/architecture.md)
