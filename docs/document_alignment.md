# 文档对齐矩阵

本文档用于说明当前项目与《基于智能体的代码漏洞检测框架研究》的逐项对应关系。状态分为：

- 已对齐：当前代码已经实现并通过基础验证。
- 部分对齐：架构和接口已经具备，但精度、实验规模或工程强度仍需增强。
- 待补齐：仍需要新的实现或外部资源。

## 一、总体流程对齐

| 文档要求 | 当前实现 | 状态 | 代码位置 | 说明 |
| --- | --- | --- | --- | --- |
| 源码输入 | CLI、API、Web 路径扫描和上传扫描 | 已对齐 | `main.py`、`backend/api/app.py`、`frontend/src/main.tsx` | 支持单文件、目录、上传文件或 zip |
| 代码预处理 | 预处理智能体输出函数、调用点、调用边、变量引用、AST 摘要、CFG/DFG 统计 | 部分对齐 | `agents/preprocess_agent.py` | 当前是 Tree-sitter AST 摘要 + 轻量函数/调用/DFG 提取，尚不是 Clang/LLVM 级精确分析 |
| 规则初筛 | CWE/OWASP 规则库和规则智能体 | 已对齐 | `rules/cwe_rules.yaml`、`agents/rule_agent.py` | 当前主要基于 sink 命中，规则条件仍可继续增强 |
| 深度学习打分 | mock、CodeBERT、GraphCodeBERT 模型接口 | 已对齐 | `models/` | 本机已缓存 Devign 微调模型；正式实验可开启严格模型模式避免 fallback |
| 数据流验证 | source-to-sink 追踪，支持函数内、跨函数、跨文件路径 | 部分对齐 | `agents/dataflow_agent.py` | 已修复函数签名误判和同名函数覆盖；别名、指针、结构体仍待增强 |
| 语义推理 | 模板解释 + DeepSeek 接口 | 已对齐 | `agents/semantic_agent.py`、`models/deepseek_client.py` | 未配置 LLM 时自动降级模板 |
| 可利用性判断 | 输入可控、路径可达、缓解逻辑判断 | 部分对齐 | `agents/exploitability_agent.py` | 已收紧缓解识别；还缺支配关系和边界条件证明 |
| 融合决策 | 规则、模型、数据流、可利用性加权融合 | 已对齐 | `agents/fusion_agent.py` | 首版采用规则加权机制 |
| 漏洞报告 | JSON、Markdown、前端详情页 | 已对齐 | `reports/`、`frontend/src/main.tsx` | 包含 CWE、位置、证据链、模型分数、数据流、修复建议 |

## 二、七个智能体对齐

| 智能体 | 当前文件 | 状态 | 说明 |
| --- | --- | --- | --- |
| 预处理智能体 | `agents/preprocess_agent.py` | 部分对齐 | 能生成 IR，但还不是 Clang/LLVM 级精确分析 |
| 规则推理智能体 | `agents/rule_agent.py` | 已对齐 | 支持 CWE/OWASP 规则命中 |
| 深度学习打分智能体 | `agents/model_score_agent.py` | 已对齐 | 已接入真实 CodeBERT/GraphCodeBERT |
| 数据流分析智能体 | `agents/dataflow_agent.py` | 部分对齐 | 支持基础 source-to-sink，仍需更强 def-use/alias 分析 |
| 语义推理智能体 | `agents/semantic_agent.py` | 已对齐 | 模板解释 + 可选 DeepSeek |
| 可利用性验证智能体 | `agents/exploitability_agent.py` | 部分对齐 | 已做缓解识别，仍需路径支配和约束判断 |
| 融合决策智能体 | `agents/fusion_agent.py` | 已对齐 | 输出最终置信度、严重等级和决策 |

## 三、模型实验对齐

| 文档要求 | 当前实现 | 状态 | 说明 |
| --- | --- | --- | --- |
| 使用预训练代码模型做概率评估 | CodeBERT/GraphCodeBERT 可对候选漏洞打分 | 已对齐 | `models/codebert_scorer.py` |
| CodeBERT baseline | 纯模型 baseline 直接对样本代码打分 | 已对齐 | `evaluation/model_baselines.py` |
| GraphCodeBERT baseline | 纯模型 baseline 直接对样本代码打分 | 已对齐 | `evaluation/model_baselines.py` |
| GNN baseline | 可训练轻量 GCN baseline + 图特征 baseline | 部分对齐 | `evaluation/gnn_baseline.py` 已能训练和输出指标；若要论文复现级别，还需 Devign/Joern 风格 CPG |
| 阈值校准 | 自动选择 F1 最优阈值 | 已对齐 | `evaluation/calibration.py` |
| 模型输入格式 | 代码文本 + CWE 上下文，统一 `max_length=512` 截断 | 已对齐 | 后续可进一步固定 train/validation/test 切分 |

## 四、数据集对齐

| 数据集 | 当前状态 | Manifest | 说明 |
| --- | --- | --- | --- |
| Juliet C/C++ | 已下载并生成 1000 条 manifest | `storage/datasets/manifests/juliet_c_1000.json` | 标签来自 Juliet good/bad 命名和内容结构 |
| Juliet Java / Find Security Bugs | 已下载，不进入当前 C/C++ 引擎评测 | 无正式 manifest | 需要 Java 解析器和 Java 规则库 |
| Devign | 已下载、MD5 校验、生成 1000 条 manifest | `storage/datasets/manifests/devign_1000.json` | 当前最适合做模型分类评测 |
| Big-Vul/MSR | 已下载并生成 1000 条正负配对 manifest | `storage/datasets/manifests/big_vul_1000.json` | 当前为 500 个漏洞样本 + 500 个修复后负样本；严格论文复现仍建议按 commit 还原完整函数 |

## 五、Web 平台对齐

| 文档要求 | 当前实现 | 状态 |
| --- | --- | --- |
| Web 前端上传或选择源码 | 路径扫描 + 文件/zip 上传 | 已对齐 |
| 新手演示入口 | 扫描页提供内置样例一键扫描并自动跳转漏洞详情 | 已对齐 |
| 扫描任务状态 | pending/running/completed/failed | 已对齐 |
| 漏洞详情展示 | CWE、位置、代码、规则、模型、数据流、解释、修复建议 | 已对齐 |
| 规则库页面 | 展示 CWE/OWASP 规则 | 已对齐 |
| 评测页面 | 展示 AUC、F1、FPR 等指标，可触发完整基线套件 | 已对齐 |
| 模型配置 | 前端可选后端并传模型路径 | 已对齐 |
| 报告下载 | 后端和前端均支持 JSON/Markdown 下载 | 已对齐 | 漏洞详情页可直接下载两种报告 |

## 六、生产化对齐

| 要求 | 当前状态 | 后续工作 |
| --- | --- | --- |
| 上传隔离 | 已限制 zip 路径穿越、大小和文件数 | 增加杀毒/文件类型白名单 |
| 路径扫描安全 | API 默认限制工作区路径 | 增加用户级项目空间 |
| 任务异步 | FastAPI BackgroundTasks | 生产建议换 Celery/RQ/Redis |
| 数据库 | SQLite，带 schema 版本记录和 `migrate-db` 入口 | 生产建议 PostgreSQL + Alembic 迁移 |
| 认证权限 | 可选 API Key | 增加登录、角色、项目隔离 |
| 部署 | 本地脚本 + Docker / docker-compose | 增加 CI/CD、TLS 和生产镜像发布流程 |
| 资源限制 | 已有上传大小、扫描文件数、扫描字节数限制 | 增加扫描子进程超时、CPU/内存限制和并发控制 |

## 七、下一步补齐顺序

1. 跑 Devign、Juliet、Big-Vul 1000 条正式对比：多智能体、CodeBERT、GraphCodeBERT、graph-feature、GNN。
2. 为 Big-Vul 增加固定数据切分和 commit 前后完整函数还原。
3. 增加报告下载按钮和评测详情页。
4. 将 Tree-sitter AST 用于函数和调用点提取，减少正则依赖。
5. 将轻量 GNN baseline 升级为更完整的代码属性图训练流程。
6. 增加 Docker、任务队列、认证和资源限制。
