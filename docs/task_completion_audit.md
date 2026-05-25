# 任务完成度审计

审计日期：2026-05-16

本文档按用户规划和论文/文档思路检查当前项目完成度。

## 一、总体结论

当前项目已经完成“完整可演示平台”的主干任务：检测引擎、后端 API、Web 前端、真实模型接口、GNN baseline、数据集适配、评测指标、JSON/Markdown 报告和中文文档均已具备。

当前状态适合本地演示、课程/毕设展示和中小规模实验评测；若要上公网生产，还需要补正式登录鉴权、任务队列、生产数据库、进程级资源隔离、审计日志和运维监控。

## 二、文档流程对齐情况

| 文档流程 | 当前完成度 | 说明 |
| --- | --- | --- |
| 源码输入 | 已完成 | CLI、API、Web 支持路径扫描、源码文件上传、zip 上传 |
| 代码预处理 | 部分完成 | 有 Tree-sitter AST 摘要、函数、调用点、调用边、变量引用、CFG/DFG；尚不是 Clang/LLVM 级精确分析 |
| 规则初筛 | 已完成 | CWE/OWASP YAML 规则库和规则智能体已接入 |
| 深度学习打分 | 已完成 | mock、CodeBERT、GraphCodeBERT 可插拔；真实模型已能跑通小样本 |
| 数据流验证 | 部分完成 | 支持函数内、跨函数、跨文件轻量 source-to-sink；别名、指针、结构体精度仍可增强 |
| 语义推理 | 已完成 | 中文模板解释 + 可选 DeepSeek LLM |
| 可利用性判断 | 部分完成 | 已识别可控输入、可达路径和缓解逻辑；缺少严格支配关系和约束证明 |
| 融合决策 | 已完成 | 规则、模型、数据流、可利用性加权输出置信度和风险等级 |
| 漏洞报告 | 已完成 | JSON、Markdown、Web 详情页均可展示 |

## 三、完整平台任务完成情况

| 模块 | 状态 | 说明 |
| --- | --- | --- |
| CLI | 已完成 | `scan`、`evaluate`、`evaluate-baseline`、`evaluate-suite`、`prepare-dataset` |
| FastAPI 后端 | 已完成 | 扫描、上传、报告、规则、评测、数据集适配接口 |
| React 前端 | 已完成 | 仪表盘、扫描、漏洞详情、规则库、评测页 |
| SQLite 存储 | 已完成 | 保存扫描任务、评测任务、报告路径和指标 |
| 真实模型接口 | 已完成 | CodeBERT / GraphCodeBERT 加载、推理、降级 |
| GNN baseline | 已完成首版 | 内置轻量 GCN，可训练、可评测；论文级复现仍需完整 CPG |
| 数据集适配 | 已完成首版 | Juliet C/C++、Devign、Big-Vul/MSR manifest |
| 评测指标 | 已完成 | AUC、F1、FPR、Alerts/KLOC、Valid Ratio、Cross-file Recall、Exploitability Recall、Non-exploit Filter |
| 中文文档 | 已完成 | README、API、架构、模型、数据集、评测、对齐矩阵、生产缺口 |

## 四、本次审计发现并已优化的问题

| 问题 | 优化结果 |
| --- | --- |
| API 缺少模型后端和评测参数校验 | 增加 Pydantic 枚举、阈值范围、GNN 轮次范围、路径非空校验 |
| 评测 manifest 可通过 API 指向任意路径 | 默认限制到项目工作区，可信本地环境可用 `AGENT_DETECTOR_ALLOW_ANY_PATH=true` 放开 |
| CORS 过宽 | 默认仅允许本地前端，支持 `AGENT_DETECTOR_CORS_ORIGINS` 配置 |
| 未知模型后端会静默降级 mock | 改为显式报错，避免实验结果被误认为真实模型 |
| CFG 节点 ID 在跨文件同名函数下可能冲突 | CFG 节点 ID 增加文件哈希前缀 |
| GNN baseline 参数缺少边界保护 | 增加 epochs、hidden_dim、max_nodes 下限，并输出训练/评测重叠样本数 |
| 评测套件中某个 baseline 失败会拖垮整体 | baseline 失败进入 `failed` 字段，模型缺失进入 `skipped` 字段 |
| 语义模板偏英文 | 改为中文模板解释，更贴合中文项目文档 |
| API 缺少最基础鉴权能力 | 增加可选 `AGENT_DETECTOR_API_KEY`，默认本地关闭 |
| 扫描缺少资源上限 | 增加最大文件数、总字节数、单文件字节数限制 |
| 部署只依赖本地脚本 | 增加 Dockerfile、docker-compose、nginx 前端代理和部署说明 |
| SQLite 缺少 schema 版本记录 | 增加 `schema_migrations` 表和 `migrate-db` CLI |
| Big-Vul 修复后样本未转为负样本 | 适配器支持 `func_after/function_after` 等字段和 patch 新增行生成 `label=0` 配对样本；本地 `big_vul_1000.json` 已重新生成 500 正 + 500 负 |

## 五、仍不建议声称已经完成的部分

- 不是工业级静态分析器：当前 CFG/DFG、别名分析、指针分析仍是轻量实现。
- 不是论文级 GNN 复现：当前 GNN baseline 是轻量 GCN，不是完整 Devign/Joern CPG 训练流水线。
- Big-Vul 当前 manifest 已有修复前后配对样本；若要论文级复现，仍建议按 commit checkout 还原完整函数，而不只依赖 diff 片段。
- 生产环境仍缺正式用户认证、队列、PostgreSQL、进程级资源隔离、审计日志和监控。

## 六、下一步建议

1. 跑完 Devign、Juliet、Big-Vul 1000 条完整评测套件，生成正式对比结果。
2. 为 Big-Vul 增加固定 train/validation/test 切分，并逐步补 commit 前后完整函数还原。
3. 将 SQLite 切换为 PostgreSQL，并引入 Alembic 等正式迁移工具。
4. 引入队列任务、扫描子进程超时、CPU/内存限制和并发控制。
5. 将轻量 GNN baseline 升级为 CPG/Joern 风格图构建与固定数据切分。
