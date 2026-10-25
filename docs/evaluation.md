# 实验评测说明

评测模块用于复现文档中的两类指标：

- 传统分类指标：AUC、F1。
- 工程级指标：FPR、Alerts/KLOC、Valid Ratio、Cross-file Recall、Exploitability Recall、Non-exploit Filter。

`valid_ratio` 是样本级精确率：预测为漏洞的样本中，标签确实为漏洞的比例。它不再用告警条数做分母。多智能体评测的 `alerts_per_kloc` 只统计没有被过滤成 `filtered_false_positive` 的告警。

`evaluation/sample_manifest.json` 的跨文件样本只指向 `tests/samples/cross_file`，避免把单文件正负样本再扫进同一次评测。`evaluate` 输出里的 `document_baselines` 是文档参考常数，并带有 `measured: false`，不是本次运行测得的结果。

某个基线抛错时，`evaluate-suite` 以退出码 2 结束。缺少 PyTorch 时 GNN 记入 `skipped`，不让整次套件失败。

## 运行示例

```powershell
python main.py evaluate evaluation/sample_manifest.json --output out/evaluation.json
```

如果要在评测中启用 DeepSeek 语义推理：

```powershell
python main.py evaluate evaluation/sample_manifest.json --output out/evaluation_llm.json --enable-llm-semantics
```

## Baseline 评测入口

`evaluate` 表示完整多智能体框架评测；`evaluate-baseline` 表示基线模型评测。

对于 `codebert` 和 `graphcodebert`，baseline 会直接读取 manifest 中每个样本的源码文本并让模型打分，不依赖规则智能体先命中候选漏洞点。这用于对齐文档中的 CodeBERT / GraphCodeBERT 分类基线。

未显式传入阈值时，系统会按固定随机种子进行分层拆分：只在 calibration 子集选择阈值，并在不重叠的 evaluation 子集报告指标；样本过少、无法安全拆分时使用固定阈值 `0.5`，不会在测试标签上调参。

CodeBERT / GraphCodeBERT 模型 baseline：

```powershell
python main.py evaluate-baseline storage/datasets/manifests/devign_1000.json --backend codebert --model-path storage/models/codebert-devign-code-vulnerability-detector-git --output out/devign_codebert_baseline.json
python main.py evaluate-baseline storage/datasets/manifests/devign_1000.json --backend graphcodebert --model-path storage/models/graphcodebert-devign-code-vulnerability-detector-git --output out/devign_graphcodebert_baseline.json
```

图特征 baseline：

```powershell
python main.py evaluate-baseline evaluation/sample_manifest.json --backend graph-feature --output out/graph_feature_baseline.json
```

GNN baseline：

```powershell
python main.py evaluate-baseline evaluation/sample_manifest.json --backend gnn --epochs 20 --output out/gnn_baseline.json
```

说明：`graph-feature` 是轻量图特征 baseline；`gnn` 是当前项目内置的可训练轻量 GCN baseline，会基于预处理智能体生成的函数、调用点、CFG、DFG 图训练并输出同一套指标。它用于对齐文档中的 GNN 基线实验入口，但不是完整 Devign/Joern 风格图神经网络复现。

## 完整评测套件

如果要一次性运行“多智能体框架 + CodeBERT + GraphCodeBERT + 图特征 baseline + GNN baseline”，可以使用：

```powershell
python main.py evaluate-suite storage/datasets/manifests/devign_1000.json --model-backend mock --gnn-epochs 20 --output out/devign_1000_suite.json
```

如果只想快速验证流程，不加载 CodeBERT/GraphCodeBERT：

```powershell
python main.py evaluate-suite evaluation/sample_manifest.json --skip-code-models --gnn-epochs 1 --output out/evaluation_suite_sample.json
```

前端“评测”页面也支持勾选“运行完整基线套件”，用于通过 Web 触发同样的后端评测流程。

## 准备你的三个测试集

### Juliet Test Suite C/C++

适用仓库：`https://github.com/arichardson/juliet-test-suite-c`

```powershell
python main.py prepare-dataset juliet-c D:\datasets\juliet-test-suite-c --output evaluation/juliet_c_manifest.json --limit 1000
python main.py evaluate evaluation/juliet_c_manifest.json --output out/juliet_c_eval.json
```

说明：该仓库的 C/C++ 用例位于 `testcases` 目录，按 CWE 组织。适配器会扫描 `.c/.cpp/.h/.hpp` 文件并生成样本。

### Juliet Java / Find Security Bugs

仓库：`https://github.com/find-sec-bugs/juliet-test-suite`

该数据集是 Java 版本 Juliet。当前项目检测引擎只支持 C/C++，因此不会把它纳入正式评测。若要使用它，需要新增 Java 文件扫描、Java AST、Java source/sink 规则和 Java 报告字段。

### Devign

来源：`https://zenodo.org/records/10975439`

下载后，如果得到 CSV/JSON/JSONL 文件，可以运行：

```powershell
python main.py prepare-dataset devign D:\datasets\devign\devign.csv --output evaluation/devign_manifest.json --materialize-dir storage/datasets --limit 1000
python main.py evaluate evaluation/devign_manifest.json --output out/devign_eval.json
```

适配器会优先读取 `func`、`function`、`code`、`source` 等字段作为函数代码，读取 `target`、`label`、`vul`、`vulnerable` 作为标签。

### Big-Vul / MSR

适用仓库：`https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset`

```powershell
python main.py prepare-dataset big-vul D:\datasets\MSR_20_Code_vulnerability_CSV_Dataset\all_c_cpp_release2.0.csv --output evaluation/big_vul_manifest.json --materialize-dir storage/datasets --limit 1000
python main.py evaluate evaluation/big_vul_manifest.json --output out/big_vul_eval.json
```

适配器会优先读取 `func_before`、`function_before`、`code`、`func` 等字段作为修复前检测代码，读取 `vul`、`target`、`label`、`vulnerable` 作为标签。

如果同一行存在 `func_after`、`function_after`、`fixed_func`、`patched_func` 等修复后函数，适配器会额外生成 `label=0` 的修复后负样本，并通过 `paired_with` 记录与漏洞样本的配对关系。

如果 Big-Vul/MSR CSV 中没有完整函数体字段，适配器会回退读取 `files_changed` 中的 patch 元数据：修复前样本抽取上下文和删除行，修复后负样本抽取上下文和新增行，最后物化为可扫描的 `.c` 文件。该方式适合工程联调和初步评测；若要做严格论文级复现，建议后续增加 commit 前后完整函数体还原流程。

## Manifest 格式

```json
{
  "dataset": "Local Demo Subset",
  "samples": [
    {
      "sample_id": "vulnerable_single_file",
      "path": "../tests/samples/vulnerable.c",
      "label": 1,
      "loc": 16,
      "cross_file": false,
      "exploitable": true
    }
  ]
}
```

后续接入 Juliet、Devign、Big-Vul 时，只需要将样本路径和标签整理为同样的 manifest 格式。
