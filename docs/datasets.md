# 本地数据集说明

本文档记录当前已经下载到本机并转换为统一 manifest 的测试集。当前检测引擎默认面向 C/C++，因此 C/C++ Juliet、Devign 和 Big-Vul/MSR 可以进入评测流程；Find Security Bugs Juliet 是 Java 数据集，已经下载但暂不纳入 C/C++ 引擎评测。

## 本地目录

```text
storage/datasets/
  raw/
    juliet-test-suite-c/
    juliet-test-suite-java/
    devign_zenodo/
      data_C_Devign_test.csv
    MSR_20_Code_vulnerability_CSV_Dataset/
      all_c_cpp_release2.0.csv
  manifests/
    juliet_c_1000.json
    devign_1000.json
    big_vul_1000.json
  materialized/
    devign/
    big_vul/
```

## 已生成的 manifest

| 数据集 | Manifest | 样本数 | 正样本 | 负样本 | 说明 |
| --- | --- | ---: | ---: | ---: | --- |
| Juliet C/C++ | `storage/datasets/manifests/juliet_c_1000.json` | 1000 | 892 | 108 | 从 `testcases` 下抽取 C/C++ 文件，按文件名和 Juliet good/bad 结构生成标签 |
| Devign | `storage/datasets/manifests/devign_1000.json` | 1000 | 487 | 513 | 从 Zenodo 的 `data_C_Devign_test.csv` 抽取函数代码并物化为本地 `.c` 文件 |
| Big-Vul/MSR | `storage/datasets/manifests/big_vul_1000.json` | 1000 | 500 | 500 | 已重新生成正负配对 manifest；漏洞样本来自修复前函数，负样本来自修复后函数或 patch 新增行 |

## 直接运行评测

```powershell
python main.py evaluate storage/datasets/manifests/juliet_c_1000.json --output out/juliet_c_eval.json
python main.py evaluate storage/datasets/manifests/devign_1000.json --output out/devign_eval.json
python main.py evaluate storage/datasets/manifests/big_vul_1000.json --output out/big_vul_eval.json
```

如果要启用真实模型评分：

```powershell
python main.py evaluate storage/datasets/manifests/devign_1000.json --model-backend codebert --model-path D:\models\codebert-vuln --output out/devign_codebert_eval.json
python main.py evaluate storage/datasets/manifests/devign_1000.json --model-backend graphcodebert --model-path D:\models\graphcodebert-vuln --output out/devign_graphcodebert_eval.json
```

如果要运行 baseline：

```powershell
python main.py evaluate-baseline storage/datasets/manifests/devign_1000.json --backend graph-feature --output out/devign_graph_feature_baseline.json
python main.py evaluate-baseline storage/datasets/manifests/devign_1000.json --backend gnn --epochs 20 --output out/devign_gnn_baseline.json
python main.py evaluate-baseline storage/datasets/manifests/devign_1000.json --backend codebert --model-path D:\models\codebert-vuln --output out/devign_codebert_baseline.json
python main.py evaluate-baseline storage/datasets/manifests/devign_1000.json --backend graphcodebert --model-path D:\models\graphcodebert-vuln --output out/devign_graphcodebert_baseline.json
python main.py evaluate-suite storage/datasets/manifests/devign_1000.json --gnn-epochs 20 --output out/devign_suite.json
```

## 重新生成 manifest

```powershell
python main.py prepare-dataset juliet-c storage/datasets/raw/juliet-test-suite-c --output storage/datasets/manifests/juliet_c_1000.json --materialize-dir storage/datasets/materialized --limit 1000
python main.py prepare-dataset devign storage/datasets/raw/devign_zenodo/data_C_Devign_test.csv --output storage/datasets/manifests/devign_1000.json --materialize-dir storage/datasets/materialized --limit 1000
python main.py prepare-dataset big-vul storage/datasets/raw/MSR_20_Code_vulnerability_CSV_Dataset/all_c_cpp_release2.0.csv --output storage/datasets/manifests/big_vul_1000.json --materialize-dir storage/datasets/materialized --limit 1000
```

## Big-Vul 正负样本说明

Big-Vul / MSR 适配器现在会优先读取 `func_before/function_before` 作为漏洞样本；如果同一行存在 `func_after/function_after/fixed_func/patched_func` 等修复后函数，会额外生成一个 `label=0` 的负样本，并用 `paired_with` 记录配对关系。

如果原 CSV 没有修复后完整函数体，适配器会回退到 `files_changed` patch 元数据：修复前样本抽取上下文和删除行，修复后负样本抽取上下文和新增行。当前本地 `big_vul_1000.json` 已按该逻辑重新生成，包含 500 个漏洞样本和 500 个修复后负样本。

## 当前限制

- `juliet-test-suite-java` 已下载，但它是 Java 数据集。要纳入正式评测，需要新增 Java 解析器、Java 规则库、Java source/sink 和报告字段。
- Big-Vul/MSR 的 patch 回退样本是从 diff 中抽取的近似函数上下文，适合平台联调和初步评测；如果要做严格论文级复现，仍建议按 commit checkout 还原修复前后完整函数。
- CodeBERT、GraphCodeBERT 需要本地模型目录。没有模型时，系统可以用 mock scorer、graph-feature baseline 或 `evaluate-suite --skip-code-models` 保证流程可运行。
- 当前 GNN baseline 是项目内置轻量训练流程，不需要外部模型权重；正式论文级复现仍建议补充固定数据切分和更完整的代码属性图构建。
