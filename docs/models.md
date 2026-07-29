# 真实模型接入说明

本文档记录当前已经下载到本机并通过加载验证的漏洞检测模型。

## 本地模型目录

```text
storage/models/
  codebert-devign-code-vulnerability-detector-git/
    config.json
    model.safetensors
    vocab.json
    merges.txt
    tokenizer_config.json
    special_tokens_map.json
  graphcodebert-devign-code-vulnerability-detector-git/
    config.json
    model.safetensors
    vocab.json
    merges.txt
    tokenizer_config.json
    special_tokens_map.json
  codebert-defect-detection-git/
```

## 已验证模型

| 模型 | 来源 | 本地路径 | 状态 |
| --- | --- | --- | --- |
| CodeBERT Devign 微调模型 | `mahdin70/codebert-devign-code-vulnerability-detector` | `storage/models/codebert-devign-code-vulnerability-detector-git` | 已下载，已加载，已跑通小样本 |
| GraphCodeBERT Devign 微调模型 | `mahdin70/graphcodebert-devign-code-vulnerability-detector` | `storage/models/graphcodebert-devign-code-vulnerability-detector-git` | 已下载，已加载，已跑通小样本 |
| CodeBERT Defect Detection 备用模型 | `phamtungthuy/codebert-defect-detection` | `storage/models/codebert-defect-detection-git` | 已下载，可作为备用分类模型 |

## 依赖说明

当前环境需要 `transformers`、`torch`、`safetensors` 和兼容版本的 `huggingface-hub`。已修正过的关键依赖约束：

```powershell
python -m pip install "huggingface-hub>=0.34.0,<1.0"
```

说明：此前 `huggingface-hub==1.6.0` 与当前 `transformers` 不兼容，会导致模型加载失败并降级为 mock scorer。

## 运行真实模型评测

正式实验建议加 `--strict-model`。开启后如果模型路径、依赖或权重加载失败，系统会直接报错；不开启时系统保留 mock fallback，适合课堂演示和离线联调。

模型的 `config.json` 应使用 `vulnerable/safe` 等有语义的 `id2label`。如果模型只提供 `LABEL_0/LABEL_1`，需要在 `.env` 中显式设置正类，例如 `AGENT_DETECTOR_MODEL_POSITIVE_LABEL=LABEL_1`，避免标签方向被错误反转。

CodeBERT：

```powershell
python main.py evaluate storage/datasets/manifests/devign_1000.json --model-backend codebert --model-path storage/models/codebert-devign-code-vulnerability-detector-git --strict-model --output out/devign_1000_codebert_eval.json
```

GraphCodeBERT：

```powershell
python main.py evaluate storage/datasets/manifests/devign_1000.json --model-backend graphcodebert --model-path storage/models/graphcodebert-devign-code-vulnerability-detector-git --strict-model --output out/devign_1000_graphcodebert_eval.json
```

## 运行模型 baseline

CodeBERT baseline：

```powershell
python main.py evaluate-baseline storage/datasets/manifests/devign_1000.json --backend codebert --model-path storage/models/codebert-devign-code-vulnerability-detector-git --strict-model --output out/devign_1000_codebert_baseline.json
```

GraphCodeBERT baseline：

```powershell
python main.py evaluate-baseline storage/datasets/manifests/devign_1000.json --backend graphcodebert --model-path storage/models/graphcodebert-devign-code-vulnerability-detector-git --strict-model --output out/devign_1000_graphcodebert_baseline.json
```

GNN baseline：

```powershell
python main.py evaluate-baseline storage/datasets/manifests/devign_1000.json --backend gnn --epochs 20 --output out/devign_1000_gnn_baseline.json
```

完整评测套件：

```powershell
python main.py evaluate-suite storage/datasets/manifests/devign_1000.json --gnn-epochs 20 --output out/devign_1000_suite.json
```

说明：`evaluate-baseline --backend codebert/graphcodebert` 是纯模型 baseline，会直接对 manifest 样本源码打分；`evaluate-baseline --backend gnn` 是可训练轻量 GCN baseline；`evaluate --model-backend codebert/graphcodebert` 是完整多智能体框架，只是把真实模型作为其中一个智能体。

当前模型输入统一使用 tokenizer 截断策略：`truncation=True, max_length=512`。这可以避免长函数或长文件超过 CodeBERT/GraphCodeBERT 最大位置长度，并保证 baseline 与智能体模型打分使用一致的长度约束。

## 已完成的小样本验证

以下命令已经跑通：

```powershell
python main.py evaluate out/checks/devign_5_manifest.json --model-backend codebert --model-path storage/models/codebert-devign-code-vulnerability-detector-git --output out/checks/devign_5_codebert_eval.json
python main.py evaluate out/checks/devign_5_manifest.json --model-backend graphcodebert --model-path storage/models/graphcodebert-devign-code-vulnerability-detector-git --output out/checks/devign_5_graphcodebert_eval.json
python main.py evaluate-baseline out/checks/devign_5_manifest.json --backend codebert --model-path storage/models/codebert-devign-code-vulnerability-detector-git --output out/checks/devign_5_codebert_baseline.json
python main.py evaluate-baseline out/checks/devign_5_manifest.json --backend graphcodebert --model-path storage/models/graphcodebert-devign-code-vulnerability-detector-git --output out/checks/devign_5_graphcodebert_baseline.json
```

小样本只用于验证链路，不用于论文或报告结论。正式指标应在 `devign_1000.json` 或更大规模 manifest 上运行，并记录阈值校准结果。

## 当前仍需增强

- 真实评测结果还没有在 1000 条或全量数据集上跑完。
- 若要复现实验表格，需要固定随机种子、样本切分、阈值策略和硬件环境。
- 当前 GNN baseline 已经可训练、可评测，但仍是轻量 GCN 实现。若要达到论文复现级别，还需要补充 Devign/Joern 风格代码属性图、固定 train/validation/test 切分和更完整的图模型训练配置。
