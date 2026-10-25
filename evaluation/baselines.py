from __future__ import annotations


DOCUMENT_BASELINES_NOTE = "这些数值是文档中的参考常数，不是本次运行测得的结果。"


def evaluation_payload(metrics: dict) -> dict:
    return {
        "proposed_agent": metrics,
        "document_baselines_note": DOCUMENT_BASELINES_NOTE,
        "document_baselines": DOCUMENT_BASELINES,
    }


DOCUMENT_BASELINES = [
    {
        "method": "CodeBERT",
        "measured": False,
        "auc": 0.94,
        "f1": 0.82,
        "fpr": 0.26,
        "alerts_per_kloc": 16.4,
        "valid_ratio": 0.29,
        "cross_file_recall": 0.44,
        "exploitability_recall": 0.41,
        "non_exploit_filter": 0.15,
    },
    {
        "method": "GraphCodeBERT",
        "measured": False,
        "auc": 0.95,
        "f1": 0.84,
        "fpr": 0.24,
        "alerts_per_kloc": 15.1,
        "valid_ratio": 0.31,
        "cross_file_recall": 0.47,
        "exploitability_recall": 0.43,
        "non_exploit_filter": 0.18,
    },
]
