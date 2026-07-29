from __future__ import annotations

import pytest

from models.factory import build_scorer
from models.codebert_scorer import CodeBERTScorer


def test_strict_model_mode_fails_when_model_is_unavailable() -> None:
    with pytest.raises(RuntimeError):
        build_scorer(
            "codebert",
            "",
            None,
            strict_model=True,
        )


def test_non_strict_model_mode_keeps_fallback_available() -> None:
    scorer = build_scorer(
        "codebert",
        "",
        None,
        strict_model=False,
    )

    assert getattr(scorer, "available", False) is False


def test_model_positive_label_is_inferred_only_from_descriptive_config() -> None:
    scorer = CodeBERTScorer.__new__(CodeBERTScorer)

    assert scorer._resolve_positive_labels({0: "safe", 1: "vulnerable"}) == {"vulnerable"}
    assert scorer._resolve_positive_labels({0: "LABEL_0", 1: "LABEL_1"}) == set()
