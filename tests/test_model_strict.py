from __future__ import annotations

import pytest

from models.factory import build_scorer


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
