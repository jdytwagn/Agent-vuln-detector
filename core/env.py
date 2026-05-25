from __future__ import annotations

import os
from pathlib import Path


def load_env(path: str | None = None, override: bool = False) -> dict[str, str]:
    env_path = Path(path) if path else Path(__file__).resolve().parents[1] / ".env"
    values: dict[str, str] = {}
    if not env_path.exists():
        return values
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        values[key] = value
        if override or key not in os.environ:
            os.environ[key] = value
    return values


def get_env(name: str, default: str = "") -> str:
    load_env()
    return os.environ.get(name, default)
