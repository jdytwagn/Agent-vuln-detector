from __future__ import annotations

from pathlib import Path

from core.types import Rule


LIST_FIELDS = {"source_types", "sink_types", "preconditions", "filters", "tags"}


def load_rules(path: str) -> list[Rule]:
    """Load a small YAML subset used by cwe_rules.yaml without external deps."""
    text = Path(path).read_text(encoding="utf-8")
    items: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith("- "):
            if current:
                items.append(current)
            current = {}
            line = line[2:]
        if ":" not in line or current is None:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key in LIST_FIELDS:
            current[key] = [item.strip() for item in value.split(",") if item.strip()]
        else:
            current[key] = value
    if current:
        items.append(current)
    return [Rule(**item) for item in items]
