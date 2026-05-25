from __future__ import annotations

import json
from pathlib import Path

from core.types import ScanReport


class JsonReporter:
    def write(self, report: ScanReport, output_path: str) -> str:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path.resolve())
