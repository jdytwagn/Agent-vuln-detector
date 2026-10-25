from __future__ import annotations

from pathlib import Path

from core.types import CandidateVulnerability, ScanReport


class MarkdownReporter:
    def write(self, report: ScanReport, output_path: str) -> str:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(report), encoding="utf-8")
        return str(path.resolve())

    def render(self, report: ScanReport) -> str:
        lines = [
            "# Agent Vulnerability Detection Report",
            "",
            f"- Source: `{report.source_path}`",
            f"- Files scanned: {report.summary['files_scanned']}",
            f"- Functions discovered: {report.summary['functions_discovered']}",
            f"- Candidates: {report.summary['candidate_count']}",
            f"- Reported findings: {report.summary['reported_count']}",
            f"- Confirmed: {report.summary.get('confirmed_count', report.summary['reported_count'])}",
            f"- Needs review: {report.summary.get('review_count', 0)}",
            f"- Filtered: {report.summary.get('filtered_count', 0)}",
            "",
            "## Findings",
            "",
        ]
        if not report.vulnerabilities:
            lines.append("No findings met the reporting threshold.")
            return "\n".join(lines) + "\n"
        for item in report.vulnerabilities:
            lines.extend(self._finding(item))
        return "\n".join(lines) + "\n"

    def _finding(self, item: CandidateVulnerability) -> list[str]:
        flow_steps = item.dataflow.steps if item.dataflow else []
        lines = [
            f"### {item.candidate_id}: {item.rule_evidence.name}",
            "",
            f"- Location: `{item.file_path}:{item.line}` in `{item.function_name}`",
            f"- CWE: {item.rule_evidence.cwe}",
            f"- Sink: `{item.sink}`",
            f"- Decision: `{item.final_decision}`",
            f"- Severity: `{item.final_severity}`",
            f"- Confidence: {item.final_confidence}",
            f"- Exploitability: `{item.exploitability}`",
            f"- Model score: {item.model_score.score if item.model_score else 'n/a'}",
            "",
            "Evidence:",
            f"- Rule: {item.rule_evidence.description}",
            f"- Data flow: {item.dataflow.scope if item.dataflow else 'none'} / reachable={item.dataflow.reachable if item.dataflow else False}",
            f"- Exploitability reason: {item.exploitability_reason}",
            f"- Semantic explanation: {item.semantic_explanation}",
            "",
            "Data-flow steps:",
        ]
        lines.extend([f"- {step}" for step in flow_steps] or ["- No path details available."])
        lines.extend(
            [
                "",
                "Code:",
                "```c",
                item.code,
                "```",
                "",
                f"Recommendation: {item.rule_evidence.recommendation}",
                "",
            ]
        )
        return lines
