"""ANALYZE agent -- Phase 3 Month 5.

Pipeline:
    fetch findings -> build prompt -> call Claude with tool_use
    -> parse structured response -> persist AnalysisReport -> notify

Uses the Anthropic SDK with tool_use to get structured output from Claude.
Handles chunking for large finding sets (>50 findings).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import anthropic

from vanguard_x.db.database import ScanRepository
from vanguard_x.db.schema import FindingRow
from vanguard_x.logging_setup import get_logger
from vanguard_x.models import (
    AnalysisReport,
    AttackPath,
    RemediationItem,
    Severity,
    TriageResult,
    TriageVerdict,
)
from vanguard_x.notifications.telegram import TelegramNotifier

_log = get_logger(__name__)

_BATCH_SIZE = 50

_SYSTEM_PROMPT = (
    "You are a senior penetration tester performing a structured triage of "
    "vulnerability scan findings. Your task is to:\n"
    "1. Classify each finding as true_positive, false_positive, or needs_review "
    "with a confidence score (0-100) and reasoning.\n"
    "2. Identify plausible multi-step attack paths from the findings.\n"
    "3. Provide a concise executive summary of the security posture.\n"
    "4. Create a prioritized remediation plan with effort estimates.\n\n"
    "Use the produce_analysis_report tool to return your structured analysis."
)

_TRIAGE_ONLY_SYSTEM_PROMPT = (
    "You are a senior penetration tester performing a structured triage of "
    "vulnerability scan findings. Classify each finding as true_positive, "
    "false_positive, or needs_review with a confidence score (0-100) and reasoning.\n\n"
    "Use the produce_triage_batch tool to return your structured triage results."
)

_TRIAGE_ITEM_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "needs_review"]},
        "confidence": {"type": "integer"},
        "reasoning": {"type": "string"},
    },
    "required": ["finding_id", "verdict", "confidence", "reasoning"],
}

_FULL_TOOL_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "findings_analyzed": {"type": "integer"},
        "triage": {
            "type": "array",
            "items": _TRIAGE_ITEM_SCHEMA,
        },
        "attack_paths": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "steps": {"type": "array", "items": {"type": "string"}},
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "exploitability_score": {"type": "number"},
                },
                "required": ["id", "title", "steps", "severity", "exploitability_score"],
            },
        },
        "executive_summary": {"type": "string"},
        "remediation_plan": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "priority": {"type": "integer"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "effort": {"type": "string", "enum": ["low", "medium", "high"]},
                    "affected_findings": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "priority",
                    "title",
                    "description",
                    "effort",
                    "affected_findings",
                ],
            },
        },
    },
    "required": [
        "findings_analyzed",
        "triage",
        "attack_paths",
        "executive_summary",
        "remediation_plan",
    ],
}

_TRIAGE_BATCH_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "triage": {
            "type": "array",
            "items": _TRIAGE_ITEM_SCHEMA,
        },
    },
    "required": ["triage"],
}

_FINAL_TOOL_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "attack_paths": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "steps": {"type": "array", "items": {"type": "string"}},
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "exploitability_score": {"type": "number"},
                },
                "required": ["id", "title", "steps", "severity", "exploitability_score"],
            },
        },
        "executive_summary": {"type": "string"},
        "remediation_plan": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "priority": {"type": "integer"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "effort": {"type": "string", "enum": ["low", "medium", "high"]},
                    "affected_findings": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "priority",
                    "title",
                    "description",
                    "effort",
                    "affected_findings",
                ],
            },
        },
    },
    "required": ["attack_paths", "executive_summary", "remediation_plan"],
}


class AnalyzeAgent:
    """Runs LLM-based analysis of vulnerability scan findings."""

    AGENT_NAME = "analyze"

    def __init__(
        self,
        *,
        repository: ScanRepository,
        notifier: TelegramNotifier,
        api_key: str,
        model: str = "claude-opus-4-5",
    ) -> None:
        if not api_key.strip():
            raise ValueError("api_key must not be empty or whitespace-only")
        self._repository = repository
        self._notifier = notifier
        self._api_key = api_key
        self._model = model
        self._client = anthropic.AsyncAnthropic(api_key=self._api_key)

    async def run(
        self, target: str, *, scan_id: int | None = None, scope_label: str = "external"
    ) -> AnalysisReport:
        """Execute the full ANALYZE pipeline and return an :class:`AnalysisReport`."""
        _log.info("analyze.start", target=target, scan_id=scan_id, scope=scope_label)

        analyze_scan_id = await self._repository.create_scan(
            target=target, scope_label=scope_label, agent=self.AGENT_NAME
        )
        await self._repository.mark_running(analyze_scan_id)

        try:
            findings = await self._fetch_findings(target, scan_id)
            report = await self._analyze_findings(target, findings)

            await self._repository.save_analysis_report(report, scan_id=analyze_scan_id)
            await self._repository.mark_done(analyze_scan_id)
            await self._notifier.send_analysis_summary(report)
            return report

        except Exception as exc:
            await self._repository.mark_failed(analyze_scan_id, error=str(exc))
            raise

    async def _fetch_findings(self, target: str, scan_id: int | None) -> list[FindingRow]:
        """Fetch findings from the repository."""
        if scan_id is not None:
            return await self._repository.list_findings(scan_id)

        # Get most recent completed scan for target
        latest_scan_id = await self._repository.get_latest_completed_scan_id(target)
        if latest_scan_id is None:
            return []
        return await self._repository.list_findings(latest_scan_id)

    async def _analyze_findings(self, target: str, findings: list[FindingRow]) -> AnalysisReport:
        """Run the LLM analysis, with chunking for large finding sets."""
        if len(findings) <= _BATCH_SIZE:
            return await self._single_batch_analysis(target, findings)
        return await self._chunked_analysis(target, findings)

    async def _single_batch_analysis(
        self, target: str, findings: list[FindingRow]
    ) -> AnalysisReport:
        """Single-call analysis for <=50 findings."""
        user_message = self._format_findings(findings)

        response = await self._client.messages.create(
            model=self._model,
            max_tokens=8192,
            system=_SYSTEM_PROMPT,
            tools=[
                {
                    "name": "produce_analysis_report",
                    "description": "Submit the structured analysis report.",
                    "input_schema": _FULL_TOOL_SCHEMA,
                }
            ],
            messages=[{"role": "user", "content": user_message}],
        )

        self._check_stop_reason(response, "produce_analysis_report")
        data = self._extract_tool_use(response, "produce_analysis_report")
        return self._build_report(target, data, len(findings))

    async def _chunked_analysis(self, target: str, findings: list[FindingRow]) -> AnalysisReport:
        """Multi-call analysis: triage in batches, then final synthesis."""
        all_triage: list[dict[str, Any]] = []

        # Triage batches
        for i in range(0, len(findings), _BATCH_SIZE):
            batch = findings[i : i + _BATCH_SIZE]
            user_message = self._format_findings(batch)

            response = await self._client.messages.create(
                model=self._model,
                max_tokens=8192,
                system=_TRIAGE_ONLY_SYSTEM_PROMPT,
                tools=[
                    {
                        "name": "produce_triage_batch",
                        "description": "Submit triage results for this batch.",
                        "input_schema": _TRIAGE_BATCH_SCHEMA,
                    }
                ],
                messages=[{"role": "user", "content": user_message}],
            )

            self._check_stop_reason(response, "produce_triage_batch")
            batch_data = self._extract_tool_use(response, "produce_triage_batch")
            triage_items: list[dict[str, Any]] = batch_data.get("triage", [])
            all_triage.extend(triage_items)

        # Final synthesis call
        synthesis_prompt = (
            "Based on the following triage results, identify attack paths, "
            "provide an executive summary, and create a remediation plan.\n\n"
            f"Triage results:\n{json.dumps(all_triage, indent=2)}"
        )

        response = await self._client.messages.create(
            model=self._model,
            max_tokens=8192,
            system=_SYSTEM_PROMPT,
            tools=[
                {
                    "name": "produce_analysis_report",
                    "description": "Submit the final analysis report.",
                    "input_schema": _FINAL_TOOL_SCHEMA,
                }
            ],
            messages=[{"role": "user", "content": synthesis_prompt}],
        )

        self._check_stop_reason(response, "produce_analysis_report")
        final_data = self._extract_tool_use(response, "produce_analysis_report")

        # Combine triage + final synthesis
        combined: dict[str, Any] = {
            "findings_analyzed": len(findings),
            "triage": all_triage,
            "attack_paths": final_data.get("attack_paths", []),
            "executive_summary": final_data.get("executive_summary", ""),
            "remediation_plan": final_data.get("remediation_plan", []),
        }
        return self._build_report(target, combined, len(findings))

    @staticmethod
    def _format_findings(findings: list[FindingRow]) -> str:
        """Format findings as text for the LLM prompt."""
        lines: list[str] = [f"Total findings to analyze: {len(findings)}\n"]
        for i, f in enumerate(findings, 1):
            lines.append(
                f"Finding #{i} (id={f.id}):\n"
                f"  Severity: {f.severity}\n"
                f"  Title: {f.title}\n"
                f"  Description: {f.description}\n"
                f"  Tool: {f.source_tool}\n"
                f"  CVE: {f.cve or 'N/A'}\n"
                f"  Confidence: {f.confidence}\n"
            )
        return "\n".join(lines)

    @staticmethod
    def _extract_tool_use(response: anthropic.types.Message, tool_name: str) -> dict[str, Any]:
        """Extract the input dict from a tool_use content block."""
        for block in response.content:
            if block.type == "tool_use" and block.name == tool_name:
                return block.input
        msg = f"No tool_use block with name '{tool_name}' found in response"
        raise ValueError(msg)

    @staticmethod
    def _check_stop_reason(response: anthropic.types.Message, tool_name: str) -> None:
        """Raise if response was truncated due to max_tokens."""
        if response.stop_reason == "max_tokens":
            raise RuntimeError(
                f"Anthropic response truncated (max_tokens reached) for tool '{tool_name}'"
            )

    @staticmethod
    def _build_report(target: str, data: dict[str, Any], findings_count: int) -> AnalysisReport:
        """Construct an AnalysisReport from parsed tool_use data."""
        triage_raw: list[dict[str, Any]] = data.get("triage", [])
        triage = [
            TriageResult(
                finding_id=str(t["finding_id"]),
                verdict=TriageVerdict(t["verdict"]),
                confidence=int(t["confidence"]),
                reasoning=str(t["reasoning"]),
            )
            for t in triage_raw
        ]

        attack_paths_raw: list[dict[str, Any]] = data.get("attack_paths", [])
        attack_paths = [
            AttackPath(
                id=str(ap["id"]),
                title=str(ap["title"]),
                steps=list(ap["steps"]),
                severity=Severity(ap["severity"]),
                exploitability_score=float(ap["exploitability_score"]),
            )
            for ap in attack_paths_raw
        ]

        remediation_raw: list[dict[str, Any]] = data.get("remediation_plan", [])
        remediation_plan = [
            RemediationItem(
                priority=int(r["priority"]),
                title=str(r["title"]),
                description=str(r["description"]),
                effort=r["effort"],
                affected_findings=list(r["affected_findings"]),
            )
            for r in remediation_raw
        ]

        return AnalysisReport(
            target=target,
            generated_at=datetime.now(UTC),
            findings_analyzed=findings_count,
            triage=triage,
            attack_paths=attack_paths,
            executive_summary=str(data.get("executive_summary", "")),
            remediation_plan=remediation_plan,
        )
