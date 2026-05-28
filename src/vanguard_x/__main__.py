"""Command-line entry point — ``python -m vanguard_x`` / ``vanguard-x``.

Subcommands::

    vanguard-x version
    vanguard-x config
    vanguard-x init-db
    vanguard-x scan    --target example.com [--scope external]
    vanguard-x monitor --target example.com [--target other.com]
                       [--interval-hours 24] [--scope external]
    vanguard-x analyze --target example.com [--run-id abc] [--json]
    vanguard-x report  --target example.com [--format markdown|html]
"""

from __future__ import annotations

import asyncio
import signal
import sys
from datetime import timedelta
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.table import Table

from vanguard_x import __version__
from vanguard_x.agents.attack import AttackAgent
from vanguard_x.agents.recon import ReconAgent
from vanguard_x.config import Settings, get_settings
from vanguard_x.core.changes import ChangeDetector
from vanguard_x.core.runners import build_runner
from vanguard_x.core.scope import ScopeEnforcer, ScopeViolation
from vanguard_x.db.database import Database, ScanRepository
from vanguard_x.db.schema import FindingRow
from vanguard_x.logging_setup import configure_logging, get_logger
from vanguard_x.models import AnalysisReport, ScanSummary, Severity
from vanguard_x.notifications.telegram import TelegramNotifier
from vanguard_x.pipeline import PipelineOrchestrator, PipelineResult
from vanguard_x.scheduler import ContinuousMonitor
from vanguard_x.tools.gobuster import GobusterWrapper
from vanguard_x.tools.harvester import HarvesterWrapper
from vanguard_x.tools.nmap import NmapWrapper
from vanguard_x.tools.nuclei import NucleiWrapper
from vanguard_x.tools.subfinder import SubfinderWrapper
from vanguard_x.tools.wafw00f import WafW00fWrapper
from vanguard_x.tools.whatweb import WhatWebWrapper

if TYPE_CHECKING:
    from vanguard_x.agents.analyze import AnalyzeAgent

app = typer.Typer(
    name="vanguard-x",
    help="Autonomous agentic pentesting & continuous security monitoring.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
_log = get_logger(__name__)


# -----------------------------------------------------------------------------
@app.command("version")
def cmd_version() -> None:
    """Print the installed VANGUARD-X version."""
    console.print(f"vanguard-x [bold]{__version__}[/bold]")


# -----------------------------------------------------------------------------
@app.command("config")
def cmd_config() -> None:
    """Print the loaded configuration (secrets are masked)."""
    settings = get_settings()
    table = Table(title="VANGUARD-X configuration", show_lines=False)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    visible = settings.model_dump()
    for key in (
        "anthropic_api_key",
        "telegram_bot_token",
    ):
        if visible.get(key):
            visible[key] = "<set>"
    visible["telegram_enabled"] = settings.telegram_enabled
    visible["authorized_targets_list"] = settings.authorized_targets_list

    for k, v in sorted(visible.items()):
        table.add_row(k, str(v))
    console.print(table)


# -----------------------------------------------------------------------------
@app.command("init-db")
def cmd_init_db() -> None:
    """Create database tables (idempotent)."""
    settings = get_settings()
    configure_logging(settings)
    asyncio.run(_init_db(settings))
    console.print(f"[green]Schema ready[/green]: {settings.database_url}")


async def _init_db(settings: Settings) -> None:
    db = Database(settings.database_url)
    try:
        await db.create_all()
    finally:
        await db.dispose()


# -----------------------------------------------------------------------------
@app.command("scan")
def cmd_scan(
    target: str = typer.Option(..., "--target", "-t", help="Bare hostname or IP."),
    scope: str = typer.Option(
        "external", "--scope", "-s", help="Free-form scope label (audit only)."
    ),
) -> None:
    """Run the RECON agent end-to-end on ``--target``."""
    settings = get_settings()
    configure_logging(settings)
    try:
        summary = asyncio.run(_run_recon(settings, target=target, scope_label=scope))
    except ScopeViolation as exc:
        console.print(f"[red]SCOPE VIOLATION[/red]: {exc}")
        sys.exit(2)
    except Exception as exc:
        console.print(f"[red]Scan failed[/red]: {exc}")
        sys.exit(1)

    console.print(
        f"[green]Scan {summary.scan_id} {summary.status.value}[/green] — "
        f"{summary.asset_count} assets, {summary.finding_count} findings."
    )


# -----------------------------------------------------------------------------
@app.command("monitor")
def cmd_monitor(
    targets: list[str] = typer.Option(  # noqa: B008 — idiomatic Typer pattern for repeatable options
        ...,
        "--target",
        "-t",
        help="One or more authorised targets (repeatable). e.g. -t a.com -t b.com",
    ),
    interval_hours: float = typer.Option(
        None,
        "--interval-hours",
        "-i",
        help=(
            "Interval between recon runs per target. "
            "Defaults to VANGUARDX_RECON_INTERVAL_HOURS (24h)."
        ),
    ),
    scope: str = typer.Option(
        "external", "--scope", "-s", help="Free-form scope label (audit only)."
    ),
) -> None:
    """Run the RECON agent on a schedule until interrupted (Ctrl-C / SIGTERM).

    The first scan of every target fires immediately; subsequent scans
    follow ``--interval-hours``. Change-alerts are sent via Telegram when
    new or removed assets are detected against the previous scan.
    """
    settings = get_settings()
    configure_logging(settings)
    interval = timedelta(
        hours=interval_hours if interval_hours is not None else settings.recon_interval_hours
    )
    if interval.total_seconds() <= 0:
        console.print("[red]--interval-hours must be > 0[/red]")
        sys.exit(2)

    try:
        asyncio.run(_run_monitor(settings, targets=targets, interval=interval, scope_label=scope))
    except KeyboardInterrupt:
        console.print("[yellow]Monitor stopped[/yellow].")
    except Exception as exc:
        console.print(f"[red]Monitor failed[/red]: {exc}")
        sys.exit(1)


# =============================================================================
# Async helpers (composition root)
# =============================================================================
def _build_recon_agent(
    settings: Settings,
    *,
    repo: ScanRepository,
    notifier: TelegramNotifier,
) -> ReconAgent:
    scope_enforcer = ScopeEnforcer(settings.authorized_targets_list)
    return ReconAgent(
        nmap=NmapWrapper(
            runner=build_runner(settings, container=settings.nmap_container),
            scope=scope_enforcer,
            timeout=settings.tool_timeout_seconds,
        ),
        harvester=HarvesterWrapper(
            runner=build_runner(settings, container=settings.harvester_container),
            scope=scope_enforcer,
            timeout=settings.tool_timeout_seconds,
        ),
        subfinder=SubfinderWrapper(
            runner=build_runner(settings, container=settings.subfinder_container),
            scope=scope_enforcer,
            timeout=settings.tool_timeout_seconds,
        ),
        whatweb=WhatWebWrapper(
            runner=build_runner(settings, container=settings.whatweb_container),
            scope=scope_enforcer,
            timeout=settings.tool_timeout_seconds,
        ),
        wafw00f=WafW00fWrapper(
            runner=build_runner(settings, container=settings.wafw00f_container),
            scope=scope_enforcer,
            timeout=settings.tool_timeout_seconds,
        ),
        scope=scope_enforcer,
        repository=repo,
        notifier=notifier,
        change_detector=ChangeDetector(repo),
    )


def _build_attack_agent(
    settings: Settings,
    *,
    repo: ScanRepository,
    notifier: TelegramNotifier,
) -> AttackAgent:
    scope_enforcer = ScopeEnforcer(settings.authorized_targets_list)
    return AttackAgent(
        nuclei=NucleiWrapper(
            runner=build_runner(settings, container=settings.nuclei_container),
            scope=scope_enforcer,
            timeout=settings.tool_timeout_seconds,
        ),
        gobuster=GobusterWrapper(
            runner=build_runner(settings, container=settings.gobuster_container),
            scope=scope_enforcer,
            timeout=settings.tool_timeout_seconds,
        ),
        scope=scope_enforcer,
        repository=repo,
        notifier=notifier,
    )


def _build_analyze_agent(
    settings: Settings,
    *,
    repo: ScanRepository,
    notifier: TelegramNotifier,
) -> AnalyzeAgent:
    from vanguard_x.agents.analyze import AnalyzeAgent

    return AnalyzeAgent(
        repository=repo,
        notifier=notifier,
        api_key=settings.anthropic_api_key or "",
        model=settings.llm_model,
    )


async def _run_recon(settings: Settings, *, target: str, scope_label: str) -> ScanSummary:
    db = Database(settings.database_url)
    await db.create_all()
    try:
        repo = ScanRepository(db)
        async with TelegramNotifier.from_settings(settings) as notifier:
            agent = _build_recon_agent(settings, repo=repo, notifier=notifier)
            return await agent.run(target, scope_label=scope_label)
    finally:
        await db.dispose()


async def _run_monitor(  # type: ignore[no-untyped-def]
    settings: Settings,
    *,
    targets: list[str],
    interval: timedelta,
    scope_label: str,
):
    db = Database(settings.database_url)
    await db.create_all()
    try:
        repo = ScanRepository(db)
        async with TelegramNotifier.from_settings(settings) as notifier:
            agent = _build_recon_agent(settings, repo=repo, notifier=notifier)
            monitor = ContinuousMonitor(
                agent,
                targets,
                interval=interval,
                scope_label=scope_label,
            )

            stop_event = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig_name in ("SIGINT", "SIGTERM"):
                sig = getattr(signal, sig_name, None)
                if sig is None:
                    continue
                try:
                    loop.add_signal_handler(sig, stop_event.set)
                except NotImplementedError:
                    # Windows — fall back to default Ctrl-C behaviour.
                    pass

            monitor.start()
            console.print(
                f"[green]Monitoring[/green] {len(monitor.targets)} target(s) "
                f"every {interval.total_seconds() / 3600:.2f}h. Ctrl-C to stop."
            )
            try:
                await stop_event.wait()
            finally:
                await monitor.shutdown(wait=True)
    finally:
        await db.dispose()


# =============================================================================
# Attack + Pipeline commands
# =============================================================================
@app.command("attack")
def cmd_attack(
    targets: list[str] = typer.Option(  # noqa: B008
        ..., "--target", "-t", help="Targets (repeatable)."
    ),
    scope: str = typer.Option("external", "--scope", "-s", help="Scope label."),
) -> None:
    """Run the ATTACK agent on one or more targets."""
    settings = get_settings()
    configure_logging(settings)
    try:
        summary = asyncio.run(_run_attack(settings, targets=targets, scope_label=scope))
    except ScopeViolation as exc:
        console.print(f"[red]SCOPE VIOLATION[/red]: {exc}")
        sys.exit(2)
    except Exception as exc:
        console.print(f"[red]Attack failed[/red]: {exc}")
        sys.exit(1)
    console.print(
        f"[green]Attack scan {summary.scan_id} {summary.status.value}[/green] -- "
        f"{summary.finding_count} findings."
    )


@app.command("pipeline")
def cmd_pipeline(
    target: str = typer.Option(..., "--target", "-t", help="Target domain."),
    scope: str = typer.Option("external", "--scope", "-s", help="Scope label."),
    analyze: bool = typer.Option(False, "--analyze", "-a", help="Run analysis after attack."),
) -> None:
    """Run the full Recon -> Attack pipeline."""
    settings = get_settings()
    configure_logging(settings)
    try:
        result = asyncio.run(
            _run_pipeline(settings, target=target, scope_label=scope, analyze=analyze)
        )
    except ScopeViolation as exc:
        console.print(f"[red]SCOPE VIOLATION[/red]: {exc}")
        sys.exit(2)
    except Exception as exc:
        console.print(f"[red]Pipeline failed[/red]: {exc}")
        sys.exit(1)
    console.print(
        f"[green]Pipeline complete[/green] -- "
        f"Recon: {result.recon_summary.asset_count} assets, "
        f"Attack: {result.total_findings} findings ({result.critical_count} critical)."
    )


@app.command("findings")
def cmd_findings(
    severity: str = typer.Option(None, "--severity", "-S", help="Filter by severity."),
    limit: int = typer.Option(50, "--limit", "-l", help="Max results."),
) -> None:
    """List findings from all scans."""
    settings = get_settings()
    configure_logging(settings)
    results = asyncio.run(_list_findings(settings, severity=severity, limit=limit))
    if not results:
        console.print("[yellow]No findings found.[/yellow]")
        return
    table = Table(title="Findings")
    table.add_column("ID", style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Title")
    table.add_column("Tool")
    table.add_column("CVE")
    for f in results:
        table.add_row(str(f.id), f.severity, f.title[:60], f.source_tool, f.cve or "")
    console.print(table)


@app.command("history")
def cmd_history(
    target: str = typer.Option(..., "--target", "-t", help="Target to query."),
) -> None:
    """Show scan history for a target."""
    settings = get_settings()
    configure_logging(settings)
    summaries = asyncio.run(_get_history(settings, target=target))
    if not summaries:
        console.print("[yellow]No scan history found.[/yellow]")
        return
    table = Table(title=f"Scan history: {target}")
    table.add_column("ID")
    table.add_column("Agent")
    table.add_column("Status")
    table.add_column("Assets")
    table.add_column("Findings")
    table.add_column("Started")
    for s in summaries:
        table.add_row(
            str(s.scan_id),
            "recon/attack",
            s.status.value,
            str(s.asset_count),
            str(s.finding_count),
            s.started_at.strftime("%Y-%m-%d %H:%M"),
        )
    console.print(table)


# =============================================================================
# Analyze + Report commands
# =============================================================================
@app.command("analyze")
def cmd_analyze(
    target: str = typer.Option(..., "--target", "-t", help="Target to analyze."),
    run_id: str = typer.Option(None, "--run-id", "-r", help="Specific scan run_id."),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Run LLM-based analysis on scan findings for a target."""
    settings = get_settings()
    configure_logging(settings)
    if settings.anthropic_api_key is None:
        console.print("[red]Error: VANGUARDX_ANTHROPIC_API_KEY is not set.[/red]")
        sys.exit(1)
    try:
        report = asyncio.run(_run_analyze(settings, target=target, run_id=run_id))
    except Exception as exc:
        console.print(f"[red]Analysis failed[/red]: {exc}")
        sys.exit(1)
    if output_json:
        console.print(report.model_dump_json(indent=2))
    else:
        _print_analysis_table(report)


@app.command("report")
def cmd_report(
    target: str = typer.Option(..., "--target", "-t", help="Target to report on."),
    fmt: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown or html."),
) -> None:
    """Generate a combined report for a target."""
    settings = get_settings()
    configure_logging(settings)
    output = asyncio.run(_generate_report(settings, target=target, fmt=fmt))
    if output is None:
        console.print("[yellow]No data found for target.[/yellow]")
        return
    console.print(output, highlight=False)


# -----------------------------------------------------------------------------
# Additional async helpers
# -----------------------------------------------------------------------------
async def _run_attack(settings: Settings, *, targets: list[str], scope_label: str) -> ScanSummary:
    db = Database(settings.database_url)
    await db.create_all()
    try:
        repo = ScanRepository(db)
        async with TelegramNotifier.from_settings(settings) as notifier:
            agent = _build_attack_agent(settings, repo=repo, notifier=notifier)
            return await agent.run(targets, scope_label=scope_label)
    finally:
        await db.dispose()


async def _run_pipeline(
    settings: Settings, *, target: str, scope_label: str, analyze: bool = False
) -> PipelineResult:
    db = Database(settings.database_url)
    await db.create_all()
    try:
        repo = ScanRepository(db)
        async with TelegramNotifier.from_settings(settings) as notifier:
            recon = _build_recon_agent(settings, repo=repo, notifier=notifier)
            attack = _build_attack_agent(settings, repo=repo, notifier=notifier)
            analyze_agent = None
            if analyze and settings.anthropic_api_key:
                analyze_agent = _build_analyze_agent(settings, repo=repo, notifier=notifier)
            pipeline = PipelineOrchestrator(
                recon_agent=recon,
                attack_agent=attack,
                repository=repo,
                notifier=notifier,
                analyze_agent=analyze_agent,
            )
            return await pipeline.run(target, scope_label=scope_label, analyze=analyze)
    finally:
        await db.dispose()


async def _list_findings(
    settings: Settings, *, severity: str | None, limit: int
) -> list[FindingRow]:
    db = Database(settings.database_url)
    await db.create_all()
    try:
        repo = ScanRepository(db)
        if severity:
            sev = Severity(severity.lower())
            return await repo.get_findings_by_severity(sev, limit=limit)
        all_findings: list[FindingRow] = []
        for sev in Severity:
            all_findings.extend(await repo.get_findings_by_severity(sev, limit=limit))
        return sorted(all_findings, key=lambda f: f.discovered_at, reverse=True)[:limit]
    finally:
        await db.dispose()


async def _get_history(settings: Settings, *, target: str) -> list[ScanSummary]:
    db = Database(settings.database_url)
    await db.create_all()
    try:
        repo = ScanRepository(db)
        return await repo.get_pipeline_results(target)
    finally:
        await db.dispose()


async def _run_analyze(settings: Settings, *, target: str, run_id: str | None) -> AnalysisReport:
    db = Database(settings.database_url)
    await db.create_all()
    try:
        repo = ScanRepository(db)
        async with TelegramNotifier.from_settings(settings) as notifier:
            agent = _build_analyze_agent(settings, repo=repo, notifier=notifier)
            scan_id = int(run_id) if run_id and run_id.isdigit() else None
            return await agent.run(target, scan_id=scan_id)
    finally:
        await db.dispose()


async def _generate_report(settings: Settings, *, target: str, fmt: str) -> str | None:
    db = Database(settings.database_url)
    await db.create_all()
    try:
        repo = ScanRepository(db)
        # Gather scan history
        summaries = await repo.get_pipeline_results(target)
        # Gather analysis reports
        analysis_reports = await repo.list_analysis_reports(target)

        if not summaries and not analysis_reports:
            return None

        # Get latest analysis report if any
        latest_report: AnalysisReport | None = None
        if analysis_reports:
            latest_run_id, _ = analysis_reports[0]
            latest_report = await repo.get_analysis_report(target, latest_run_id)

        return _render_report(target, summaries, latest_report, fmt)
    finally:
        await db.dispose()


def _render_report(
    target: str,
    summaries: list[ScanSummary],
    report: AnalysisReport | None,
    fmt: str,
) -> str:
    """Render a combined report in markdown or html format."""
    sections: list[str] = []

    # Executive Summary
    sections.append("# Security Report: " + target)
    sections.append("")
    if report:
        sections.append("## Executive Summary")
        sections.append("")
        sections.append(report.executive_summary)
        sections.append("")

    # Scan History
    if summaries:
        sections.append("## Scan History")
        sections.append("")
        sections.append("| ID | Status | Assets | Findings | Started |")
        sections.append("|---|---|---|---|---|")
        for s in summaries[:10]:
            sections.append(
                f"| {s.scan_id} | {s.status.value} | {s.asset_count} "
                f"| {s.finding_count} | {s.started_at.strftime('%Y-%m-%d %H:%M')} |"
            )
        sections.append("")

    # Findings Summary
    if report:
        sections.append("## Findings Summary")
        sections.append("")
        sections.append(f"Total findings analyzed: {report.findings_analyzed}")
        sections.append("")
        if report.triage:
            sections.append("| Finding | Verdict | Confidence |")
            sections.append("|---|---|---|")
            for t in report.triage[:20]:
                sections.append(f"| {t.finding_id} | {t.verdict.value} | {t.confidence}% |")
            sections.append("")

        # Attack Paths
        if report.attack_paths:
            sections.append("## Attack Paths")
            sections.append("")
            for ap in report.attack_paths:
                sections.append(f"### {ap.title}")
                sections.append(
                    f"Severity: {ap.severity.value} | Exploitability: {ap.exploitability_score:.2f}"
                )
                sections.append("")
                for i, step in enumerate(ap.steps, 1):
                    sections.append(f"{i}. {step}")
                sections.append("")

        # Remediation Plan
        if report.remediation_plan:
            sections.append("## Remediation Plan")
            sections.append("")
            for r in report.remediation_plan:
                sections.append(f"### {r.priority}. {r.title}")
                sections.append(f"Effort: {r.effort.value}")
                sections.append("")
                sections.append(r.description)
                sections.append("")

    md_content = "\n".join(sections)

    if fmt == "html":
        return (
            "<!DOCTYPE html>\n<html>\n<head><title>Security Report: "
            + target
            + "</title></head>\n<body>\n<pre>\n"
            + md_content
            + "\n</pre>\n</body>\n</html>"
        )
    return md_content


def _print_analysis_table(report: AnalysisReport) -> None:
    """Print analysis report as rich tables."""
    console.print(f"\n[bold]Analysis Report: {report.target}[/bold]")
    console.print(f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}")
    console.print(f"Findings analyzed: {report.findings_analyzed}\n")

    # Triage table
    if report.triage:
        triage_table = Table(title="Triage Results")
        triage_table.add_column("Finding", style="cyan")
        triage_table.add_column("Verdict", style="bold")
        triage_table.add_column("Confidence")
        triage_table.add_column("Reasoning")
        for t in report.triage:
            triage_table.add_row(
                t.finding_id, t.verdict.value, f"{t.confidence}%", t.reasoning[:60]
            )
        console.print(triage_table)

    # Attack paths
    if report.attack_paths:
        ap_table = Table(title="Attack Paths")
        ap_table.add_column("Title", style="cyan")
        ap_table.add_column("Severity", style="bold")
        ap_table.add_column("Exploitability")
        ap_table.add_column("Steps")
        for ap in report.attack_paths:
            ap_table.add_row(
                ap.title,
                ap.severity.value,
                f"{ap.exploitability_score:.2f}",
                str(len(ap.steps)),
            )
        console.print(ap_table)

    # Executive summary
    console.print(f"\n[bold]Executive Summary:[/bold]\n{report.executive_summary}")


# -----------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    app()
