"""Command-line entry point — ``python -m vanguard_x`` / ``vanguard-x``.

Subcommands::

    vanguard-x version
    vanguard-x config
    vanguard-x init-db
    vanguard-x scan    --target example.com [--scope external]
    vanguard-x monitor --target example.com [--target other.com]
                       [--interval-hours 24] [--scope external]
"""

from __future__ import annotations

import asyncio
import signal
import sys
from datetime import timedelta

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
from vanguard_x.models import ScanSummary, Severity
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
) -> None:
    """Run the full Recon -> Attack pipeline."""
    settings = get_settings()
    configure_logging(settings)
    try:
        result = asyncio.run(_run_pipeline(settings, target=target, scope_label=scope))
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
            str(s.scan_id), "recon/attack", s.status.value,
            str(s.asset_count), str(s.finding_count),
            s.started_at.strftime("%Y-%m-%d %H:%M"),
        )
    console.print(table)


# -----------------------------------------------------------------------------
# Additional async helpers
# -----------------------------------------------------------------------------
async def _run_attack(
    settings: Settings, *, targets: list[str], scope_label: str
) -> ScanSummary:
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
    settings: Settings, *, target: str, scope_label: str
) -> PipelineResult:
    db = Database(settings.database_url)
    await db.create_all()
    try:
        repo = ScanRepository(db)
        async with TelegramNotifier.from_settings(settings) as notifier:
            recon = _build_recon_agent(settings, repo=repo, notifier=notifier)
            attack = _build_attack_agent(settings, repo=repo, notifier=notifier)
            pipeline = PipelineOrchestrator(
                recon_agent=recon, attack_agent=attack,
                repository=repo, notifier=notifier,
            )
            return await pipeline.run(target, scope_label=scope_label)
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


# -----------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    app()
