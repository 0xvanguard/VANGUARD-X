"""Command-line entry point — ``python -m vanguard_x`` / ``vanguard-x``.

Subcommands::

    vanguard-x version
    vanguard-x config
    vanguard-x init-db
    vanguard-x scan --target example.com --scope external
"""

from __future__ import annotations

import asyncio
import sys

import typer
from rich.console import Console
from rich.table import Table

from vanguard_x import __version__
from vanguard_x.agents.recon import ReconAgent
from vanguard_x.config import Settings, get_settings
from vanguard_x.core.runners import build_runner
from vanguard_x.core.scope import ScopeEnforcer, ScopeViolation
from vanguard_x.db.database import Database, ScanRepository
from vanguard_x.logging_setup import configure_logging, get_logger
from vanguard_x.notifications.telegram import TelegramNotifier
from vanguard_x.tools.harvester import HarvesterWrapper
from vanguard_x.tools.nmap import NmapWrapper

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


async def _run_recon(settings: Settings, *, target: str, scope_label: str):  # type: ignore[no-untyped-def]
    db = Database(settings.database_url)
    await db.create_all()
    try:
        repo = ScanRepository(db)
        scope_enforcer = ScopeEnforcer(settings.authorized_targets_list)

        nmap = NmapWrapper(
            runner=build_runner(settings, container=settings.nmap_container),
            scope=scope_enforcer,
            timeout=settings.tool_timeout_seconds,
        )
        harvester = HarvesterWrapper(
            runner=build_runner(settings, container=settings.harvester_container),
            scope=scope_enforcer,
            timeout=settings.tool_timeout_seconds,
        )

        async with TelegramNotifier.from_settings(settings) as notifier:
            agent = ReconAgent(
                nmap=nmap,
                harvester=harvester,
                scope=scope_enforcer,
                repository=repo,
                notifier=notifier,
            )
            return await agent.run(target, scope_label=scope_label)
    finally:
        await db.dispose()


# -----------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    app()
