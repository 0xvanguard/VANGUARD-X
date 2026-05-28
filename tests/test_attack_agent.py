"""End-to-end tests for the ATTACK agent."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from vanguard_x.agents.attack import AttackAgent
from vanguard_x.core.scope import ScopeEnforcer, ScopeViolation
from vanguard_x.models import ScanStatus, Severity
from vanguard_x.notifications.telegram import TelegramNotifier
from vanguard_x.tools.gobuster import GobusterWrapper
from vanguard_x.tools.nuclei import NucleiWrapper

FIXTURES = Path(__file__).parent / "fixtures"


def _silent_notifier() -> TelegramNotifier:
    """A notifier that records calls without performing real network I/O."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return TelegramNotifier(bot_token="t", chat_id="c", client=client)


def _build_attack_agent(*, fake_runner, scope, repository, notifier):
    return AttackAgent(
        nuclei=NucleiWrapper(fake_runner, scope, timeout=5),
        gobuster=GobusterWrapper(fake_runner, scope, timeout=5),
        scope=scope,
        repository=repository,
        notifier=notifier,
    )


# -----------------------------------------------------------------------------
async def test_full_attack_persists_findings(fake_runner, scope, repository):
    from tests.conftest import make_command_result

    fake_runner.responses["nuclei"] = make_command_result(
        stdout=(FIXTURES / "nuclei_sample.jsonl").read_text()
    )
    fake_runner.responses["gobuster"] = make_command_result(
        stdout=(FIXTURES / "gobuster_sample.txt").read_text()
    )

    notifier = _silent_notifier()
    agent = _build_attack_agent(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )
    summary = await agent.run(["example.com"])

    assert summary.status is ScanStatus.DONE
    assert summary.target == "example.com"
    assert summary.finding_count >= 1
    assert summary.asset_count >= 1
    await notifier.aclose()


async def test_tools_run_in_parallel(fake_runner, scope, repository):
    """Both tools are launched concurrently, not sequentially."""
    from tests.conftest import make_command_result

    started: list[str] = []
    finish_event = asyncio.Event()

    async def slow_run(self, target):
        started.append(self.name)
        if len(started) < 2:
            await asyncio.wait_for(finish_event.wait(), timeout=2.0)
        else:
            finish_event.set()
        return self.parse(
            target,
            make_command_result(stdout="", argv=(self.name,)),
        )

    monkey = pytest.MonkeyPatch()
    try:
        for cls in (NucleiWrapper, GobusterWrapper):
            monkey.setattr(cls, "run", slow_run)

        notifier = _silent_notifier()
        agent = _build_attack_agent(
            fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
        )
        summary = await agent.run(["example.com"])
    finally:
        monkey.undo()

    assert summary.status is ScanStatus.DONE
    assert set(started) == {"nuclei", "gobuster"}
    await notifier.aclose()


async def test_scope_violation_blocks(fake_runner, repository):
    """A target outside the authorised list must never reach the runner."""
    scope = ScopeEnforcer(["allowed.com"])
    notifier = _silent_notifier()
    agent = _build_attack_agent(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )

    with pytest.raises(ScopeViolation):
        await agent.run(["evil.com"])

    assert fake_runner.calls == []
    await notifier.aclose()


async def test_partial_results(fake_runner, scope, repository, monkeypatch):
    """If nuclei fails, gobuster results still persist."""
    from tests.conftest import make_command_result

    fake_runner.responses["gobuster"] = make_command_result(
        stdout=(FIXTURES / "gobuster_sample.txt").read_text()
    )

    async def _explode(self, target):
        raise RuntimeError("nuclei crashed")

    monkeypatch.setattr(NucleiWrapper, "run", _explode)

    notifier = _silent_notifier()
    agent = _build_attack_agent(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )
    summary = await agent.run(["example.com"])

    assert summary.status is ScanStatus.DONE
    assert summary.asset_count >= 1
    await notifier.aclose()


async def test_critical_alert_sent(fake_runner, scope, repository, monkeypatch):
    """Verify notifier.send_critical_alert is called for critical findings."""
    from tests.conftest import make_command_result

    fake_runner.responses["nuclei"] = make_command_result(
        stdout=(FIXTURES / "nuclei_sample.jsonl").read_text()
    )
    fake_runner.responses["gobuster"] = make_command_result(
        stdout=(FIXTURES / "gobuster_sample.txt").read_text()
    )

    notifier = _silent_notifier()
    alerts_sent: list[object] = []

    original = notifier.send_critical_alert

    async def spy(finding):
        alerts_sent.append(finding)
        return await original(finding)

    monkeypatch.setattr(notifier, "send_critical_alert", spy)

    agent = _build_attack_agent(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )
    summary = await agent.run(["example.com"])

    # The nuclei fixture has critical and high findings
    assert summary.status is ScanStatus.DONE
    # At least one critical/high alert should have been sent
    high_crit = [
        f
        for f in alerts_sent
        if hasattr(f, "severity") and f.severity in (Severity.HIGH, Severity.CRITICAL)
    ]
    assert len(high_crit) >= 1
    await notifier.aclose()
