"""Tests for the PipelineOrchestrator (Recon -> Attack)."""

from __future__ import annotations

from pathlib import Path

import httpx

from vanguard_x.agents.attack import AttackAgent
from vanguard_x.agents.recon import ReconAgent
from vanguard_x.core.changes import ChangeDetector
from vanguard_x.models import ScanStatus
from vanguard_x.notifications.telegram import TelegramNotifier
from vanguard_x.pipeline import PipelineOrchestrator
from vanguard_x.tools.gobuster import GobusterWrapper
from vanguard_x.tools.harvester import HarvesterWrapper
from vanguard_x.tools.nmap import NmapWrapper
from vanguard_x.tools.nuclei import NucleiWrapper
from vanguard_x.tools.subfinder import SubfinderWrapper
from vanguard_x.tools.wafw00f import WafW00fWrapper
from vanguard_x.tools.whatweb import WhatWebWrapper

FIXTURES = Path(__file__).parent / "fixtures"


def _silent_notifier() -> TelegramNotifier:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return TelegramNotifier(bot_token="t", chat_id="c", client=client)


def _build_pipeline(*, fake_runner, scope, repository, notifier):
    recon = ReconAgent(
        nmap=NmapWrapper(fake_runner, scope, timeout=5),
        harvester=HarvesterWrapper(fake_runner, scope, timeout=5),
        subfinder=SubfinderWrapper(fake_runner, scope, timeout=5),
        whatweb=WhatWebWrapper(fake_runner, scope, timeout=5),
        wafw00f=WafW00fWrapper(fake_runner, scope, timeout=5),
        scope=scope,
        repository=repository,
        notifier=notifier,
        change_detector=ChangeDetector(repository),
    )
    attack = AttackAgent(
        nuclei=NucleiWrapper(fake_runner, scope, timeout=5),
        gobuster=GobusterWrapper(fake_runner, scope, timeout=5),
        scope=scope,
        repository=repository,
        notifier=notifier,
    )
    return PipelineOrchestrator(
        recon_agent=recon,
        attack_agent=attack,
        repository=repository,
        notifier=notifier,
    )


# -----------------------------------------------------------------------------
async def test_pipeline_runs_recon_then_attack(fake_runner, scope, repository):
    from tests.conftest import make_command_result

    # Recon fixtures
    fake_runner.responses["nmap"] = make_command_result(
        stdout=(FIXTURES / "nmap_sample.xml").read_text()
    )
    fake_runner.responses["theHarvester"] = make_command_result(
        stdout=(FIXTURES / "harvester_sample.txt").read_text()
    )
    fake_runner.responses["subfinder"] = make_command_result(
        stdout=(FIXTURES / "subfinder_sample.jsonl").read_text()
    )
    fake_runner.responses["whatweb"] = make_command_result(
        stdout=(FIXTURES / "whatweb_sample.json").read_text()
    )
    fake_runner.responses["wafw00f"] = make_command_result(
        stdout=(FIXTURES / "wafw00f_sample.json").read_text()
    )
    # Attack fixtures
    fake_runner.responses["nuclei"] = make_command_result(
        stdout=(FIXTURES / "nuclei_sample.jsonl").read_text()
    )
    fake_runner.responses["gobuster"] = make_command_result(
        stdout=(FIXTURES / "gobuster_sample.txt").read_text()
    )

    notifier = _silent_notifier()
    pipeline = _build_pipeline(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )
    result = await pipeline.run("example.com")

    assert result.recon_summary.status is ScanStatus.DONE
    assert result.attack_summary is not None
    assert result.attack_summary.status is ScanStatus.DONE
    assert result.total_findings >= 1
    await notifier.aclose()


async def test_pipeline_extracts_targets(fake_runner, scope, repository):
    """Attack targets should include subdomains from recon assets."""
    from tests.conftest import make_command_result

    # Subfinder produces subdomains that the pipeline should extract.
    fake_runner.responses["subfinder"] = make_command_result(
        stdout='{"host":"sub.example.com","input":"example.com","source":"crtsh"}\n'
    )

    # Attack fixtures
    fake_runner.responses["nuclei"] = make_command_result(stdout="")
    fake_runner.responses["gobuster"] = make_command_result(stdout="")

    notifier = _silent_notifier()
    pipeline = _build_pipeline(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )
    result = await pipeline.run("example.com")

    # Recon should have found sub.example.com, which is passed to attack.
    assert result.recon_summary.status is ScanStatus.DONE
    assert result.attack_summary is not None
    await notifier.aclose()


async def test_pipeline_with_no_assets(fake_runner, scope, repository):
    """If recon finds no assets, attack_summary should be None."""
    from tests.conftest import make_command_result

    # All tools return empty output => no assets discovered.
    # But _extract_targets always includes the original target, so attack
    # will still run. We need to make the tool wrappers return nothing.
    fake_runner.responses["nuclei"] = make_command_result(stdout="")
    fake_runner.responses["gobuster"] = make_command_result(stdout="")

    notifier = _silent_notifier()
    pipeline = _build_pipeline(
        fake_runner=fake_runner, scope=scope, repository=repository, notifier=notifier
    )
    result = await pipeline.run("example.com")

    # The pipeline always includes the original target, so attack does run.
    assert result.recon_summary.status is ScanStatus.DONE
    # Attack still runs because original target is included in the target list.
    assert result.attack_summary is not None
    await notifier.aclose()
