"""Async theHarvester wrapper (passive OSINT).

theHarvester is a passive-recon OSINT tool: it queries public sources
(DNS, search engines, certificate transparency, etc.) for subdomains,
emails and host names. Because it does not actually probe the target,
scope enforcement is still applied — we don't want VANGUARD-X harvesting
data on third-party domains by mistake.

For Month 1 we parse the human-readable stdout. Phase 2 will switch to
``-f <json>`` plus filesystem read-back once the docker-exec runner
gains a "copy file out of container" helper.
"""

from __future__ import annotations

import re

from vanguard_x.core.runners import CommandResult, CommandRunner
from vanguard_x.core.scope import ScopeEnforcer
from vanguard_x.models import Asset, AssetType, ToolRunResult
from vanguard_x.tools import BaseTool

# Conservative regexes — we only accept matches under the requested target
# domain (filtered later) so noise (404 search snippets etc.) is dropped.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class HarvesterWrapper(BaseTool):
    """Run theHarvester and extract subdomains / emails / IPs."""

    name = "theharvester"

    def __init__(
        self,
        runner: CommandRunner,
        scope: ScopeEnforcer,
        *,
        timeout: float = 600.0,
        sources: str = "crtsh,duckduckgo,bing,hackertarget,rapiddns",
        limit: int = 200,
    ) -> None:
        super().__init__(runner, scope, timeout=timeout)
        self._sources = sources
        self._limit = limit

    # ------------------------------------------------------------------
    def build_argv(self, target: str) -> tuple[str, ...]:
        return (
            "theHarvester",
            "-d",
            target,
            "-b",
            self._sources,
            "-l",
            str(self._limit),
        )

    # ------------------------------------------------------------------
    def parse(self, target: str, result: CommandResult) -> ToolRunResult:
        text = result.stdout
        target_lower = target.lower().lstrip(".")

        subdomains: set[str] = set()
        emails: set[str] = set()
        ips: set[str] = set()

        for match in _HOST_RE.findall(text):
            host = match.lower()
            # Keep only hosts under the queried domain (drops banner noise).
            if host == target_lower or host.endswith("." + target_lower):
                if host != target_lower:
                    subdomains.add(host)

        for match in _EMAIL_RE.findall(text):
            email = match.lower()
            domain = email.split("@", 1)[1]
            if domain == target_lower or domain.endswith("." + target_lower):
                emails.add(email)

        for match in _IPV4_RE.findall(text):
            # Skip obvious non-routable / placeholder addresses.
            if match.startswith(("0.", "127.", "255.")):
                continue
            ips.add(match)

        assets: list[Asset] = [
            *(
                Asset(asset_type=AssetType.SUBDOMAIN, value=sd, source_tool=self.name)
                for sd in sorted(subdomains)
            ),
            *(
                Asset(asset_type=AssetType.EMAIL, value=em, source_tool=self.name)
                for em in sorted(emails)
            ),
            *(
                Asset(asset_type=AssetType.HOST, value=ip, source_tool=self.name)
                for ip in sorted(ips)
            ),
        ]

        return ToolRunResult(
            tool=self.name,
            target=target,
            started_at=result.started_at,
            completed_at=result.completed_at,
            return_code=result.return_code,
            assets=assets,
            raw_excerpt=text[:2048],
        )
