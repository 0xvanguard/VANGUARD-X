"""Async Nmap wrapper.

Runs Nmap with XML output to stdout and parses the result into
:class:`~vanguard_x.models.Asset` / :class:`~vanguard_x.models.Finding`
records. We use ``-sT`` (TCP connect) so the wrapper works without root
or ``CAP_NET_RAW`` — production deployments using the hardened
``vanguardx/nmap`` container can opt into SYN scans by overriding
``argv_overrides``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from vanguard_x.core.runners import CommandResult, CommandRunner
from vanguard_x.core.scope import ScopeEnforcer
from vanguard_x.models import Asset, AssetType, ToolRunResult
from vanguard_x.tools import BaseTool


class NmapWrapper(BaseTool):
    """Run Nmap and emit structured assets."""

    name = "nmap"

    def __init__(
        self,
        runner: CommandRunner,
        scope: ScopeEnforcer,
        *,
        timeout: float = 900.0,
        top_ports: int = 1000,
        max_rate: int = 500,
        argv_overrides: tuple[str, ...] | None = None,
    ) -> None:
        super().__init__(runner, scope, timeout=timeout)
        self._top_ports = top_ports
        self._max_rate = max_rate
        self._argv_overrides = argv_overrides

    # ------------------------------------------------------------------
    def build_argv(self, target: str) -> tuple[str, ...]:
        if self._argv_overrides is not None:
            return (*self._argv_overrides, target)
        return (
            "nmap",
            "-sT",  # TCP connect (no root needed)
            "-sV",  # service / version detection
            "-Pn",  # skip host discovery
            "-T4",  # aggressive timing template
            "--top-ports",
            str(self._top_ports),
            "--max-rate",
            str(self._max_rate),  # safety cap against accidental DoS
            "--open",  # only report open ports
            "-oX",
            "-",  # XML to stdout
            target,
        )

    # ------------------------------------------------------------------
    def parse(self, target: str, result: CommandResult) -> ToolRunResult:
        assets: list[Asset] = []
        if result.stdout.strip():
            assets = self._parse_xml(result.stdout)

        return ToolRunResult(
            tool=self.name,
            target=target,
            started_at=result.started_at,
            completed_at=result.completed_at,
            return_code=result.return_code,
            assets=assets,
            raw_excerpt=result.stdout[:2048],
        )

    # ------------------------------------------------------------------
    def _parse_xml(self, xml_text: str) -> list[Asset]:
        """Parse Nmap XML output into asset records.

        Defensive: malformed XML, missing fields, or unexpected schemas
        result in an empty / partial list rather than an exception.
        """
        try:
            root = ET.fromstring(xml_text)  # noqa: S314 — input is from our own tool
        except ET.ParseError:
            return []

        assets: list[Asset] = []
        for host in root.iter("host"):
            address = host.find("address")
            if address is None or not address.get("addr"):
                continue
            ip = address.get("addr") or ""

            # Hostname (if Nmap resolved any)
            hostname_el = host.find("hostnames/hostname")
            hostname = hostname_el.get("name") if hostname_el is not None else None

            assets.append(
                Asset(
                    asset_type=AssetType.HOST,
                    value=ip,
                    source_tool=self.name,
                    extra={"hostname": hostname} if hostname else {},
                )
            )

            for port in host.iter("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = port.get("portid")
                proto = port.get("protocol", "tcp")
                if not portid:
                    continue

                service = port.find("service")
                svc_name = service.get("name") if service is not None else None
                svc_product = service.get("product") if service is not None else None
                svc_version = service.get("version") if service is not None else None

                assets.append(
                    Asset(
                        asset_type=AssetType.PORT,
                        value=f"{ip}:{portid}/{proto}",
                        source_tool=self.name,
                        extra={
                            "ip": ip,
                            "port": int(portid),
                            "protocol": proto,
                            "service": svc_name,
                        },
                    )
                )

                if svc_name:
                    assets.append(
                        Asset(
                            asset_type=AssetType.SERVICE,
                            value=f"{svc_name} on {ip}:{portid}",
                            source_tool=self.name,
                            extra={
                                "ip": ip,
                                "port": int(portid),
                                "name": svc_name,
                                "product": svc_product,
                                "version": svc_version,
                            },
                        )
                    )

                if svc_product:
                    tech_value = svc_product
                    if svc_version:
                        tech_value = f"{svc_product} {svc_version}"
                    assets.append(
                        Asset(
                            asset_type=AssetType.TECHNOLOGY,
                            value=tech_value,
                            source_tool=self.name,
                            extra={"ip": ip, "port": int(portid)},
                        )
                    )

        return assets
