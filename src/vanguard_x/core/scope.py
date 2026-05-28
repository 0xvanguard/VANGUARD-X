"""Scope enforcement — the hard safety boundary of VANGUARD-X.

No tool wrapper, no agent, no orchestrator should ever start a scan without
asking :class:`ScopeEnforcer` first. The contract is intentionally strict:

- An empty / non-configured authorized list **denies everything**. Default-deny.
- Hostnames and their subdomains are accepted (``example.com`` permits
  ``api.example.com`` but **not** ``notexample.com``).
- IPv4 / IPv6 addresses match exactly OR fall inside an authorized CIDR range.
- URLs and inputs containing whitespace / control chars are rejected outright;
  callers must pass plain hostnames or IPs.

A :class:`ScopeViolation` is **always** raised on rejection — never silenced,
never downgraded to a warning. This is the property that lets us tell a
client "VANGUARD-X cannot accidentally scan something we did not authorise".
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass

# Hostname per RFC-1123 (relaxed: allow leading digits, single-label is OK).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$"
)


class ScopeViolation(Exception):
    """Raised when a target is not within the authorised scope.

    Carries both the requested target and the configured scope so logs and
    Telegram alerts can show exactly what was attempted.
    """

    def __init__(self, target: str, authorized: Iterable[str]) -> None:
        self.target = target
        self.authorized = list(authorized)
        super().__init__(
            f"SCOPE_VIOLATION: target {target!r} is not in the authorised scope "
            f"({', '.join(self.authorized) or '<empty>'})."
        )


@dataclass(frozen=True)
class _ParsedRule:
    """One entry from the authorised-targets list, pre-classified."""

    raw: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None
    hostname: str | None


def _parse_rule(rule: str) -> _ParsedRule:
    rule_norm = rule.strip().lower()
    if not rule_norm:
        raise ValueError("empty scope rule")

    # IP / CIDR first
    try:
        net = ipaddress.ip_network(rule_norm, strict=False)
        return _ParsedRule(raw=rule_norm, network=net, hostname=None)
    except ValueError:
        pass

    if not _HOSTNAME_RE.match(rule_norm):
        raise ValueError(f"invalid scope rule: {rule!r}")
    return _ParsedRule(raw=rule_norm, network=None, hostname=rule_norm)


def _classify_target(
    target: str,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address | None, str | None]:
    """Return ``(ip, hostname)`` — exactly one will be non-None on success.

    Raises :class:`ValueError` on syntactically unsafe input.
    """
    if not target or any(c.isspace() for c in target):
        raise ValueError(f"target must be a non-empty whitespace-free string: {target!r}")
    if any(ch in target for ch in ("/", "\\", "@", " ", "\t", "\n", "\r")):
        # Block schemes (http://...), path traversal, command injection vectors.
        raise ValueError(f"target must be a bare host or IP, got {target!r}")

    target_norm = target.strip().lower()
    try:
        return ipaddress.ip_address(target_norm), None
    except ValueError:
        pass

    if _HOSTNAME_RE.match(target_norm):
        return None, target_norm
    raise ValueError(f"target is neither a valid IP nor hostname: {target!r}")


class ScopeEnforcer:
    """Default-deny scope checker for pentest targets.

    Construct once per process from ``Settings.authorized_targets_list`` and
    pass it to every agent / tool that performs network I/O against a target.
    """

    def __init__(self, authorized: Iterable[str]) -> None:
        rules: list[_ParsedRule] = []
        for raw in authorized:
            if not raw.strip():
                continue
            rules.append(_parse_rule(raw))
        self._rules: tuple[_ParsedRule, ...] = tuple(rules)

    # ------------------------------------------------------------------
    @property
    def authorized(self) -> tuple[str, ...]:
        """Tuple of normalised rule strings — useful for logging."""
        return tuple(r.raw for r in self._rules)

    @property
    def is_empty(self) -> bool:
        """True iff no scope rules are configured (default-deny mode)."""
        return not self._rules

    # ------------------------------------------------------------------
    def is_authorized(self, target: str) -> bool:
        """Return ``True`` iff ``target`` is permitted by **any** rule.

        Never raises; on malformed input returns ``False`` (default-deny).
        """
        if self.is_empty:
            return False
        try:
            ip, hostname = _classify_target(target)
        except ValueError:
            return False

        for rule in self._rules:
            if ip is not None and rule.network is not None and ip in rule.network:
                return True
            if hostname is not None and rule.hostname is not None:
                if hostname == rule.hostname or hostname.endswith("." + rule.hostname):
                    return True
        return False

    def assert_authorized(self, target: str) -> None:
        """Raise :class:`ScopeViolation` if ``target`` is not authorised."""
        if not self.is_authorized(target):
            raise ScopeViolation(target, self.authorized)
