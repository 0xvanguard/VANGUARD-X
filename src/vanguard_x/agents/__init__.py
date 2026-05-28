"""VANGUARD-X agents.

An *agent* is a stateless coordinator that owns a slice of the kill chain
(RECON, ATTACK, ANALYZE, REPORT). It depends on tool wrappers, the scope
enforcer, the scan repository and the notifier — but never on lower-level
plumbing such as subprocess or HTTP clients.
"""

from __future__ import annotations

from vanguard_x.agents.recon import ReconAgent

__all__ = ["ReconAgent"]
