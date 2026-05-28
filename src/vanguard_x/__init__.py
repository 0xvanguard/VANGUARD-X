"""VANGUARD-X — autonomous agentic pentesting & continuous security monitoring.

Public package surface is intentionally narrow: most code is consumed via the
CLI (``python -m vanguard_x``) or by composing the building blocks in
``vanguard_x.agents``, ``vanguard_x.tools``, ``vanguard_x.core`` and
``vanguard_x.db``.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
