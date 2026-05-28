"""Exhaustive tests for the scope enforcement boundary.

Scope enforcement is the single most safety-critical component in
VANGUARD-X. These tests are intentionally paranoid.
"""

from __future__ import annotations

import pytest

from vanguard_x.core.scope import ScopeEnforcer, ScopeViolation


# -----------------------------------------------------------------------------
# Construction / introspection
# -----------------------------------------------------------------------------
def test_empty_scope_is_default_deny():
    enforcer = ScopeEnforcer([])
    assert enforcer.is_empty
    assert not enforcer.is_authorized("anything.com")
    assert not enforcer.is_authorized("1.2.3.4")


def test_blank_entries_ignored():
    enforcer = ScopeEnforcer(["", "  ", "example.com"])
    assert enforcer.authorized == ("example.com",)


def test_invalid_rule_rejected_at_construction():
    with pytest.raises(ValueError):
        ScopeEnforcer(["not a hostname!!"])


# -----------------------------------------------------------------------------
# Hostname matching
# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "rules,target,expected",
    [
        (["example.com"], "example.com", True),
        (["example.com"], "EXAMPLE.com", True),  # case-insensitive
        (["example.com"], "api.example.com", True),  # subdomain
        (["example.com"], "deep.api.example.com", True),  # nested subdomain
        (["example.com"], "notexample.com", False),  # suffix collision
        (["example.com"], "example.com.evil.com", False),  # confusable
        (["example.com"], "evil.com", False),
        (["api.example.com"], "example.com", False),  # apex not implied
    ],
)
def test_hostname_matching(rules, target, expected):
    assert ScopeEnforcer(rules).is_authorized(target) is expected


# -----------------------------------------------------------------------------
# IP / CIDR matching
# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "rules,target,expected",
    [
        (["1.2.3.4"], "1.2.3.4", True),
        (["1.2.3.4"], "1.2.3.5", False),
        (["10.0.0.0/24"], "10.0.0.55", True),
        (["10.0.0.0/24"], "10.0.1.55", False),
        (["10.0.0.0/8"], "10.255.255.1", True),
        (["2001:db8::/32"], "2001:db8::1", True),
        (["2001:db8::/32"], "2001:dead::1", False),
    ],
)
def test_ip_and_cidr_matching(rules, target, expected):
    assert ScopeEnforcer(rules).is_authorized(target) is expected


# -----------------------------------------------------------------------------
# Hostile inputs — every one of these MUST fail safe.
# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "example.com ",  # whitespace inside
        "example.com\nattack.com",
        "http://example.com",  # scheme prefix
        "example.com/path",
        "example.com:80",
        "user@example.com",
        "../../etc/passwd",
        "example.com; rm -rf /",
        "example.com$(whoami)",
    ],
)
def test_hostile_inputs_default_deny(target):
    enforcer = ScopeEnforcer(["example.com"])
    assert enforcer.is_authorized(target) is False


# -----------------------------------------------------------------------------
def test_assert_authorized_raises_with_full_context():
    enforcer = ScopeEnforcer(["example.com", "10.0.0.0/24"])
    with pytest.raises(ScopeViolation) as ex:
        enforcer.assert_authorized("evil.com")
    assert ex.value.target == "evil.com"
    assert "example.com" in str(ex.value)
    assert "10.0.0.0/24" in str(ex.value)


def test_assert_authorized_passes_silently_for_valid_target():
    enforcer = ScopeEnforcer(["example.com"])
    # No raise = pass
    enforcer.assert_authorized("api.example.com")
