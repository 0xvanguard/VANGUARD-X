"""Tests for configuration loading."""

from __future__ import annotations

import pytest

from vanguard_x.config import (
    Environment,
    Settings,
    ToolRunnerKind,
    get_settings,
    reset_settings_cache,
)


def test_defaults_are_safe():
    s = Settings()
    assert s.environment is Environment.DEVELOPMENT
    assert s.tool_runner is ToolRunnerKind.LOCAL
    # default-deny: no authorised targets means an empty list
    assert s.authorized_targets_list == []
    # telegram disabled by default
    assert not s.telegram_enabled


def test_authorized_targets_parsing():
    s = Settings(authorized_targets="EXAMPLE.com, 10.0.0.0/24 ,, dvwa.local")
    assert s.authorized_targets_list == ["example.com", "10.0.0.0/24", "dvwa.local"]


def test_invalid_log_level_rejected():
    with pytest.raises(ValueError):
        Settings(log_level="LOUD")


def test_log_level_normalised_to_upper():
    s = Settings(log_level="debug")
    assert s.log_level == "DEBUG"


def test_get_settings_is_cached(monkeypatch):
    reset_settings_cache()
    monkeypatch.setenv("VANGUARDX_LOG_LEVEL", "WARNING")
    a = get_settings()
    monkeypatch.setenv("VANGUARDX_LOG_LEVEL", "ERROR")
    b = get_settings()
    assert a is b  # cached, env mutation has no effect until reset
    reset_settings_cache()
    c = get_settings()
    assert c is not a


def test_telegram_enabled_requires_both_token_and_chat():
    assert not Settings(telegram_bot_token="t").telegram_enabled
    assert not Settings(telegram_chat_id="c").telegram_enabled
    assert Settings(telegram_bot_token="t", telegram_chat_id="c").telegram_enabled
