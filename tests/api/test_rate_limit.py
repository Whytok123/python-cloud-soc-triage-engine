"""Sliding-window rate-limiter tests."""

from __future__ import annotations

import pytest

from src.api.rate_limit import (
    SlidingWindowRateLimiter,
)


def test_requests_are_allowed_up_to_limit():
    limiter = SlidingWindowRateLimiter()

    first = limiter.check(
        "login:192.0.2.10",
        limit=3,
        window_seconds=60,
        now=100.0,
    )

    second = limiter.check(
        "login:192.0.2.10",
        limit=3,
        window_seconds=60,
        now=101.0,
    )

    third = limiter.check(
        "login:192.0.2.10",
        limit=3,
        window_seconds=60,
        now=102.0,
    )

    assert first.allowed is True
    assert first.remaining == 2

    assert second.allowed is True
    assert second.remaining == 1

    assert third.allowed is True
    assert third.remaining == 0


def test_request_over_limit_is_blocked():
    limiter = SlidingWindowRateLimiter()

    for timestamp in (
        100.0,
        101.0,
        102.0,
    ):
        limiter.check(
            "login:192.0.2.10",
            limit=3,
            window_seconds=60,
            now=timestamp,
        )

    blocked = limiter.check(
        "login:192.0.2.10",
        limit=3,
        window_seconds=60,
        now=103.0,
    )

    assert blocked.allowed is False
    assert blocked.remaining == 0
    assert blocked.retry_after_seconds == 57


def test_key_recovers_after_window():
    limiter = SlidingWindowRateLimiter()

    for timestamp in (
        100.0,
        101.0,
    ):
        limiter.check(
            "api:192.0.2.20",
            limit=2,
            window_seconds=10,
            now=timestamp,
        )

    blocked = limiter.check(
        "api:192.0.2.20",
        limit=2,
        window_seconds=10,
        now=105.0,
    )

    recovered = limiter.check(
        "api:192.0.2.20",
        limit=2,
        window_seconds=10,
        now=111.0,
    )

    assert blocked.allowed is False
    assert recovered.allowed is True
    assert recovered.remaining == 1


def test_keys_are_isolated():
    limiter = SlidingWindowRateLimiter()

    limiter.check(
        "login:192.0.2.10",
        limit=1,
        window_seconds=60,
        now=100.0,
    )

    blocked = limiter.check(
        "login:192.0.2.10",
        limit=1,
        window_seconds=60,
        now=101.0,
    )

    other_client = limiter.check(
        "login:192.0.2.11",
        limit=1,
        window_seconds=60,
        now=101.0,
    )

    assert blocked.allowed is False
    assert other_client.allowed is True


def test_reset_clears_request_history():
    limiter = SlidingWindowRateLimiter()

    limiter.check(
        "api:192.0.2.30",
        limit=1,
        window_seconds=60,
        now=100.0,
    )

    assert limiter.reset(
        "api:192.0.2.30"
    ) is True

    allowed = limiter.check(
        "api:192.0.2.30",
        limit=1,
        window_seconds=60,
        now=101.0,
    )

    assert allowed.allowed is True


def test_invalid_rules_are_rejected():
    limiter = SlidingWindowRateLimiter()

    with pytest.raises(
        ValueError,
        match="at least one",
    ):
        limiter.check(
            "test",
            limit=0,
            window_seconds=60,
            now=100.0,
        )

    with pytest.raises(
        ValueError,
        match="at least one second",
    ):
        limiter.check(
            "test",
            limit=1,
            window_seconds=0,
            now=100.0,
        )

    with pytest.raises(
        ValueError,
        match="non-empty",
    ):
        limiter.check(
            "   ",
            limit=1,
            window_seconds=60,
            now=100.0,
        )
