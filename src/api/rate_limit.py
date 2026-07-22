"""Deterministic request rate-limiting primitives."""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Result of one rate-limit evaluation."""

    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    window_seconds: int


class SlidingWindowRateLimiter:
    """Thread-safe in-memory sliding-window limiter."""

    def __init__(self) -> None:
        self._events: dict[
            str,
            deque[float],
        ] = defaultdict(deque)

        self._lock = Lock()

    @staticmethod
    def _validate_rule(
        *,
        limit: int,
        window_seconds: int,
    ) -> None:
        if limit < 1:
            raise ValueError(
                "Rate-limit count must be at least one."
            )

        if window_seconds < 1:
            raise ValueError(
                "Rate-limit window must be at least one second."
            )

    def check(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        now: float | None = None,
    ) -> RateLimitDecision:
        """Evaluate and record one request."""

        self._validate_rule(
            limit=limit,
            window_seconds=window_seconds,
        )

        normalized_key = key.strip()

        if not normalized_key:
            raise ValueError(
                "A non-empty rate-limit key is required."
            )

        current_time = (
            time.monotonic()
            if now is None
            else float(now)
        )

        cutoff = (
            current_time
            - window_seconds
        )

        with self._lock:
            events = self._events[
                normalized_key
            ]

            while (
                events
                and events[0] <= cutoff
            ):
                events.popleft()

            if len(events) >= limit:
                oldest_event = events[0]

                retry_after = max(
                    1,
                    math.ceil(
                        (
                            oldest_event
                            + window_seconds
                        )
                        - current_time
                    ),
                )

                return RateLimitDecision(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    retry_after_seconds=(
                        retry_after
                    ),
                    window_seconds=(
                        window_seconds
                    ),
                )

            events.append(current_time)

            remaining = max(
                0,
                limit - len(events),
            )

            return RateLimitDecision(
                allowed=True,
                limit=limit,
                remaining=remaining,
                retry_after_seconds=0,
                window_seconds=(
                    window_seconds
                ),
            )

    def reset(
        self,
        key: str,
    ) -> bool:
        """Remove one key's current request history."""

        normalized_key = key.strip()

        if not normalized_key:
            return False

        with self._lock:
            existed = (
                normalized_key
                in self._events
            )

            self._events.pop(
                normalized_key,
                None,
            )

        return existed

    def clear(self) -> None:
        """Remove every recorded request window."""

        with self._lock:
            self._events.clear()
