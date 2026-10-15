"""Tiny in-process TTL cache. Failed results are never cached."""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

_lock = threading.Lock()
_entries: dict[str, tuple[float, Any]] = {}


def cached(
    key: str,
    ttl_seconds: float,
    loader: Callable[[], Any],
    refresh: bool = False,
    should_cache: Callable[[Any], bool] = lambda value: True,
) -> Any:
    """Return a fresh-enough cached value, otherwise call `loader`.

    `key` must include the tenant/account once authentication exists, so one
    tenant can never be served another tenant's cached data.
    """
    if ttl_seconds > 0 and not refresh:
        with _lock:
            hit = _entries.get(key)
        if hit and time.monotonic() - hit[0] < ttl_seconds:
            return hit[1]

    value = loader()

    if ttl_seconds > 0 and should_cache(value):
        with _lock:
            _entries[key] = (time.monotonic(), value)
    return value