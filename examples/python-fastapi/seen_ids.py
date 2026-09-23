"""Idempotency: remember which message ids have already been handled.

Cleat posts each message once, but a delivery that fails is RETRIED on a
backoff, so the same ``data.id`` can legitimately arrive twice. Handling it
twice is your bug, not Cleat's.

THIS STORE IS IN-MEMORY AND PER-PROCESS. It is here so the example runs with no
setup. It forgets everything on restart, and two workers behind a load balancer
(or two uvicorn processes) do not see each other's ids. In a real deployment,
key on the message id in something durable and shared: a unique index on the id
column in your database (insert, and treat the duplicate-key error as "already
done"), or Redis with ``SET key value NX EX 86400``.
"""

from __future__ import annotations

import time
from collections import OrderedDict


class SeenIds:
    def __init__(self, *, max_entries: int = 10_000, ttl_seconds: float = 24 * 60 * 60) -> None:
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        # id -> expiry, in insertion order, so the oldest entry is the first one.
        self._entries: "OrderedDict[str, float]" = OrderedDict()

    def __contains__(self, message_id: str) -> bool:
        expires_at = self._entries.get(message_id)
        if expires_at is None:
            return False
        if expires_at <= time.monotonic():
            del self._entries[message_id]
            return False
        return True

    def add_if_new(self, message_id: str) -> bool:
        """Claim an id: True the first time, False on every repeat.

        Checking and marking in one call keeps them from drifting apart. A single
        event loop runs this without interleaving; if you move to threads, hold a
        lock here (or, better, use the database).
        """
        if message_id in self:
            return False
        self._entries[message_id] = time.monotonic() + self.ttl_seconds
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        return True

    def clear(self) -> None:
        self._entries.clear()
