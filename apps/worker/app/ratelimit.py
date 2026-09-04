"""Giới hạn tần suất request tối thiểu giữa 2 lần gọi (scoped endpoint)."""

import asyncio
import time


class RateLimiter:
    def __init__(self, min_interval: float) -> None:
        self.min_interval = min_interval
        self._next_ok = 0.0

    async def wait(self) -> None:
        now = time.monotonic()
        if now < self._next_ok:
            await asyncio.sleep(self._next_ok - now)
        self._next_ok = time.monotonic() + self.min_interval
