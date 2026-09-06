"""Giới hạn tần suất request tối thiểu giữa 2 lần gọi (scoped endpoint)."""

import asyncio
import time


class RateLimiter:
    def __init__(self, min_interval: float) -> None:
        self.min_interval = min_interval
        self._next_ok = 0.0
        self._lock = asyncio.Lock()  # chốt slot ngay cả khi nhiều waiter cùng lúc

    async def wait(self) -> None:
        # giữ lock suốt chỗ ngủ để các waiter lần lượt nhận slot, không dồn cục
        async with self._lock:
            delay = self._next_ok - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self._next_ok = time.monotonic() + self.min_interval
