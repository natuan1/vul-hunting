"""Hàng đợi việc trên Postgres thuần theo ADR-0001 — bảng jobs + SKIP LOCKED.

Tự lo đủ ba mảng ADR nhắc tới:
- retry: job lỗi → về 'pending' với run_after = now() + backoff luỹ thừa;
- visibility timeout: job 'running' quá hạn không report (consumer chết giữa
  chừng) → được claim lại như thường;
- dead-letter: hết lượt thử → status 'dead' (callback qua dead_handlers).

Toàn bộ thao tác queue chỉ đi qua module này — khi nào cần đổi sang Redis/Celery
chỉ sửa đúng một nơi (ADR-0001).
"""

import asyncio
import logging

import asyncpg

log = logging.getLogger("jobqueue")

POLL_INTERVAL = 1.0  # giây nghỉ giữa 2 lần poll khi hàng đợi trống
VISIBILITY_TIMEOUT_S = 60.0  # job 'running' quá hạn này → coi consumer chết, reclaim
RETRY_BASE_S = 5.0  # backoff lần đầu
RETRY_CAP_S = 300.0  # trần backoff

_CLAIM = """
UPDATE jobs SET status = 'running', locked_at = now(), locked_by = $1,
                attempts = attempts + 1, updated_at = now()
WHERE id = (
    SELECT id FROM jobs
    WHERE (status = 'pending' AND run_after <= now())
       OR (status = 'running'
           AND locked_at < now() - make_interval(secs => $2))
    ORDER BY id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING *
"""


def _backoff(attempts: int) -> float:
    """Delay trước lần thử kế tiếp — luỹ thừa theo số lần đã thử, chặn trần."""
    return min(RETRY_BASE_S * 2 ** (attempts - 1), RETRY_CAP_S)


async def enqueue(conn: asyncpg.Connection, run_id: int, type_: str = "run") -> int:
    return await conn.fetchval(
        "INSERT INTO jobs (run_id, type) VALUES ($1, $2) RETURNING id",
        run_id,
        type_,
    )


async def claim(pool: asyncpg.Pool, worker_id: str) -> asyncpg.Record | None:
    """Lấy 1 job: 'pending' đến hạn, hoặc 'running' quá visibility timeout."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            return await conn.fetchrow(_CLAIM, worker_id, VISIBILITY_TIMEOUT_S)


async def complete(pool: asyncpg.Pool, job_id: int) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE jobs SET status = 'done', locked_at = NULL, locked_by = NULL, "
            "updated_at = now() WHERE id = $1",
            job_id,
        )


async def heartbeat(pool: asyncpg.Pool, job_id: int) -> None:
    """Consumer đang giữ job báo hiệu còn sống — đẩy mốc locked_at để job không
    bị coi là chết giữa chừng (Recon Phase với tool thật chạy dài hơn nhiều so
    với visibility timeout 60s; thiếu heartbeat thì job bị reclaim và quét
    TRÙNG target)."""
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE jobs SET locked_at = now(), updated_at = now() "
            "WHERE id = $1 AND status = 'running'",
            job_id,
        )


async def fail(pool: asyncpg.Pool, job: asyncpg.Record, error: str) -> str:
    """Job lỗi: còn lượt → retry (backoff qua run_after); hết lượt → 'dead'.

    Job bị crash (không ai kịp gọi fail) không đi qua đây — tự được reclaim
    sau visibility timeout ngay trong claim().
    """
    dead = job["attempts"] >= job["max_attempts"]
    async with pool.acquire() as conn:
        if dead:
            await conn.execute(
                "UPDATE jobs SET status = 'dead', last_error = $2, locked_at = NULL, "
                "locked_by = NULL, updated_at = now() WHERE id = $1",
                job["id"],
                error[:500],
            )
        else:
            await conn.execute(
                "UPDATE jobs SET status = 'pending', "
                "run_after = now() + make_interval(secs => $2), "
                "last_error = $3, locked_at = NULL, locked_by = NULL, "
                "updated_at = now() WHERE id = $1",
                job["id"],
                _backoff(job["attempts"]),
                error[:500],
            )
    return "dead" if dead else "retry"


async def loop(
    pool: asyncpg.Pool,
    handlers: dict,
    dead_handlers: dict,
    worker_id: str,
    retry_handlers: dict | None = None,
) -> None:
    """Vòng lặp consumer: claim → thực thi → complete/fail. Chạy mãi (task nền).

    retry_handlers/dead_handlers theo job type: gọi khi job lỗi còn lượt thử
    (đang chờ backoff) và khi job hết lượt (dead) — để bề mặt Run hiển thị đúng
    trạng thái thay vì treo 'running' im lặng.
    """
    retry_handlers = retry_handlers or {}
    log.info("consumer %s khởi động", worker_id)
    while True:
        try:
            job = await claim(pool, worker_id)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — DB gián đoạn tạm thời thì thử lại sau
            log.exception("claim lỗi — thử lại sau")
            await asyncio.sleep(POLL_INTERVAL)
            continue
        if job is None:
            await asyncio.sleep(POLL_INTERVAL)
            continue

        handler = handlers.get(job["type"])
        log.info(
            "claim job %d (run %d, lần thử %d/%d)",
            job["id"],
            job["run_id"],
            job["attempts"],
            job["max_attempts"],
        )
        try:
            if handler is None:
                raise KeyError(f"không có handler cho job type '{job['type']}'")
            await handler(pool, job)
            await complete(pool, job["id"])
        except asyncio.CancelledError:
            # worker tắt giữa chừng — trả job về 'pending' để chạy lại ngay
            # lúc khởi động, không phải chờ visibility timeout
            await fail(pool, job, "worker tắt giữa chừng")
            raise
        except Exception as exc:  # noqa: BLE001 — mọi lỗi của handler đi qua queue
            log.error("job %d lỗi: %s", job["id"], exc)
            outcome = await fail(pool, job, str(exc))
            callbacks = dead_handlers if outcome == "dead" else retry_handlers
            if job["type"] in callbacks:
                try:
                    await callbacks[job["type"]](pool, job, str(exc))
                except Exception:  # noqa: BLE001
                    log.exception("%s handler lỗi cho job %d", outcome, job["id"])
