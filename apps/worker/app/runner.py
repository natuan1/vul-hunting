"""Thực thi Run (ticket #6) — vòng lặp Tool Execution với stub tool sleep+echo.

Tool thật (recon, nuclei, …) ở ticket sau; cơ chế đã đủ dùng:
- rate limit (req/s) và header định danh nằm trong Run config, MỌI Tool
  Execution đều kế thừa (limiter chờ trước, header ghi kèm mỗi lần gọi);
- stdout của từng lần chạy đổ vào run_logs để UI stream qua SSE, kèm row
  tool_executions giữ exit code + stdout đầy đủ;
- lỗi giữa chừng ném lên cho jobqueue xử lý retry/dead.
"""

import asyncio
import logging
import time

import asyncpg

from . import jobqueue
from .ratelimit import RateLimiter

log = logging.getLogger("runner")

STUB_TOOL = "stub-echo"
STUB_EXECUTIONS = 5  # đủ dài để xem stream real-time và demo retry giữa chừng
STUB_SLEEP_S = 1.5


async def add_log(pool: asyncpg.Pool, run_id: int, message: str, level: str = "info") -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO run_logs (run_id, level, message) VALUES ($1, $2, $3)",
            run_id,
            level,
            message,
        )


async def mark_run_failed(pool: asyncpg.Pool, job: asyncpg.Record, error: str) -> None:
    """Job hết lượt thử (dead) → Run chuyển 'failed'."""
    await pool.execute(
        "UPDATE runs SET status = 'failed', error = $2, finished_at = now() WHERE id = $1",
        job["run_id"],
        error[:500],
    )
    await add_log(
        pool,
        job["run_id"],
        f"Run thất bại sau {job['attempts']} lần thử: {error}",
        level="error",
    )


async def log_run_retry(pool: asyncpg.Pool, job: asyncpg.Record, error: str) -> None:
    """Job lỗi còn lượt thử → ghi log để UI biết Run đang chờ retry, không treo lặng."""
    delay = jobqueue._backoff(job["attempts"])
    await add_log(
        pool,
        job["run_id"],
        f"Lỗi lần thử {job['attempts']}/{job['max_attempts']}: {error[:200]} — "
        f"sẽ thử lại sau {delay:.0f}s",
        level="error",
    )


async def _run_stub(args: str) -> tuple[int, str]:
    """Stub tool: ngủ rồi echo — chứng minh vòng lặp, thay bằng CLI thật sau."""
    await asyncio.sleep(STUB_SLEEP_S)
    return 0, f"{args}\n(stdout stub — tool CLI thật sẽ vào chỗ này ở ticket sau)"


async def _execute_tool(
    pool: asyncpg.Pool,
    run_id: int,
    seq: int,
    total: int,
    args: str,
    limiter: RateLimiter | None,
    ident: dict[str, str],
) -> None:
    """Một Tool Execution: chờ rate limit → chạy tool → ghi stdout vào log stream."""
    if limiter is not None:
        await limiter.wait()  # mọi request của Run đều đi qua đây
    header_note = " ".join(f"[{k}: {v}]" for k, v in ident.items())
    async with pool.acquire() as conn:
        exec_id = await conn.fetchval(
            "INSERT INTO tool_executions (run_id, seq, tool, args) "
            "VALUES ($1, $2, $3, $4) RETURNING id",
            run_id,
            seq,
            STUB_TOOL,
            args,
        )
    await add_log(pool, run_id, f"$ {STUB_TOOL} {args} {header_note}".rstrip())

    started = time.monotonic()
    exit_code, stdout = await _run_stub(args)
    elapsed = time.monotonic() - started

    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE tool_executions SET status = 'ok', exit_code = $2, stdout = $3, "
            "finished_at = now() WHERE id = $1",
            exec_id,
            exit_code,
            stdout,
        )
    for line in stdout.splitlines():
        await add_log(pool, run_id, line)
    await add_log(pool, run_id, f"→ xong #{seq}/{total} · exit {exit_code} · {elapsed:.1f}s")


async def execute_run(pool: asyncpg.Pool, job: asyncpg.Record) -> None:
    """Handler của job type 'run' — chạy 1 Run tới completed hoặc ném lỗi để queue retry."""
    run_id = job["run_id"]
    async with pool.acquire() as conn:
        run = await conn.fetchrow(
            """
            SELECT r.*, pr.name AS program_name, pl.slug AS platform,
                   pl.name AS platform_name
            FROM runs r
            JOIN programs pr ON pr.id = r.program_id
            JOIN platforms pl ON pl.id = pr.platform_id
            WHERE r.id = $1
            """,
            run_id,
        )
    if run is None:
        raise RuntimeError(f"run {run_id} không tồn tại")

    # lần chạy đầu: pending → running; lần reclaim sau crash giữ nguyên 'running'
    await pool.execute(
        "UPDATE runs SET status = 'running', started_at = COALESCE(started_at, now()), "
        "error = NULL WHERE id = $1 AND status = 'pending'",
        run_id,
    )
    # attempt mới = bộ Tool Execution mới (log giữ nguyên để còn xem dấu vết retry)
    await pool.execute("DELETE FROM tool_executions WHERE run_id = $1", run_id)

    rate = run["rate_limit_rps"]
    limiter = RateLimiter(1.0 / rate) if rate and rate > 0 else None
    ident: dict[str, str] = {}
    if run["ident_header_name"] and run["ident_header_value"]:
        ident[run["ident_header_name"]] = run["ident_header_value"]

    await add_log(
        pool,
        run_id,
        f"Bắt đầu Run cho Program «{run['program_name']}» "
        f"(platform {run['platform_name']}, lần thử {job['attempts']}/{job['max_attempts']})",
    )
    if limiter is None:
        await add_log(pool, run_id, "Rate limit: không giới hạn")
    else:
        await add_log(pool, run_id, f"Rate limit: tối đa {rate:g} req/s cho mọi Tool Execution")
    if ident:
        (hname, hvalue), = ident.items()
        await add_log(pool, run_id, f"Header định danh: {hname}: {hvalue}")

    for seq in range(1, STUB_EXECUTIONS + 1):
        args = f"hello từ Tool Execution #{seq}/{STUB_EXECUTIONS}"
        await _execute_tool(pool, run_id, seq, STUB_EXECUTIONS, args, limiter, ident)

    await pool.execute(
        "UPDATE runs SET status = 'completed', finished_at = now() WHERE id = $1",
        run_id,
    )
    await add_log(
        pool, run_id, f"Run hoàn tất: {STUB_EXECUTIONS}/{STUB_EXECUTIONS} Tool Execution thành công"
    )
    log.info("run %d hoàn tất", run_id)


HANDLERS = {"run": execute_run}
DEAD_HANDLERS = {"run": mark_run_failed}
RETRY_HANDLERS = {"run": log_run_retry}
