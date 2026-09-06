"""Thực thi Run (ticket #6) — vòng lặp Tool Execution với stub tool sleep+echo.

Tool thật (recon, nuclei, …) ở ticket sau; cơ chế đã đủ dùng:
- rate limit (req/s) và header định danh nằm trong Run config, MỌI Tool
  Execution đều kế thừa (limiter chờ trước, header ghi kèm mỗi lần gọi);
- Scope Validator (ticket #7) chặn cứng mọi target không thuộc Scope snapshot
  của Run — tool nhận lỗi rõ ràng (TargetBlockedError), không crash âm thầm;
- mọi target đều ghi audit log (cả allowed lẫn blocked) vào scope_audit_log;
- stdout của từng lần chạy đổ vào run_logs để UI stream qua SSE, kèm row
  tool_executions giữ exit code + stdout đầy đủ;
- lỗi giữa chừng ném lên cho jobqueue xử lý retry/dead.
"""

import asyncio
import logging
import time
from dataclasses import dataclass

import asyncpg

from . import audit, jobqueue
from .runs import parse_snapshot
from .ratelimit import RateLimiter
from .scope_validator import ScopeDecision, check_target, target_host

log = logging.getLogger("runner")

STUB_TOOL = "stub-echo"
STUB_EXECUTIONS = 5  # đủ dài để xem stream real-time và demo retry giữa chừng
STUB_SLEEP_S = 1.5


class TargetBlockedError(Exception):
    """Scope Validator chặn target — tool nhận lỗi này tường minh."""


@dataclass
class ToolContext:
    """Cái MỌI Tool Execution của Run đều kế thừa: rate limit, header định danh,
    Scope snapshot + config non-prod. validate() là cửa ắt BẮT BUỘC trước khi
    chạm target — audit log ghi cả lần được phép lẫn lần bị chặn."""

    run_id: int
    tool: str
    limiter: RateLimiter | None
    ident: dict[str, str]
    snapshot: list[dict]
    allow_non_prod: bool = False

    async def validate(self, pool: asyncpg.Pool, target: str) -> ScopeDecision:
        """Cửa ra ngoài duy nhất của tool — ghi audit TRƯỚC khi quyết định.

        Fail-closed: nếu chính lần ghi audit lỗi (DB trục trặc), exception
        đẩy lên để Run retry — không có request nào ra ngoài mà thiếu audit.
        """
        d = check_target(target, self.snapshot, allow_non_prod=self.allow_non_prod)
        await audit.record(
            pool, self.run_id, self.tool, target_host(target), d.decision, d.reason
        )
        if not d.allowed:
            raise TargetBlockedError(d.reason)
        return d


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


def _demo_targets(snapshot: list[dict]) -> list[str]:
    """5 target demo (stub): in-scope qua wildcard → ngoài scope → non-prod → in-scope ×2.

    Scope không có wildcard thì mọi target đều ngoài scope — log vẫn minh hoạ
    validator chặn đúng. Target thật sẽ đến từ tool CLI ở ticket sau.
    """
    wild = next((a for a in snapshot if a.get("asset_type") == "WILDCARD"), None)
    if not wild:
        return ["out-of-scope.invalid"] * STUB_EXECUTIONS
    base = wild["asset_identifier"].removeprefix("*.")
    return [
        f"app.{base}",
        "out-of-scope.invalid",
        f"dev.{base}",
        f"api.{base}",
        f"app.{base}",
    ]


async def _run_stub(target: str) -> tuple[int, str]:
    """Stub tool: ngủ rồi echo — chứng minh vòng lặp, thay bằng CLI thật sau."""
    await asyncio.sleep(STUB_SLEEP_S)
    return 0, f"đã 'quét' {target}\n(stdout stub — tool CLI thật sẽ vào chỗ này ở ticket sau)"


async def _execute_tool(
    pool: asyncpg.Pool,
    ctx: ToolContext,
    seq: int,
    total: int,
    target: str,
) -> str:
    """Một Tool Execution: Scope Validator → chờ rate limit → chạy tool.

    Trả 'ok' | 'blocked'. Target bị chặn KHÔNG làm Run thất bại — validator
    đang làm đúng việc: ghi audit, báo tool lỗi tường minh rồi chạy tiếp.
    """
    header_note = " ".join(f"[{k}: {v}]" for k, v in ctx.ident.items())
    args = f"--target {target} (Tool Execution #{seq}/{total})"
    async with pool.acquire() as conn:
        exec_id = await conn.fetchval(
            "INSERT INTO tool_executions (run_id, seq, tool, args) "
            "VALUES ($1, $2, $3, $4) RETURNING id",
            ctx.run_id,
            seq,
            ctx.tool,
            args,
        )
    await add_log(pool, ctx.run_id, f"$ {ctx.tool} {args} {header_note}".rstrip())

    started = time.monotonic()
    try:
        await ctx.validate(pool, target)
    except TargetBlockedError as exc:
        await pool.execute(
            "UPDATE tool_executions SET status = 'blocked', exit_code = 2, stdout = $2, "
            "finished_at = now() WHERE id = $1",
            exec_id,
            str(exc),
        )
        await add_log(pool, ctx.run_id, f"BLOCKED: {exc}", level="error")
        return "blocked"

    if ctx.limiter is not None:
        await ctx.limiter.wait()  # mọi request ra ngoài của Run đều đi qua đây
    exit_code, stdout = await _run_stub(target)
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
        await add_log(pool, ctx.run_id, line)
    await add_log(pool, ctx.run_id, f"→ xong #{seq}/{total} · exit {exit_code} · {elapsed:.1f}s")
    return "ok"


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

    # asyncpg trả jsonb dạng str — parse tường minh tại điểm tiêu thụ
    snapshot = parse_snapshot(run["scope_snapshot"])
    rate = run["rate_limit_rps"]
    limiter = RateLimiter(1.0 / rate) if rate and rate > 0 else None
    ident: dict[str, str] = {}
    if run["ident_header_name"] and run["ident_header_value"]:
        ident[run["ident_header_name"]] = run["ident_header_value"]
    ctx = ToolContext(
        run_id=run_id,
        tool=STUB_TOOL,
        limiter=limiter,
        ident=ident,
        snapshot=snapshot,
        allow_non_prod=bool(run["allow_non_prod"]),
    )

    await add_log(
        pool,
        run_id,
        f"Bắt đầu Run cho Program «{run['program_name']}» "
        f"(platform {run['platform_name']}, lần thử {job['attempts']}/{job['max_attempts']})",
    )
    non_prod_note = "cho phép" if ctx.allow_non_prod else "chặn"
    await add_log(
        pool,
        run_id,
        f"Scope Validator: đối chiếu {len(snapshot)} Asset trong snapshot · "
        f"subdomain non-production: {non_prod_note}",
    )
    if limiter is None:
        await add_log(pool, run_id, "Rate limit: không giới hạn")
    else:
        await add_log(pool, run_id, f"Rate limit: tối đa {rate:g} req/s cho mọi Tool Execution")
    if ident:
        (hname, hvalue), = ident.items()
        await add_log(pool, run_id, f"Header định danh: {hname}: {hvalue}")

    targets = _demo_targets(snapshot)
    ok = blocked = 0
    for seq, target in enumerate(targets, start=1):
        if await _execute_tool(pool, ctx, seq, len(targets), target) == "blocked":
            blocked += 1
        else:
            ok += 1

    await pool.execute(
        "UPDATE runs SET status = 'completed', finished_at = now() WHERE id = $1",
        run_id,
    )
    await add_log(
        pool,
        run_id,
        f"Run hoàn tất: {ok}/{len(targets)} Tool Execution ok · "
        f"{blocked}/{len(targets)} bị Scope Validator chặn",
    )
    log.info("run %d hoàn tất", run_id)


HANDLERS = {"run": execute_run}
DEAD_HANDLERS = {"run": mark_run_failed}
RETRY_HANDLERS = {"run": log_run_retry}
