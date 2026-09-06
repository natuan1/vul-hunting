"""Tạo Run + chụp Scope snapshot, truy vấn Run, stream log (ticket #6).

Snapshot chụp NGAY lúc tạo Run — Run sau này thao tác trên bản chụp, không đọc
bảng assets trực tiếp, để Scope thay đổi giữa chừng không làm lệch Run đang chạy.
"""

import asyncio
import json

import asyncpg

from . import jobqueue
from .config import settings

# platform slug → (nhãn dùng trong header, getter username từ settings)
_PLATFORM_IDENT = {
    "hackerone": ("HackerOne", lambda: settings.hackerone_username),
    "intigriti": ("Intigriti", lambda: settings.intigriti_username),
}

IDENT_HEADER_NAME = "X-Bug-Bounty"

_SCOPE_SNAPSHOT = """
SELECT asset_identifier, asset_type, eligible_for_bounty, eligible_for_submission,
       max_severity, tier, instruction
FROM assets WHERE program_id = $1
ORDER BY eligible_for_bounty DESC, asset_identifier
"""


def default_ident(platform_slug: str) -> tuple[str, str] | None:
    """Header định danh mặc định cho platform, vd ('X-Bug-Bounty', 'HackerOne-tuan').

    Thiếu username platform → None (caller để giá trị trống, UI tự điền tay).
    """
    entry = _PLATFORM_IDENT.get(platform_slug)
    if entry is None:
        return None
    label, username_getter = entry
    username = username_getter()
    if not username:
        return None
    return (IDENT_HEADER_NAME, f"{label}-{username}")


async def create_run(
    pool: asyncpg.Pool,
    program_id: int,
    rate_limit_rps: float | None,
    ident_header_name: str | None,
    ident_header_value: str | None,
) -> dict:
    """Tạo Run 'pending' + Scope snapshot + job xếp hàng — chung 1 transaction để
    không bao giờ tồn tại Run mà mất job (mất job thì không thứ gì chạy lại được).

    Trả {"run": …, "job_id": …}; rate_limit_rps không hợp lệ raise ValueError;
    sai program trả {}.
    """
    if rate_limit_rps is not None and rate_limit_rps <= 0:
        raise ValueError("rate_limit_rps phải > 0 (hoặc null để không giới hạn)")
    ident_header_name = (ident_header_name or "").strip() or None
    ident_header_value = (ident_header_value or "").strip() or None
    async with pool.acquire() as conn:
        async with conn.transaction():
            prog = await conn.fetchrow(
                """
                SELECT pr.id, pl.slug AS platform
                FROM programs pr JOIN platforms pl ON pl.id = pr.platform_id
                WHERE pr.id = $1
                """,
                program_id,
            )
            if prog is None:
                return {}
            snapshot = [dict(r) for r in await conn.fetch(_SCOPE_SNAPSHOT, program_id)]
            # header định danh: dùng giá trị người dùng nhập, thiếu thì lấy mặc định env
            if ident_header_value:
                ident_header_name = ident_header_name or IDENT_HEADER_NAME
            else:
                d = default_ident(prog["platform"])
                if d:
                    ident_header_name = ident_header_name or d[0]
                    ident_header_value = d[1]
            row = await conn.fetchrow(
                """
                INSERT INTO runs (program_id, rate_limit_rps,
                                  ident_header_name, ident_header_value, scope_snapshot)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING *
                """,
                program_id,
                rate_limit_rps,
                ident_header_name,
                ident_header_value,
                json.dumps(snapshot),
            )
            job_id = await jobqueue.enqueue(conn, row["id"])
    return {"run": dict(row), "job_id": job_id}


async def get_run(pool: asyncpg.Pool, run_id: int) -> dict | None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT r.*, pr.name AS program_name, pr.handle AS program_handle,
                   pl.slug AS platform, pl.name AS platform_name
            FROM runs r
            JOIN programs pr ON pr.id = r.program_id
            JOIN platforms pl ON pl.id = pr.platform_id
            WHERE r.id = $1
            """,
            run_id,
        )
        if row is None:
            return None
        run = dict(row)
        run["tool_executions"] = [
            dict(r)
            for r in await conn.fetch(
                "SELECT id, seq, tool, args, status, exit_code, stdout, "
                "started_at, finished_at FROM tool_executions "
                "WHERE run_id = $1 ORDER BY seq",
                run_id,
            )
        ]
    return run


async def list_runs(pool: asyncpg.Pool, status: str | None, limit: int) -> list[dict]:
    where = "WHERE r.status = $1" if status else ""
    params: list = [status] if status else []
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT r.id, r.program_id, r.status, r.rate_limit_rps,
                   r.ident_header_name, r.ident_header_value, r.error,
                   r.created_at, r.started_at, r.finished_at,
                   pr.name AS program_name, pr.handle AS program_handle,
                   pl.slug AS platform
            FROM runs r
            JOIN programs pr ON pr.id = r.program_id
            JOIN platforms pl ON pl.id = pr.platform_id
            {where}
            ORDER BY r.id DESC
            LIMIT ${len(params) + 1}
            """,
            *params,
            limit,
        )
    return [dict(r) for r in rows]


async def logs_after(pool: asyncpg.Pool, run_id: int, after: int, limit: int = 1000) -> list[dict]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, level, message, ts FROM run_logs "
            "WHERE run_id = $1 AND id > $2 ORDER BY id LIMIT $3",
            run_id,
            after,
            limit,
        )
    return [dict(r) for r in rows]


async def stream_events(pool: asyncpg.Pool, run_id: int, after: int):
    """SSE generator: `event: log` cho từng dòng mới, `event: done` khi Run kết thúc."""
    yield "retry: 3000\n\n"
    last = after
    while True:
        items = await logs_after(pool, run_id, last)
        for item in items:
            last = item["id"]
            data = json.dumps(
                {"level": item["level"], "message": item["message"],
                 "ts": item["ts"].isoformat()},
                ensure_ascii=False,
            )
            yield f"id: {item['id']}\nevent: log\ndata: {data}\n\n"
        if items:
            continue  # còn dồn log — đón lô kế tiếp ngay, không nghỉ
        row = await pool.fetchrow("SELECT status FROM runs WHERE id = $1", run_id)
        if row is None:
            yield f"event: done\ndata: {json.dumps({'status': 'missing'})}\n\n"
            return
        if row["status"] in ("completed", "failed"):
            yield f"event: done\ndata: {json.dumps({'status': row['status']})}\n\n"
            return
        await asyncio.sleep(1.0)
