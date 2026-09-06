"""Audit log của Scope Validator (ticket #7).

Mọi target mà Tool Execution định chạm tới đều được ghi lại ở đây — cả khi
được phép lẫn khi bị chặn. Truy theo Run hoặc theo asset (target) qua
`list_entries`; đây là bằng chứng "validator đã nhìn thấy mọi request".
"""

import asyncpg

_INSERT = """
INSERT INTO scope_audit_log (run_id, tool, target, decision, reason)
VALUES ($1, $2, $3, $4, $5)
"""


async def record(
    pool: asyncpg.Pool,
    run_id: int,
    tool: str,
    target: str,
    decision: str,
    reason: str,
) -> None:
    async with pool.acquire() as conn:
        await conn.execute(_INSERT, run_id, tool, target, decision, reason)


async def list_entries(
    pool: asyncpg.Pool,
    run_id: int | None = None,
    target: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """Lọc theo Run (`run_id`) và/hoặc theo asset (`target`, khớp một phần)."""
    clauses: list[str] = []
    params: list = []
    if run_id is not None:
        params.append(run_id)
        clauses.append(f"a.run_id = ${len(params)}")
    if target:
        params.append(f"%{target}%")
        clauses.append(f"a.target ILIKE ${len(params)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT a.id, a.run_id, a.tool, a.target, a.decision, a.reason, a.ts,
                   pr.name AS program_name, pl.slug AS platform
            FROM scope_audit_log a
            JOIN runs r ON r.id = a.run_id
            JOIN programs pr ON pr.id = r.program_id
            JOIN platforms pl ON pl.id = pr.platform_id
            {where}
            ORDER BY a.id DESC
            LIMIT ${len(params)}
            """,
            *params,
        )
    return [dict(r) for r in rows]
