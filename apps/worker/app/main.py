import asyncio
import logging
import socket
import time
from contextlib import asynccontextmanager

import asyncpg
import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import audit, hermes_client, jobqueue, recon, runner, runs, summary, sync
from .config import settings
from .db import run_migrations

logging.basicConfig(level=logging.INFO)

pool: asyncpg.Pool | None = None
_consumer_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool, _consumer_task
    # jsonb KHÔNG đặt codec toàn cục (set_type_codec 'pg_catalog' không có tác
    # dụng với jsonb trên asyncpg 0.30) — parse tường minh ở 2 điểm tiêu thụ:
    # runs.get_run và runner.execute_run
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=5)
    applied = await run_migrations(pool)
    if applied:
        logging.getLogger("worker").info("applied migrations: %s", applied)
    await sync.recover_on_startup(pool)
    await summary.recover_on_startup(pool)
    # consumer queue (ADR-0001) — job crash giữa chừng được reclaim qua visibility timeout
    worker_id = f"{socket.gethostname()}-{id(pool)}"
    _consumer_task = asyncio.create_task(
        jobqueue.loop(
            pool, runner.HANDLERS, runner.DEAD_HANDLERS, worker_id, runner.RETRY_HANDLERS
        )
    )
    yield
    if _consumer_task is not None:
        _consumer_task.cancel()
        await asyncio.gather(_consumer_task, return_exceptions=True)
    if pool is not None:
        await pool.close()


app = FastAPI(title="vul-hunting worker", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict:
    assert pool is not None
    started = time.perf_counter()
    try:
        async with pool.acquire() as conn:
            version = await conn.fetchval("SELECT version()")
        postgres = {
            "connected": True,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "version": version.split()[1] if version else None,
        }
    except Exception as exc:
        postgres = {"connected": False, "error": str(exc)}
    return {
        "status": "ok" if postgres["connected"] else "degraded",
        "service": "worker",
        "postgres": postgres,
    }


# ─────────────────────────── hermes agent (ticket #2) ───────────────────────────


class SmokeRequest(BaseModel):
    prompt: str | None = None


_SMOKE_PROMPT = 'Dùng skill "hello" và trả lời đúng theo hướng dẫn của skill đó.'


@app.get("/agent/health")
async def agent_health() -> dict:
    return await hermes_client.health()


@app.post("/agent/smoke")
async def agent_smoke(req: SmokeRequest) -> dict:
    """Prompt → text model + usage JSON (chạy qua POST /v1/runs + đọc SSE events)."""
    try:
        result = await hermes_client.run_agent(req.prompt or _SMOKE_PROMPT)
    except hermes_client.HermesError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    usage = result["usage"]
    cost = usage.get("total_cost") or usage.get("cost")
    return {
        "run_id": result["run_id"],
        "status": result["status"],
        "text": result["text"],
        "usage": usage,
        "estimated_cost_usd": cost,
        "events_seen": result["events_seen"],
    }


@app.post("/agent/chat")
async def agent_chat(req: SmokeRequest) -> dict:
    """One-shot qua POST /v1/chat/completions (không tool)."""
    try:
        result = await hermes_client.chat_completion(req.prompt or "ping")
    except hermes_client.HermesError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    usage = result["usage"]
    return {
        "text": result["text"],
        "usage": usage,
        "estimated_cost_usd": usage.get("total_cost") or usage.get("cost"),
        "model": result["model"],
    }


# ─────────────────────── sync platforms (ticket #3, #4) ───────────────────────


@app.post("/sync/{platform}")
async def sync_platform(platform: str) -> dict:
    assert pool is not None
    if platform not in sync.PLATFORMS:
        raise HTTPException(status_code=404, detail=f"platform '{platform}' không hỗ trợ")
    try:
        return await sync.start_sync(pool, platform)
    except (sync.h1_client.HackerOneError, sync.intigriti_client.IntigritiError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/sync/{platform}/status")
async def sync_platform_status(platform: str) -> dict:
    assert pool is not None
    if platform not in sync.PLATFORMS:
        raise HTTPException(status_code=404, detail=f"platform '{platform}' không hỗ trợ")
    return await sync.sync_status(pool, platform)


@app.get("/programs")
async def list_programs(
    platform: str | None = None,
    bounty: str | None = None,  # 'any' | 'yes' | 'no'
    bounty_min: float | None = None,  # payout tối đa của program ≥ số này
    asset_type: str | None = None,
    q: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
) -> dict:
    assert pool is not None
    clauses: list[str] = []
    params: list = []

    def add(cond: str, *values, cast: str = "text") -> None:
        # thay TỪNG "?" một (không dùng replace toàn cục — nhiều ? chung 1 cond
        # cần các $N khác nhau) + cast tường minh để Postgres không bầu kiểu
        for v in values:
            params.append(v)
            cond = cond.replace("?", f"${len(params)}::{cast}", 1)
        clauses.append(cond)

    if platform and platform != "all":
        add("pl.slug = ?", platform)
    if bounty == "yes":
        add("pr.offers_bounties = TRUE")
    elif bounty == "no":
        add("pr.offers_bounties = FALSE")
    if bounty_min:
        add("pr.max_bounty >= ?", float(bounty_min), cast="numeric")
    if asset_type and asset_type != "all":
        add(
            "EXISTS (SELECT 1 FROM assets a WHERE a.program_id = pr.id "
            "AND a.asset_type = ?)",
            asset_type,
        )
    if q:
        like = f"%{q}%"
        add(
            "(pr.name ILIKE ? OR pr.handle ILIKE ? OR EXISTS "
            "(SELECT 1 FROM assets a WHERE a.program_id = pr.id "
            "AND a.asset_identifier ILIKE ?))",
            like,
            like,
            like,
        )

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    offset = (page - 1) * page_size
    async with pool.acquire() as conn:
        total = await conn.fetchval(
            f"SELECT count(*) FROM programs pr JOIN platforms pl ON pl.id = pr.platform_id {where}",
            *params,
        )
        rows = await conn.fetch(
            f"""
            SELECT pr.id, pr.handle, pr.name, pr.currency, pr.submission_state,
                   pr.offers_bounties, pr.min_bounty, pr.max_bounty,
                   pr.open_scope, pr.triage_active, pr.synced_at,
                   pl.slug AS platform,
                   (SELECT count(*) FROM assets a WHERE a.program_id = pr.id) AS asset_count
            FROM programs pr JOIN platforms pl ON pl.id = pr.platform_id
            {where}
            ORDER BY pr.offers_bounties DESC, pr.name
            LIMIT {page_size} OFFSET {offset}
            """,
            *params,
        )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [dict(r) for r in rows],
    }


@app.get("/programs/{program_id}")
async def get_program(program_id: int) -> dict:
    assert pool is not None
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT pr.*, pl.slug AS platform, pl.name AS platform_name,
                   s.summary, s.model AS summary_model, s.status AS summary_status,
                   s.error AS summary_error, s.generated_at AS summary_generated_at
            FROM programs pr
            JOIN platforms pl ON pl.id = pr.platform_id
            LEFT JOIN program_summaries s ON s.program_id = pr.id
            WHERE pr.id = $1
            """,
            program_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="program không tồn tại")
        assets = await conn.fetch(
            "SELECT * FROM assets WHERE program_id = $1 "
            "ORDER BY eligible_for_bounty DESC, asset_identifier",
            program_id,
        )
    program = dict(row)
    # chưa từng sinh summary → row LEFT JOIN rỗng → chuẩn hoá về 'none'
    program["summary_status"] = program["summary_status"] or "none"
    program["assets"] = [dict(a) for a in assets]
    return program


@app.post("/programs/{program_id}/summary")
async def generate_program_summary(program_id: int) -> dict:
    """Bật sinh AI summary nền (lazy khi mở detail / bấm refresh). Không chặn."""
    assert pool is not None
    result = await summary.start(pool, program_id)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail="program không tồn tại")
    return result


# ─────────────────── Run core: queue + log stream (ticket #6) ───────────────────


class CreateRunRequest(BaseModel):
    rate_limit_rps: float | None = Field(default=1.0)  # None (null) = không giới hạn
    ident_header_name: str | None = None  # trống → 'X-Bug-Bounty'
    ident_header_value: str | None = None  # trống → mặc định từ username platform trong env
    allow_non_prod: bool = False  # cho phép subdomain non-production (mặc định chặn)


@app.post("/programs/{program_id}/runs", status_code=201)
async def create_run(program_id: int, req: CreateRunRequest | None = None) -> dict:
    """Tạo Run 'pending' + Scope snapshot + job xếp hàng chung 1 transaction."""
    assert pool is not None
    req = req or CreateRunRequest()
    try:
        result = await runs.create_run(
            pool,
            program_id,
            req.rate_limit_rps,
            req.ident_header_name,
            req.ident_header_value,
            allow_non_prod=req.allow_non_prod,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="program không tồn tại")
    return result


@app.get("/runs")
async def list_runs(status: str | None = None, limit: int = Query(50, ge=1, le=200)) -> dict:
    assert pool is not None
    items = await runs.list_runs(pool, status, limit)
    return {"items": items}


@app.get("/runs/{run_id}")
async def get_run(run_id: int) -> dict:
    assert pool is not None
    run = await runs.get_run(pool, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run không tồn tại")
    return run


@app.get("/runs/{run_id}/assets")
async def list_run_assets(
    run_id: int, limit: int = Query(500, ge=1, le=5000)
) -> dict:
    """Kết quả Recon Phase (subdomain + live host + CNAME) + bộ đếm — UI poll
    endpoint này để thấy số lượng tăng dần trong lúc Run chạy."""
    assert pool is not None
    return await recon.list_assets(pool, run_id, limit)


@app.get("/runs/{run_id}/logs")
async def get_run_logs(run_id: int, after: int = Query(0, ge=0)) -> dict:
    """Log mới kể từ `after` (id cuối đã thấy) — fallback poll khi SSE không dùng được."""
    assert pool is not None
    items = await runs.logs_after(pool, run_id, after)
    return {"items": items}


@app.get("/runs/{run_id}/stream")
async def stream_run(run_id: int, after: int = Query(0, ge=0)) -> StreamingResponse:
    """SSE stream log của Run — generator nằm ở runs.py, endpoint chỉ bọc response."""
    assert pool is not None
    return StreamingResponse(
        runs.stream_events(pool, run_id, after),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/audit")
async def list_audit(
    run_id: int | None = None,
    target: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
) -> dict:
    """Audit log của Scope Validator — lọc theo Run và/hoặc theo asset (target)."""
    assert pool is not None
    items = await audit.list_entries(pool, run_id, target, limit)
    return {"items": items}
