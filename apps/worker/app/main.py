import logging
import time
from contextlib import asynccontextmanager

import asyncpg
import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from . import hermes_client, sync
from .config import settings
from .db import run_migrations

logging.basicConfig(level=logging.INFO)

pool: asyncpg.Pool | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=5)
    applied = await run_migrations(pool)
    if applied:
        logging.getLogger("worker").info("applied migrations: %s", applied)
    await sync.recover_on_startup(pool)
    yield
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
            SELECT pr.*, pl.slug AS platform, pl.name AS platform_name
            FROM programs pr JOIN platforms pl ON pl.id = pr.platform_id
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
    program["assets"] = [dict(a) for a in assets]
    return program
