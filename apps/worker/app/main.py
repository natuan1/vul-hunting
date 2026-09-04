import time
from contextlib import asynccontextmanager

import asyncpg
from fastapi import FastAPI

from .config import settings

pool: asyncpg.Pool | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=5)
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
