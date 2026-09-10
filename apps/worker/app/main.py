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

from . import audit, detect, guardrails, hermes_client, httpverify, jobqueue, oob, recon, report, runner, runs, sandbox, sandbox_mcp, summary, sync, takeover, verify
from .config import settings
from .db import run_migrations
from .egress import EgressProxy

logging.basicConfig(level=logging.INFO)

pool: asyncpg.Pool | None = None
_consumer_task: asyncio.Future | None = None
_proxy_server: asyncio.AbstractServer | None = None
_oob_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pool, _consumer_task, _proxy_server, _oob_task
    # jsonb KHÔNG đặt codec toàn cục (set_type_codec 'pg_catalog' không có tác
    # dụng với asyncpg 0.30) — parse tường minh ở 2 điểm tiêu thụ:
    # runs.get_run và runner.execute_run
    pool = await asyncpg.create_pool(
        settings.database_url, min_size=1, max_size=settings.db_pool_max
    )
    applied = await run_migrations(pool)
    if applied:
        logging.getLogger("worker").info("applied migrations: %s", applied)
    await sync.recover_on_startup(pool)
    await summary.recover_on_startup(pool)

    # sandbox bridge (ticket #11): dọn container/network sót từ lần crash +
    # egress proxy (luật ra ngoài duy nhất của container sandbox) + MCP server
    sandbox_mcp.bind_pool(pool)
    await sandbox.cleanup_stale()
    proxy = EgressProxy(
        registry=sandbox.session_registry,
        record=lambda *args: sandbox.record_egress(pool, *args),
    )
    _proxy_server = await asyncio.start_server(
        proxy.handle_client, "0.0.0.0", settings.sandbox_proxy_port
    )
    logging.getLogger("worker").info(
        "egress proxy listening on :%d", settings.sandbox_proxy_port
    )

    # MCP server của sandbox bridge: session manager PHẢI chạy trong lifespan
    # (Mount không truyền lifespan của sub-app xuống) — giữ nguyên suốt vòng
    # đời process, mọi request /mcp đi qua đây
    async with sandbox_mcp.mcp.session_manager.run():
        # consumer queue (ADR-0001) — job crash giữa chừng được reclaim qua
        # visibility timeout. Chạy N consumer SONG SONG (= guardrail cap, ticket
        # #19): nhiều Run chạy đồng thời nhưng tổng Tool Execution vẫn ≤ cap
        # (guardrails.CAP chặn trong execute_tool); SKIP LOCKED lo claim an toàn
        worker_id = f"{socket.gethostname()}-{id(pool)}"
        _consumer_task = asyncio.gather(
            *[
                jobqueue.loop(
                    pool,
                    runner.HANDLERS,
                    runner.DEAD_HANDLERS,
                    f"{worker_id}-{i}",
                    runner.RETRY_HANDLERS,
                )
                for i in range(settings.guardrail_max_concurrent)
            ],
            return_exceptions=True,
        )
        # poller OOB (ticket #13): callback từ Internet gắn vào Candidate đang
        # chờ verify + sweep registration hết hạn + dọn callback cache
        _oob_task = asyncio.create_task(oob.poll_forever(pool))
        yield
        for task in (_consumer_task, _oob_task):
            if task is not None:
                task.cancel()
        await asyncio.gather(_consumer_task, _oob_task, return_exceptions=True)
    if _proxy_server is not None:
        _proxy_server.close()
        await _proxy_server.wait_closed()
    if pool is not None:
        await pool.close()


app = FastAPI(title="vul-hunting worker", lifespan=lifespan)

# MCP server của sandbox bridge (ticket #11) — hermes trỏ MCP toolset về đây
app.mount("/mcp", sandbox_mcp.mcp_asgi_app())


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
        # guardrails (ticket #19): cap Tool Execution đồng thời + mức cao nhất
        # đã quan sát trong đời process — bằng chứng "không bao giờ vượt cap"
        "guardrails": {
            **guardrails.CAP.stats(),
            "runs_guarded": guardrails.runs_guarded(),
        },
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


@app.post("/runs/{run_id}/resume")
async def resume_run(run_id: int) -> dict:
    """Lối thoát DUY NHẤT khỏi 'halted' (guardrail ban signal, ticket #19) —
    người dùng bấm tay, KHÔNG có auto-resume. Run về 'pending' + job xếp hàng lại."""
    assert pool is not None
    resumed = await guardrails.resume_run(pool, run_id)
    if not resumed:
        raise HTTPException(status_code=409, detail="run không ở trạng thái halted")
    run = await runs.get_run(pool, run_id)
    return {"run": run}


@app.get("/runs/{run_id}/assets")
async def list_run_assets(
    run_id: int, limit: int = Query(500, ge=1, le=5000)
) -> dict:
    """Kết quả Recon Phase (subdomain + live host + CNAME) + bộ đếm — UI poll
    endpoint này để thấy số lượng tăng dần trong lúc Run chạy."""
    assert pool is not None
    return await recon.list_assets(pool, run_id, limit)


@app.get("/runs/{run_id}/urls")
async def list_run_urls(
    run_id: int,
    limit: int = Query(500, ge=1, le=5000),
    classed: bool | None = Query(None),
) -> dict:
    """Bảng URLs + params + nhãn class từ gf (ticket #9) — nguồn mục tiêu của
    Detection Phase; truy được theo Run (và qua Run là theo Program)."""
    assert pool is not None
    return await recon.list_urls(pool, run_id, limit, classed)


@app.get("/programs/{program_id}/urls")
async def list_program_urls(
    program_id: int, limit: int = Query(500, ge=1, le=5000)
) -> dict:
    """URL của mọi Run thuộc Program (ticket #9) — truy theo Program."""
    assert pool is not None
    return await recon.list_program_urls(pool, program_id, limit)


# ─────────────── Detection: Candidate + Findings (ticket #10) ───────────────


class CandidateStatusRequest(BaseModel):
    status: str  # new | verifying | verified | rejected


@app.get("/candidates")
async def list_candidates(
    run_id: int | None = None,
    status: str | None = None,
    class_: str | None = Query(None, alias="class"),
    severity: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
) -> dict:
    """Findings screen: list Candidate + bộ đếm lifecycle, filter theo
    Run/status/class/severity."""
    assert pool is not None
    try:
        return await detect.list_candidates(
            pool, run_id, status, class_, severity, limit
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/candidates/{candidate_id}")
async def get_candidate(candidate_id: int) -> dict:
    assert pool is not None
    candidate = await detect.get_candidate(pool, candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail="candidate không tồn tại")
    return candidate


@app.get("/candidates/{candidate_id}/evidence")
async def get_candidate_evidence(candidate_id: int) -> dict:
    """Evidence viewer: nội dung file JSON (raw request/response, template,
    matcher) từ volume — 404 nếu Candidate/evidence không tồn tại."""
    assert pool is not None
    evidence = await detect.read_evidence(pool, candidate_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="evidence không tồn tại")
    return evidence


@app.post("/candidates/{candidate_id}/status")
async def set_candidate_status(candidate_id: int, req: CandidateStatusRequest) -> dict:
    """Chuyển lifecycle của Candidate (new → verifying → verified/rejected)."""
    assert pool is not None
    try:
        result = await detect.set_status(pool, candidate_id, req.status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="candidate không tồn tại")
    return result


class VerifyCandidateRequest(BaseModel):
    payload: str | None = None  # URL canary cho PoC (trống → canary mặc định)


@app.post("/candidates/{candidate_id}/verify")
async def verify_candidate(candidate_id: int, req: VerifyCandidateRequest | None = None) -> dict:
    """Chạy trọn vòng xác minh open redirect (ticket #12): baseline capture →
    soạn PoC → sandbox → response diff so baseline → confidence ≥ ngưỡng
    (VERIFY_CONFIDENCE_THRESHOLD, mặc định 0.85) → verified kèm evidence diff,
    ngược lại rejected kèm lý do + pattern log. Mọi payload chạy trong sandbox.
    Endpoint chỉ dành cho Candidate class 'redirect'."""
    assert pool is not None
    candidate = await detect.get_candidate(pool, candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail="candidate không tồn tại")
    if candidate["class"] != "redirect":
        raise HTTPException(
            status_code=422,
            detail=f"candidate thuộc class '{candidate['class']}' — vòng verify này dành cho class 'redirect'",
        )
    try:
        result = await verify.run_redirect_verification(
            pool, candidate, payload=(req.payload if req else None)
        )
    except verify.ProbeBlocked as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    updated = await detect.get_candidate(pool, candidate_id)
    return {"candidate": updated, "verify": result}


@app.get("/candidates/{candidate_id}/verify-evidence")
async def get_candidate_verify_evidence(candidate_id: int) -> dict:
    """Evidence diff của vòng xác minh (baseline + PoC + pattern log) — 404
    nếu Candidate/chưa verify/evidence không tồn tại."""
    assert pool is not None
    try:
        evidence = await detect.read_evidence(
            pool, candidate_id, path_column="verify_evidence_path"
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if evidence is None:
        raise HTTPException(status_code=404, detail="verify evidence không tồn tại")
    return evidence


# ─────────────── Interactsh OOB (ticket #13) ───────────────


@app.get("/candidates/{candidate_id}/oob")
async def get_candidate_oob(candidate_id: int) -> dict:
    """Callback count + chi tiết OOB của Candidate: registration hiện hành của
    Run (domain riêng per-Run) + danh sách callback (source, protocol,
    timestamp, raw interaction). 404 nếu Candidate không tồn tại."""
    assert pool is not None
    result = await oob.list_for_candidate(pool, candidate_id)
    if result is None:
        raise HTTPException(status_code=404, detail="candidate không tồn tại")
    return result


class VerifyOobRequest(BaseModel):
    wait_s: float | None = Field(default=None, gt=0, le=600)  # cửa sổ chờ callback
    poll_s: float | None = Field(default=None, gt=0, le=60)  # nhịp poll


@app.post("/candidates/{candidate_id}/verify-oob")
async def verify_candidate_oob(candidate_id: int, req: VerifyOobRequest | None = None) -> dict:
    """Chạy trọn vòng xác minh OOB (ticket #13 + batch C #17) cho Candidate
    blind class ssrf / blind XSS / XXE / deserialization: ensure registration
    interactsh per-Run → payload theo class (`oob_payload`) chèn vào param →
    baseline + PoC qua sandbox → chờ/poll callback trong cửa sổ chờ (mặc định
    OOB_VERIFY_WAIT_S) → callback về = verified kèm evidence OOB, hết cửa sổ
    → rejected kèm lý do. Deserialization: Finding luôn kèm cờ human review +
    severity trần. Payload gây cost → guardrails HALT Run."""
    assert pool is not None
    candidate = await detect.get_candidate(pool, candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail="candidate không tồn tại")
    if candidate["class"] not in oob.OOB_VERIFY_CLASSES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"candidate thuộc class '{candidate['class']}' — vòng verify OOB "
                f"dành cho class {', '.join(oob.OOB_VERIFY_CLASSES)}"
            ),
        )
    try:
        result = await oob.run_oob_verification(
            pool, candidate,
            wait_s=(req.wait_s if req else None),
            poll_s=(req.poll_s if req else None),
        )
    except verify.ProbeBlocked as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except oob.InteractshError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except guardrails.RunHalted as exc:
        raise HTTPException(
            status_code=422,
            detail=f"GUARDRAIL HALT: {exc}",
        ) from exc
    updated = await detect.get_candidate(pool, candidate_id)
    return {"candidate": updated, "verify": result}


@app.get("/candidates/{candidate_id}/oob-evidence")
async def get_candidate_oob_evidence(candidate_id: int) -> dict:
    """Evidence OOB của Candidate (callbacks + phân tích vòng verify OOB) —
    404 nếu Candidate/chưa có callback/evidence không tồn tại."""
    assert pool is not None
    try:
        evidence = await detect.read_evidence(
            pool, candidate_id, path_column="oob_evidence_path"
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if evidence is None:
        raise HTTPException(status_code=404, detail="oob evidence không tồn tại")
    return evidence


@app.post("/candidates/{candidate_id}/verify-takeover")
async def verify_candidate_takeover(candidate_id: int) -> dict:
    """Chạy trọn vòng xác minh subdomain takeover (ticket #14): fingerprint
    probe qua sandbox → soạn PoC page chứa username định danh + token → deploy
    qua hosting khả dụng (TAKEOVER_HOSTING; chưa cấu hình → needs_manual kèm
    hướng dẫn) → confirm probe: PoC được phục vụ QUA SUBDOMAIN → verified.
    Fingerprint match nhưng không kiểm soát được → rejected (report thiếu PoC
    hoạt động bị đóng N/A). Endpoint chỉ dành cho Candidate class 'takeover'."""
    assert pool is not None
    candidate = await detect.get_candidate(pool, candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail="candidate không tồn tại")
    if candidate["class"] != "takeover":
        raise HTTPException(
            status_code=422,
            detail=f"candidate thuộc class '{candidate['class']}' — vòng verify này dành cho class 'takeover'",
        )
    try:
        result = await takeover.run_takeover_verification(pool, candidate)
    except verify.ProbeBlocked as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    updated = await detect.get_candidate(pool, candidate_id)
    return {"candidate": updated, "verify": result}


@app.post("/candidates/{candidate_id}/verify-http")
async def verify_candidate_http(candidate_id: int, req: VerifyCandidateRequest | None = None) -> dict:
    """Chạy trọn vòng xác minh batch A (ticket #15) cho 7 lớp HTTP-only: cors,
    dirlist, graphql, crlf, ssti, headers, disclosure — confirm tool output +
    baseline diff qua sandbox → confidence ≥ ngưỡng → verified kèm evidence,
    dưới ngưỡng → rejected. Class 'headers' chỉ informational: chỉ thu evidence
    + ép severity thấp, KHÔNG đổi status (không tự tạo report)."""
    assert pool is not None
    candidate = await detect.get_candidate(pool, candidate_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail="candidate không tồn tại")
    if candidate["class"] not in httpverify.HTTP_VERIFY_CLASSES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"candidate thuộc class '{candidate['class']}' — vòng verify HTTP "
                f"dành cho class {', '.join(httpverify.HTTP_VERIFY_CLASSES)}"
            ),
        )
    try:
        result = await httpverify.run_http_verification(
            pool, candidate, payload=(req.payload if req else None)
        )
    except httpverify.ProbeBlocked as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    updated = await detect.get_candidate(pool, candidate_id)
    return {"candidate": updated, "verify": result}


# ─────────────── Report theo mẫu platform (ticket #18) ───────────────


class ReportDraftRequest(BaseModel):
    platform: str
    sections: dict[str, str]  # markdown trọn bản do worker compose khi lưu


class MarkReportedRequest(BaseModel):
    report_url: str | None = None   # link report trên platform sau khi nộp tay
    report_notes: str | None = None  # ghi chú tự do (ngày nộp, kết quả...)


@app.get("/candidates/{candidate_id}/report")
async def get_candidate_report(
    candidate_id: int,
    platform: str | None = None,  # trống → platform của Program
    refresh: bool = False,        # true → sinh lại từ evidence bỏ bản nháp
) -> dict:
    """Draft report của Finding (verified) theo mẫu platform — HackerOne
    (## Summary / Steps to Reproduce / Impact / Supporting Material) hoặc
    Intigriti (### Description / Steps to Reproduce / Impact / Proof of
    Concept). Sinh THUẦN từ evidence đã có; ưu tiên bản nháp user đã lưu.
    Endpoint chỉ ĐỌC + LƯU NHÁP — không có đường nào POST report lên platform
    (auto-submit là v2, phải hỏi user + quyền API write)."""
    assert pool is not None
    try:
        result = await report.get_report(pool, candidate_id, platform, refresh)
    except report.ReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="candidate không tồn tại")
    return result


@app.put("/candidates/{candidate_id}/report")
async def save_candidate_report(candidate_id: int, req: ReportDraftRequest) -> dict:
    """Lưu nháp nội dung report đã sửa trên Preview (lưu trễ trong DB theo
    platform — không gửi đi đâu cả)."""
    assert pool is not None
    try:
        result = await report.save_report_draft(
            pool, candidate_id, req.platform, req.sections, req.markdown
        )
    except report.ReportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="candidate không tồn tại")
    return {"candidate": result}


@app.post("/candidates/{candidate_id}/reported")
async def mark_candidate_reported(candidate_id: int, req: MarkReportedRequest) -> dict:
    """User đã TỰ nộp report trên platform → đánh dấu Finding `reported` +
    link + ngày nộp (now()) + ghi chú tự do. Chỉ từ trạng thái verified
    (hoặc cập nhật tiếp trên reported). KHÔNG gửi gì đi platform ở đây."""
    assert pool is not None
    try:
        result = await report.mark_reported(
            pool, candidate_id, req.report_url, req.report_notes
        )
    except report.ReportError as exc:
        # nhất quán với GET/PUT report: sai điều kiện đầu vào/lifecycle → 422
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="candidate không tồn tại")
    return {"candidate": result}


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


# ─────────────── Sandbox bridge: verify session + egress (ticket #11) ───────────────


@app.get("/sandbox/sessions")
async def list_sandbox_sessions(
    run_id: int | None = None,
    status: str | None = None,
    limit: int = Query(50, ge=1, le=500),
) -> dict:
    """Verify session sandbox gần nhất — filter theo Run/status; mỗi session
    = 1 container ephemeral (docker ps truy được qua container_name)."""
    assert pool is not None
    return {"items": await sandbox.list_sessions(pool, run_id, status, limit)}


@app.get("/sandbox/sessions/{session_id}")
async def get_sandbox_session(session_id: int) -> dict:
    """Chi tiết verify session: script + stdout/stderr đầy đủ + egress log
    (mọi destination mỗi request ra ngoài, kể cả request bị chặn)."""
    assert pool is not None
    session = await sandbox.get_session(pool, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="verify session không tồn tại")
    return session


# ───────────────────────────────── audit log ─────────────────────────────────


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
