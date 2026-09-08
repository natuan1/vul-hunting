"""Orchestration của Run (ticket #6 + #8) — vòng đời: pending → running →
completed/failed, thân Run là Recon Phase (chuỗi subfinder → amass → dnsx →
naabu → httpx, nằm ở recon.py).

Cơ chế kế thừa từ #6/#7: rate limit + header định danh trong Run config,
Scope Validator chặn cứng target ngoài Scope, Tool Execution ghi stdout/
stderr/exit code/thời gian vào DB, lỗi giữa chừng ném lên cho jobqueue
xử lý retry/dead.
"""

import asyncio
import logging

import asyncpg

from . import detect, guardrails, jobqueue, oob, recon
from .tools import add_log, clear_artifacts

log = logging.getLogger("runner")

# nhịp heartbeat: phải nhỏ hơn VISIBILITY_TIMEOUT_S (60s) của jobqueue để job
# chạy dài (recon với tool thật) không bị reclaim gây quét trùng
HEARTBEAT_INTERVAL_S = 20.0


async def _heartbeat_loop(pool: asyncpg.Pool, job_id: int) -> None:
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL_S)
        await jobqueue.heartbeat(pool, job_id)


async def mark_run_failed(pool: asyncpg.Pool, job: asyncpg.Record, error: str) -> None:
    """Job hết lượt thử (dead) → Run chuyển 'failed'."""
    await pool.execute(
        "UPDATE runs SET status = 'failed', error = $2, finished_at = now() WHERE id = $1",
        job["run_id"],
        error[:500],
    )
    # Run chết → đóng registration OOB (hết hạn sạch sẽ, không poll_domain mồ côi)
    await oob.close_run_registrations(pool, job["run_id"])
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
    # attempt mới = bộ Tool Execution mới (log giữ nguyên để còn xem dấu vết retry;
    # recon_assets KHÔNG xoá — upsert gộp sources nên chạy lại chỉ bổ sung)
    await pool.execute("DELETE FROM tool_executions WHERE run_id = $1", run_id)
    clear_artifacts(run_id)

    await add_log(
        pool,
        run_id,
        f"Bắt đầu Run cho Program «{run['program_name']}» "
        f"(platform {run['platform_name']}, lần thử {job['attempts']}/{job['max_attempts']})",
    )

    heartbeat_task = asyncio.create_task(_heartbeat_loop(pool, job["id"]))
    try:
        recon_summary = await recon.run_recon_phase(pool, run)
        # Detection Phase (ticket #10) chạy ngay sau Recon trong cùng Run —
        # recon cho bề mặt (live host + URL đã phân loại class), nuclei chọt
        detection_summary = await detect.run_detection_phase(pool, run)
    except guardrails.RunHalted:
        # Guardrail HALT (ban signal) — status 'halted' đã ghi trong DB bởi
        # halt_run. Job kết thúc BÌNH THƯỜNG (queue KHÔNG retry → không có
        # auto-resume); người dùng bấm Resume mới chạy lại (ticket #19).
        log.warning("run %d bị guardrail HALT — chờ người dùng resume", run_id)
        return
    finally:
        heartbeat_task.cancel()
        await asyncio.gather(heartbeat_task, return_exceptions=True)

    await pool.execute(
        "UPDATE runs SET status = 'completed', finished_at = now() WHERE id = $1",
        run_id,
    )
    # Run xong → deregister interactsh (domain per-Run không tái sử dụng chéo;
    # verify về sau sẽ tự register domain mới nếu cần, vẫn gắn Run cũ)
    closed = await oob.close_run_registrations(pool, run_id)
    await add_log(
        pool,
        run_id,
        f"Run hoàn tất: {recon_summary['subdomains']} subdomain · "
        f"{recon_summary['live_hosts']} live host · "
        f"{recon_summary['urls']} URL ({recon_summary['urls_classed']} có nhãn class) · "
        f"{detection_summary['candidates']} Candidate · "
        f"{recon_summary['blocked'] + detection_summary['blocked']} target bị Scope Validator chặn"
        + (f" · đóng {closed} registration OOB" if closed else ""),
    )
    log.info("run %d hoàn tất", run_id)


HANDLERS = {"run": execute_run}
DEAD_HANDLERS = {"run": mark_run_failed}
RETRY_HANDLERS = {"run": log_run_retry}
