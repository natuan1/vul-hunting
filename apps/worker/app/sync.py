"""Sync platform (HackerOne / Intigriti) → Postgres với progress + resume.

Chạy trong background task; tiến độ lưu bảng sync_state để UI poll.
Resume: khi sync lỗi (hoặc worker restart giữa chừng), lần gọi POST kế tiếp
tiếp tục từ program sau `last_ref` — phần đã sync được bỏ qua (upsert idempotent).
"""

import asyncio
import logging

import asyncpg

from . import h1_client, intigriti_client

log = logging.getLogger("sync")

PLATFORMS = {
    "hackerone": {"name": "HackerOne", "client": h1_client},
    "intigriti": {"name": "Intigriti", "client": intigriti_client},
}
CLAIM_STALE = "15 minutes"

_running: set[str] = set()  # guard trong process; cross-restart dùng claim hết hạn trong DB

_UPSERT_PROGRAM = """
INSERT INTO programs (platform_id, handle, name, currency, policy, submission_state,
                      state, offers_bounties, min_bounty, max_bounty,
                      open_scope, triage_active, started_accepting_at, synced_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
ON CONFLICT (platform_id, handle) DO UPDATE SET
    name = EXCLUDED.name, currency = EXCLUDED.currency, policy = EXCLUDED.policy,
    submission_state = EXCLUDED.submission_state, state = EXCLUDED.state,
    offers_bounties = EXCLUDED.offers_bounties,
    min_bounty = EXCLUDED.min_bounty, max_bounty = EXCLUDED.max_bounty,
    open_scope = EXCLUDED.open_scope, triage_active = EXCLUDED.triage_active,
    started_accepting_at = EXCLUDED.started_accepting_at, synced_at = now()
RETURNING id
"""

_UPSERT_ASSET = """
INSERT INTO assets (program_id, asset_identifier, asset_type, eligible_for_bounty,
                    eligible_for_submission, tier, max_severity, instruction)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (program_id, asset_identifier, asset_type) DO UPDATE SET
    eligible_for_bounty = EXCLUDED.eligible_for_bounty,
    eligible_for_submission = EXCLUDED.eligible_for_submission,
    tier = EXCLUDED.tier,
    max_severity = EXCLUDED.max_severity, instruction = EXCLUDED.instruction
RETURNING id
"""


async def recover_on_startup(pool: asyncpg.Pool) -> None:
    """Worker restart giữa chừng → đánh dấu các sync 'running' là lỗi (resume được)."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "UPDATE sync_state SET status = 'error', "
            "error = 'worker restart giữa chừng — sync lại để resume từ điểm dừng', "
            "updated_at = now() WHERE status = 'running' RETURNING platform_slug"
        )
    for row in rows:
        log.warning("sync %s bị gián đoạn do worker restart", row["platform_slug"])


async def _state_row(pool: asyncpg.Pool, slug: str) -> asyncpg.Record | None:
    async with pool.acquire() as conn:
        return await conn.fetchrow(
            "SELECT * FROM sync_state WHERE platform_slug = $1 "
            "ORDER BY started_at DESC, id DESC LIMIT 1",
            slug,
        )


async def _claim(pool: asyncpg.Pool, slug: str) -> asyncpg.Record | None:
    """Tạo row 'running' nếu không có claim sống; trả row mới hoặc None."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            stale = await conn.fetchval(
                "SELECT 1 FROM sync_state WHERE platform_slug = $1 "
                f"AND status = 'running' AND updated_at > now() - interval '{CLAIM_STALE}'",
                slug,
            )
            if stale:
                return None
            return await conn.fetchrow(
                "INSERT INTO sync_state (platform_slug, status) "
                "VALUES ($1, 'running') RETURNING *",
                slug,
            )


async def start_sync(pool: asyncpg.Pool, slug: str) -> dict:
    if slug not in PLATFORMS:
        return {"status": "unknown_platform"}
    if slug in _running:
        return {"status": "already_running", "state": dict(await _state_row(pool, slug) or {})}
    state = await _claim(pool, slug)
    if state is None:
        return {"status": "already_running", "state": dict(await _state_row(pool, slug) or {})}
    _running.add(slug)
    asyncio.create_task(_run(pool, slug, dict(state)))
    return {"status": "started", "state": dict(state)}


async def sync_status(pool: asyncpg.Pool, slug: str) -> dict:
    row = await _state_row(pool, slug)
    if row is None:
        return {"status": "never_synced"}
    return dict(row)


async def _update(pool: asyncpg.Pool, state_id: int, **fields) -> None:
    sets = ", ".join(f"{k} = ${i + 2}" for i, k in enumerate(fields))
    values = list(fields.values())
    async with pool.acquire() as conn:
        await conn.execute(
            f"UPDATE sync_state SET updated_at = now(), {sets} WHERE id = $1",
            state_id,
            *values,
        )


async def _run(pool: asyncpg.Pool, slug: str, state: dict) -> None:
    client = PLATFORMS[slug]["client"]
    platform_name = PLATFORMS[slug]["name"]
    state_id = state["id"]
    last_ref: str | None = state.get("last_handle")
    resume = state.get("status") == "error" and bool(last_ref)
    programs_done = 0
    scopes_done = 0
    try:
        async with pool.acquire() as conn:
            platform_id = await conn.fetchval(
                "INSERT INTO platforms (slug, name) VALUES ($1, $2) "
                "ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name "
                "RETURNING id",
                slug,
                platform_name,
            )

        refs: list[str] = []
        ref_to_handle: dict[str, str] = {}
        async for prog in client.programs():
            ref = prog["ref"]
            refs.append(ref)
            ref_to_handle[ref] = prog["handle"]
            await _update(pool, state_id, last_handle=ref)  # progress phase 1
            async with pool.acquire() as conn:
                await conn.fetchval(
                    _UPSERT_PROGRAM,
                    platform_id,
                    prog["handle"],
                    prog["name"],
                    prog["currency"],
                    prog["policy"],
                    prog["submission_state"],
                    prog["state"],
                    prog["offers_bounties"],
                    prog["min_bounty"],
                    prog["max_bounty"],
                    prog["open_scope"],
                    prog["triage_active"],
                    prog["started_accepting_at"],
                )

        if resume:
            # bỏ qua các program đã sync xong ở lần lỗi trước (đi đúng sau last_ref)
            idx = refs.index(last_ref) + 1 if last_ref in refs else 0
            refs = refs[idx:]
            log.info("[%s] resume sau %s — còn %d program", slug, last_ref, len(refs))

        await _update(
            pool,
            state_id,
            programs_total=len(refs),
            programs_done=0,
            scopes_done=0,
            error=None,
        )

        for ref in refs:
            handle = ref_to_handle.get(ref)
            if not handle:
                continue
            async with pool.acquire() as conn:
                program_id = await conn.fetchval(
                    "SELECT id FROM programs WHERE platform_id = $1 AND handle = $2",
                    platform_id,
                    handle,
                )
            if program_id is None:
                continue
            kept_ids: list[int] = []
            async for asset in client.scopes(ref):
                async with pool.acquire() as conn:
                    asset_id = await conn.fetchval(
                        _UPSERT_ASSET,
                        program_id,
                        asset["identifier"],
                        asset["type"],
                        asset["eligible_for_bounty"],
                        asset["eligible_for_submission"],
                        asset["tier"],
                        asset["max_severity"],
                        asset["instruction"],
                    )
                kept_ids.append(asset_id)
                scopes_done += 1
            # asset bị gỡ khỏi scope trên platform → xoá cho DB khớp thực tế
            async with pool.acquire() as conn:
                if kept_ids:
                    await conn.execute(
                        "DELETE FROM assets WHERE program_id = $1 "
                        "AND NOT (id = ANY($2::int[]))",
                        program_id,
                        kept_ids,
                    )
                else:
                    await conn.execute(
                        "DELETE FROM assets WHERE program_id = $1", program_id
                    )
            programs_done += 1
            await _update(
                pool,
                state_id,
                programs_done=programs_done,
                scopes_done=scopes_done,
                last_handle=ref,
            )

        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE sync_state SET status = 'done', updated_at = now(), "
                "finished_at = now() WHERE id = $1",
                state_id,
            )
        log.info("[%s] sync xong: %d program, %d scope", slug, programs_done, scopes_done)
    except Exception as exc:  # noqa: BLE001 — ghi trạng thái lỗi để resume
        log.error("[%s] sync lỗi: %s", slug, exc)
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE sync_state SET status = 'error', error = $2, "
                    "last_handle = COALESCE($3, last_handle), updated_at = now() "
                    "WHERE id = $1",
                    state_id,
                    str(exc)[:500],
                    last_ref,
                )
        except Exception:  # noqa: BLE001
            log.exception("không ghi được sync_state lỗi")
    finally:
        _running.discard(slug)
