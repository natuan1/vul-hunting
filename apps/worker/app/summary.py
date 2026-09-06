"""Sinh AI summary + đánh giá khả năng tự động hoá cho Program (ticket #5).

Lazy: chỉ chạy khi UI mở Program Detail mà chưa có cache (hoặc bấm refresh) —
lỗi hermes không chặn việc mở trang, UI chỉ hiển thị trạng thái 'chưa có summary'.
Kết quả cache bảng program_summaries; các lần mở sau đọc thẳng cache.
"""

import asyncio
import logging

import asyncpg

from . import hermes_client

log = logging.getLogger("summary")

MAX_POLICY_CHARS = 15_000
MAX_ASSETS_IN_PROMPT = 200

_GENERATING: set[int] = set()  # guard trong process (1 worker instance, như sync.py)

_UPSERT_READY = """
INSERT INTO program_summaries (program_id, summary, model, status, error, generated_at)
VALUES ($1, $2, $3, 'ready', NULL, now())
ON CONFLICT (program_id) DO UPDATE SET
    summary = EXCLUDED.summary, model = EXCLUDED.model, status = 'ready',
    error = NULL, generated_at = now()
"""

_SET_ERROR = """
INSERT INTO program_summaries (program_id, status, error, generated_at)
VALUES ($1, 'error', $2, now())
ON CONFLICT (program_id) DO UPDATE SET
    status = 'error', error = EXCLUDED.error, generated_at = now()
"""

_SET_GENERATING = """
INSERT INTO program_summaries (program_id, status, generated_at)
VALUES ($1, 'generating', now())
ON CONFLICT (program_id) DO UPDATE SET
    status = 'generating', generated_at = now()
"""


async def recover_on_startup(pool: asyncpg.Pool) -> None:
    """Worker restart giữa chừng → summary kẹt 'generating' chuyển thành lỗi (retry được)."""
    async with pool.acquire() as conn:
        n = await conn.fetchval(
            "UPDATE program_summaries SET status = 'error', "
            "error = 'worker restart giữa chừng — bấm refresh để sinh lại' "
            "WHERE status = 'generating'"
        )
    if n:
        log.warning("%d summary kẹt 'generating' do worker restart", n)


def build_prompt(program: dict, assets: list[dict]) -> str:
    """Prompt tiếng Việt, dùng đúng thuật ngữ trong CONTEXT.md."""
    pl = []

    def money(v: dict) -> str:
        if not v.get("offers_bounties"):
            return "không có bounty"
        parts = []
        if v.get("min_bounty") is not None:
            parts.append(f"tối thiểu {v['min_bounty']}")
        if v.get("max_bounty") is not None:
            parts.append(f"tối đa {v['max_bounty']}")
        cur = f" {v['currency']}" if v.get("currency") else ""
        return "có bounty" + (f" ({', '.join(parts)}{cur})" if parts else "")

    def b(v) -> str:
        return "—" if v is None else ("có" if v else "không")

    pl.append(
        "Bạn là trợ lý bug bounty hunting. Hãy đọc dữ liệu một Program (chương trình "
        "bug bounty) dưới đây và viết tóm tắt phục vụ việc quyết định có nên chạy Run "
        "tự động (recon + kiểm thử) lên Program này hay không.\n"
    )
    pl.append("## Dữ liệu Program\n")
    pl.append(f"- Platform: {program['platform']}")
    pl.append(f"- Program: {program['name']} (handle: {program['handle']})")
    pl.append(f"- Bounty: {money(program)}")
    pl.append(f"- Submission state: {program.get('submission_state') or '—'}")
    pl.append(f"- Scope mở cho submission mới: {b(program.get('open_scope'))}")
    pl.append(f"- Đang triage: {b(program.get('triage_active'))}")
    pl.append(f"- Số Asset trong Scope: {len(assets)}\n")

    pl.append("## Scope (danh sách Asset)\n")
    pl.append("| Asset | Loại | Bounty | Submission | Max severity | Tier | Ghi chú |")
    pl.append("|---|---|---|---|---|---|---|")
    for a in assets[:MAX_ASSETS_IN_PROMPT]:
        note = (a.get("instruction") or "").replace("\n", " ").strip()
        if len(note) > 200:
            note = note[:200] + "…"
        pl.append(
            f"| {a['asset_identifier']} | {a['asset_type']} "
            f"| {b(a['eligible_for_bounty'])} | {b(a['eligible_for_submission'])} "
            f"| {a.get('max_severity') or '—'} | {a.get('tier') or '—'} "
            f"| {note or '—'} |"
        )
    if len(assets) > MAX_ASSETS_IN_PROMPT:
        pl.append(f"(…còn {len(assets) - MAX_ASSETS_IN_PROMPT} Asset nữa, đã lược bớt)")

    policy = (program.get("policy") or "").strip()
    pl.append("\n## Chính sách (policy)\n")
    if policy:
        if len(policy) > MAX_POLICY_CHARS:
            policy = policy[:MAX_POLICY_CHARS] + "\n(…đã cắt bớt do quá dài)"
        pl.append(policy)
    else:
        pl.append("(platform không trả về policy text)")

    pl.append(
        "\n## Yêu cầu\n"
        "Viết bằng tiếng Việt, dùng đúng thuật ngữ: Program, Asset, Scope, Run, "
        "Recon Phase, Detection Phase, Candidate. Trả về duy nhất nội dung markdown "
        "gồm các mục sau:\n\n"
        "### Tóm tắt\n"
        "3–6 gạch đầu dòng: Program này nhắm vào cái gì, phạm vi chính, điểm đáng chú ý.\n\n"
        "### Đánh giá khả năng tự động hoá\n"
        "- **Độ phủ wildcard**: Scope có Asset dạng wildcard (*.domain) không — "
        "con dao hai lưỡi: bề mặt rộng nhưng dễ trúng asset ngoài phạm vi.\n"
        "- **API / bề mặt kỹ thuật**: từ identifier và policy, ước lượng có API host, "
        "ứng dụng web thuần, hay chỉ app store/mobile.\n"
        "- **Chính sách khắt khe**: điểm nào cấm/limit rõ (không auto scan, không "
        "automated tools, chỉ testing trên account riêng, yêu cầu report báo trước…).\n"
        "- **Rate limit policy**: policy có nêu giới hạn request hay yêu cầu tôn trọng "
        "rate limit không.\n"
        "- **Kết luận**: nên / cân nhắc / tránh chạy Run tự động, 1 câu lý do.\n\n"
        "### Lưu ý khi chạy Run\n"
        "2–4 gạch đầu dòng: những gì Recon Phase/Detection Phase phải tránh hoặc "
        "chú ý với Program này. Không suy diễn thông tin không có trong dữ liệu — "
        "thiếu dữ liệu thì ghi rõ 'không có thông tin'."
    )
    return "\n".join(pl)


async def start(pool: asyncpg.Pool, program_id: int) -> dict:
    """Bật generation nền; trả ngay để không chặn UI. Idempotent khi đang chạy."""
    async with pool.acquire() as conn:
        ok = await conn.fetchval("SELECT 1 FROM programs WHERE id = $1", program_id)
    if ok is None:
        return {"status": "not_found"}
    if program_id in _GENERATING:
        return {"status": "generating"}
    # ghi row 'generating' NGAY để UI poll thấy trạng thái (F5 giữa chừng cũng thấy)
    await pool.execute(_SET_GENERATING, program_id)
    _GENERATING.add(program_id)
    asyncio.create_task(_run(pool, program_id))
    return {"status": "started"}


async def _run(pool: asyncpg.Pool, program_id: int) -> None:
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT pr.*, pl.slug AS platform
                FROM programs pr JOIN platforms pl ON pl.id = pr.platform_id
                WHERE pr.id = $1
                """,
                program_id,
            )
            assets = await conn.fetch(
                "SELECT * FROM assets WHERE program_id = $1 "
                "ORDER BY eligible_for_bounty DESC, asset_identifier",
                program_id,
            )
        if row is None:
            return
        program = dict(row)
        if not program.get("policy") and not assets:
            await pool.execute(
                _SET_ERROR, program_id, "chưa có policy và Scope nào — sync lại program"
            )
            return

        result = await hermes_client.chat_completion(build_prompt(program, [dict(a) for a in assets]))
        text = (result.get("text") or "").strip()
        if not text:
            raise hermes_client.HermesError("hermes trả về nội dung rỗng")
        await pool.execute(_UPSERT_READY, program_id, text, result.get("model"))
        log.info("summary program %d xong (model %s)", program_id, result.get("model"))
    except Exception as exc:  # noqa: BLE001 — ghi lỗi vào cache để UI hiển thị + retry
        log.error("summary program %d lỗi: %s", program_id, exc)
        try:
            await pool.execute(_SET_ERROR, program_id, str(exc)[:500])
        except Exception:  # noqa: BLE001
            log.exception("không ghi được lỗi summary")
    finally:
        _GENERATING.discard(program_id)
