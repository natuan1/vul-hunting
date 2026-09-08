"""Guardrails (ticket #19) — phân loại lỗi TRƯỚC, phản ứng SAU.

Bài học từ notebook: retry-generic là con đường nhanh nhất tới IP ban. Cùng
một tín hiệu "tool bị chặn" phải có phản ứng KHÁC NHAU tuỳ loại:

- rate limit (429 / "too many requests") → backoff luỹ thừa x2, trần 1 giờ;
- ban signal (CAPTCHA, chuỗi 401/403 liên tiếp) → **HALT toàn bộ Run** —
  không auto-resume, chỉ người bấm Resume mới chạy lại;
- auth error → nhắc refresh credential + retry (tối đa 3);
- timeout → kéo dài timeout x2 + giảm parallelism toàn cục;
- scope violation → asset vào blacklist (chặn cả các Run sau).

Bảng pattern phân loại + toàn bộ strategy nằm ĐÚNG Ở ĐÂY — `execute_tool`
(tools.py) là cửa ắt MỌI Tool Execution đi qua, gọi classify → react. Module
này KHÔNG import tools (tránh vòng): ToolResult đọc duck-typing 3 trường
exit_code/stdout/stderr; add_log import lười trong hàm.

Trạng thái guard theo Run nằm trong bộ nhớ worker (`_guards`) — mất khi
restart chỉ means backoff/streak bắt đầu lại từ đầu, an toàn (hướng bảo vệ).
"""

import asyncio
import logging
import re
from enum import Enum

import asyncpg

from . import jobqueue
from .config import settings

log = logging.getLogger("guardrails")


class ErrorKind(str, Enum):
    """Loại tín hiệu lỗi nhận diện được từ kết quả Tool Execution."""

    NONE = "none"
    RATE_LIMIT = "rate_limit"
    BAN_SIGNAL = "ban_signal"
    AUTH_ERROR = "auth_error"
    TIMEOUT = "timeout"


class RunHalted(Exception):
    """Guardrail HALT Run (ban signal) — jobqueue KHÔNG được retry job này,
    người dùng phải bấm Resume. execute_run bắt riêng để job kết thúc bình
    thường (status đã là 'halted' trong DB)."""


# ── bảng phân loại: pattern (lowercase) → ErrorKind ──
# Dương tính giả cố ý hướng AN TOÀN: ban nhầm thì dừng Run sớm (tệ nhất là
# phiền), lọt ban signal thì ăn ban IP thật.
_BAN_PATTERNS = (
    "captcha",
    "cf-challenge",
    "cf_challenge",
    "just a moment",
    "attention required",
    "banned",
    "blocked by waf",
    "access denied by",
)
_RATE_LIMIT_TEXT = ("too many requests", "rate limit", "rate-limited", "ratelimit")
_AUTH_TEXT = ("unauthorized", "forbidden", "access denied")
# mã HTTP soi theo ranh giới từ — "1403"/"4029" không phải mã 403/429
_CODE_429 = re.compile(r"\b429\b")
_CODE_40X = re.compile(r"\b40[13]\b")


def classify(result) -> ErrorKind:
    """ToolResult (duck-typing exit_code/stdout/stderr) → ErrorKind.

    Thứ tự: ban (kể cả exit 0 — WAF trả trang CAPTCHA mà tool "thành công"
    vẫn là bị cấm) → timeout (exit 124, quy ước của DockerToolRunner) → với
    exit KHÁC 0 mới soi rate limit/auth (exit 0 với "429" trong stdout là DỮ
    LIỆU quét, không phải tool bị giới hạn).
    """
    text = f"{result.stderr}\n{result.stdout}".lower()
    if any(p in text for p in _BAN_PATTERNS):
        return ErrorKind.BAN_SIGNAL
    if result.exit_code == 124:
        return ErrorKind.TIMEOUT
    if result.exit_code == 0:
        return ErrorKind.NONE
    if any(p in text for p in _RATE_LIMIT_TEXT) or _CODE_429.search(text):
        return ErrorKind.RATE_LIMIT
    if any(p in text for p in _AUTH_TEXT) or _CODE_40X.search(text):
        return ErrorKind.AUTH_ERROR
    return ErrorKind.NONE


class RunGuard:
    """Trạng thái phản ứng của MỘT Run: mức backoff, chuỗi 40x, timeout học được.

    Các phương thức note_* là thuần (không IO) — seam test chính của ticket.
    """

    def __init__(
        self,
        run_id: int,
        *,
        base_s: float | None = None,
        cap_s: float | None = None,
        ban_threshold: int | None = None,
        auth_max: int | None = None,
        rate_max: int | None = None,
        timeout_max_s: float | None = None,
        timeout_max_retries: int | None = None,
    ):
        self.run_id = run_id
        self.base_s = settings.guardrail_backoff_base_s if base_s is None else base_s
        self.cap_s = settings.guardrail_backoff_cap_s if cap_s is None else cap_s
        self.ban_threshold = (
            settings.guardrail_ban_consecutive if ban_threshold is None else ban_threshold
        )
        self.auth_max = settings.guardrail_auth_max_retries if auth_max is None else auth_max
        self.rate_max = (
            settings.guardrail_rate_limit_max_retries if rate_max is None else rate_max
        )
        self.timeout_max_s = (
            settings.guardrail_timeout_max_s if timeout_max_s is None else timeout_max_s
        )
        self.timeout_max_retries = (
            settings.guardrail_timeout_max_retries
            if timeout_max_retries is None
            else timeout_max_retries
        )
        self.rate_stage = 0  # vừa là mức backoff vừa là số lượt retry đã dùng
        self.auth_streak = 0
        self.auth_retries_used = 0
        self.timeout_retries_used = 0
        self.timeout_s = settings.tool_timeout_s

    def note_rate_limit(self) -> float:
        """Ghi nhận 1 lần bị rate limit → delay cho lần thử lại (x2, trần cap)."""
        delay = min(self.base_s * 2**self.rate_stage, self.cap_s)
        self.rate_stage += 1
        return delay

    def rate_retry_left(self) -> bool:
        """Còn lượt backoff cho rate limit (chống loop vô hạn)."""
        return self.rate_stage < self.rate_max

    def note_auth_like(self) -> int:
        """Ghi nhận 1 kết quả 401/403 → độ dài chuỗi liên tiếp hiện tại."""
        self.auth_streak += 1
        return self.auth_streak

    def ban_triggered(self) -> bool:
        """Chuỗi 401/403 đã đủ dài để coi là tín hiệu bị cấm."""
        return self.auth_streak >= self.ban_threshold

    def auth_retry_left(self) -> bool:
        """Còn lượt retry auth (tối đa guardrail_auth_max_retries)."""
        return self.auth_retries_used < self.auth_max

    def note_auth_retry(self) -> None:
        self.auth_retries_used += 1

    def note_timeout(self) -> float:
        """Kéo dài timeout x2 (chặn trần) — trả timeout mới."""
        self.timeout_s = min(self.timeout_s * 2, self.timeout_max_s)
        self.timeout_retries_used += 1
        return self.timeout_s

    def timeout_retry_left(self) -> bool:
        """Còn lượt retry sau khi kéo dài timeout."""
        return self.timeout_retries_used < self.timeout_max_retries

    def note_clean(self) -> None:
        """Kết quả sạch — chuỗi 40x đứt, backoff về mốc đầu (timeout học được
        thì GIỮ: tool vẫn cần thời gian đó ở lần sau)."""
        self.rate_stage = 0
        self.auth_streak = 0
        self.auth_retries_used = 0
        self.timeout_retries_used = 0


class DynamicCap:
    """Cap Tool Execution đồng thời — như Semaphore nhưng `limit` hạ được lúc
    chạy (strategy timeout: giảm parallelism). `max_active` để test/metrics
    chứng minh không bao giờ vượt."""

    def __init__(self, limit: int):
        self.limit = limit
        self._active = 0
        self.max_active = 0
        self._cond = asyncio.Condition()

    async def acquire(self) -> None:
        """Chờ tới khi còn chỗ trong trần rồi chiếm 1 slot."""
        async with self._cond:
            await self._cond.wait_for(lambda: self._active < self.limit)
            self._active += 1
            self.max_active = max(self.max_active, self._active)

    async def release(self) -> None:
        """Trả lại 1 slot và đánh thức người đang chờ."""
        async with self._cond:
            self._active -= 1
            self._cond.notify_all()

    def reduce(self) -> int:
        """Hạ trần 1 đơn vị (sàn 1) — strategy timeout."""
        self.limit = max(1, self.limit - 1)
        return self.limit

    def stats(self) -> dict:
        """Ảnh chụp chỉ số cho /healthz — bằng chứng không vượt trần."""
        return {
            "cap": self.limit,
            "active": self._active,
            "max_active": self.max_active,
        }


# cap toàn cục của worker — mọi execute_tool chờ qua đây trước khi launch
CAP = DynamicCap(settings.guardrail_max_concurrent)

# trạng thái guard per-Run (bộ nhớ worker — restart thì bắt đầu lại, an toàn)
_guards: dict[int, RunGuard] = {}


def for_run(run_id: int) -> RunGuard:
    """Guard của Run (tạo mới nếu chưa có) — MỌI phản ứng đều qua trạng thái này."""
    if run_id not in _guards:
        _guards[run_id] = RunGuard(run_id)
    return _guards[run_id]


def reset_run(run_id: int) -> None:
    """Xoá trạng thái guard (Run resume/hết) — lần sau bắt đầu sạch sẽ."""
    _guards.pop(run_id, None)


def runs_guarded() -> int:
    """Số Run đang có trạng thái guard trong process (cho /healthz)."""
    return len(_guards)


async def _log(pool: asyncpg.Pool, run_id: int, message: str, level: str = "warn") -> None:
    from .tools import add_log  # import lười — tránh vòng (tools import module này)

    await add_log(pool, run_id, message, level=level)


async def react(pool: asyncpg.Pool, run_id: int, tool: str, kind: ErrorKind, guard: RunGuard) -> bool:
    """Áp strategy cho tín hiệu đã phân loại. Trả True = chạy lại tool ngay
    (đã ngủ backoff nếu cần); False = ghi nhận và dùng kết quả này; raise
    RunHalted = Run bị HALT (không auto-resume)."""
    if kind is ErrorKind.BAN_SIGNAL:
        reason = (
            f"ban signal từ '{tool}': WAF/CAPTCHA phát hiện — dừng toàn bộ Run "
            f"để bảo vệ IP. Xử lý xong hãy bấm Resume."
        )
        await halt_run(pool, run_id, reason)
        raise RunHalted(reason)

    if kind is ErrorKind.RATE_LIMIT:
        if not guard.rate_retry_left():
            await _log(
                pool,
                run_id,
                f"GUARDRAIL: '{tool}' vẫn bị rate limit sau {guard.rate_max} lần backoff — "
                f"ghi nhận kết quả và tiếp tục",
                level="error",
            )
            return False
        delay = guard.note_rate_limit()
        await _log(
            pool,
            run_id,
            f"GUARDRAIL: '{tool}' bị rate limit — backoff {delay:.0f}s "
            f"(x2, trần {guard.cap_s:.0f}s) rồi thử lại",
        )
        await asyncio.sleep(delay)
        return True

    if kind is ErrorKind.AUTH_ERROR:
        streak = guard.note_auth_like()
        if guard.ban_triggered():
            reason = (
                f"chuỗi {streak} lần 401/403 liên tiếp (lần này từ '{tool}') — "
                f"tín hiệu bị chặn, dừng toàn bộ Run để bảo vệ IP."
            )
            await halt_run(pool, run_id, reason)
            raise RunHalted(reason)
        if guard.auth_retry_left():
            guard.note_auth_retry()
            await _log(
                pool,
                run_id,
                f"GUARDRAIL: '{tool}' lỗi auth (401/403, chuỗi {streak}) — cần refresh "
                f"credential/header định danh; thử lại "
                f"{guard.auth_retries_used}/{guard.auth_max}",
            )
            return True
        await _log(
            pool,
            run_id,
            f"GUARDRAIL: '{tool}' hết lượt retry auth ({guard.auth_max}) — bỏ qua kết quả này",
            level="error",
        )
        return False

    if kind is ErrorKind.TIMEOUT:
        if not guard.timeout_retry_left():
            return False
        guard.note_timeout()
        new_cap = CAP.reduce()  # giảm parallelism toàn cục
        await _log(
            pool,
            run_id,
            f"GUARDRAIL: '{tool}' quá hạn — kéo dài timeout lên {guard.timeout_s:.0f}s, "
            f"giảm parallelism xuống {new_cap} Tool Execution đồng thời",
        )
        return True

    return False


async def halt_run(pool: asyncpg.Pool, run_id: int, reason: str) -> bool:
    """Run → 'halted' (đỏ trên UI) + log lỗi. Trả False nếu Run không đang chạy.

    finished_at không đặt — Run chưa xong, đang bị NGHỈ để chờ người xử lý;
    resume sẽ xếp hàng lại như Run mới."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "UPDATE runs SET status = 'halted', error = $2 "
            "WHERE id = $1 AND status = 'running' RETURNING id",
            run_id,
            reason[:500],
        )
    if row is None:
        return False
    log.warning("run %d bị HALT: %s", run_id, reason)
    await _log(pool, run_id, f"⛔ GUARDRAIL HALT: {reason}", level="error")
    return True


async def resume_run(pool: asyncpg.Pool, run_id: int) -> bool:
    """Người dùng bấm Resume — đây là lối thoát DUY NHẤT khỏi 'halted'
    (không có auto-resume nào khác). Xếp hàng job mới + reset guard state."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                "UPDATE runs SET status = 'pending', error = NULL, finished_at = NULL "
                "WHERE id = $1 AND status = 'halted' RETURNING id",
                run_id,
            )
            if row is None:
                return False
            await jobqueue.enqueue(conn, run_id)
    reset_run(run_id)
    log.info("run %d được resume bởi người dùng", run_id)
    return True


# ── scope violation: blacklist asset (chặn cả các Run sau) ──


async def blacklist_asset(
    pool: asyncpg.Pool, program_id: int, asset_identifier: str, reason: str
) -> None:
    """Đưa asset (chuỗi identifier chuẩn hoá về host) vào blacklist của Program —
    idempotent (ON CONFLICT bỏ qua)."""
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO asset_blacklist (program_id, host, reason) "
            "VALUES ($1, $2, $3) ON CONFLICT (program_id, host) DO NOTHING",
            program_id,
            asset_identifier,
            reason[:500],
        )


async def is_blacklisted(pool: asyncpg.Pool, program_id: int | None, asset_identifier: str) -> bool:
    """Asset đã nằm trong blacklist của Program chưa — None program thì không."""
    if program_id is None:
        return False
    async with pool.acquire() as conn:
        return (
            await conn.fetchval(
                "SELECT 1 FROM asset_blacklist WHERE program_id = $1 AND host = $2",
                program_id,
                asset_identifier,
            )
            is not None
        )
