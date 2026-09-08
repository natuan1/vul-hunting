"""Guardrails (ticket #19) — phân loại lỗi TRƯỚC, phản ứng SAU.

Bài học từ notebook: retry-generic là con đường nhanh nhất tới IP ban. Bảng
phân loại + response strategy phải nằm ở MỘT module duy nhất mà mọi Tool
Execution đi qua (`execute_tool` là cửa ắt).

Seam test:
- `classify()` thuần: ToolResult → ErrorKind theo bảng pattern;
- `RunGuard` thuần: backoff x2 trần 1h, chuỗi 401/403, timeout kéo dài;
- `DynamicCap` thuần: cap concurrency điều chỉnh được lúc chạy;
- `react()`/`halt_run`/`resume_run`: DB giả — halt KHÔNG tự resume;
- `execute_tool`: integration — cửa ắt classify → react → retry/halt;
- `ToolContext.validate`: scope violation → blacklist asset.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_guardrails.py -q
"""

import asyncio
from types import SimpleNamespace

import pytest

from app import config, guardrails
from app.guardrails import (
    DynamicCap,
    ErrorKind,
    RunGuard,
    RunHalted,
    classify,
)


def R(exit_code=0, stdout="", stderr=""):
    """ToolResult giả — classify chỉ đọc 3 trường này (duck typing)."""
    return SimpleNamespace(exit_code=exit_code, stdout=stdout, stderr=stderr)


@pytest.fixture(autouse=True)
def _iso(tmp_path, monkeypatch):
    """Mỗi test có registry + cap RIÊNG (không đụng state toàn cục) + artifact ghi tmp."""
    monkeypatch.setattr(config.settings, "artifacts_dir", str(tmp_path / "artifacts"))
    guardrails._guards.clear()
    monkeypatch.setattr(guardrails, "CAP", DynamicCap(config.settings.guardrail_max_concurrent))


class GuardFakePool:
    """Pool giả: ghi lại mọi SQL (đã gọn whitespace) + script fetchrow/fetchval
    theo mẩu SQL (match đầu tiên thắng; không match → fetchval trả id tăng dần
    cho các INSERT … RETURNING, fetchrow trả None)."""

    def __init__(self, fetchrow_script=None, fetchval_script=None):
        self.executed = []
        self.fetchrow_script = fetchrow_script or []
        self.fetchval_script = fetchval_script or []
        self._ids = iter(range(100, 10000))

    def acquire(self):
        return self

    def transaction(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    @staticmethod
    def _flat(sql):
        return " ".join(sql.split())

    async def execute(self, sql, *params):
        self.executed.append((self._flat(sql), params))

    async def fetchval(self, sql, *params):
        flat = self._flat(sql)
        self.executed.append((flat, params))
        for needle, value in self.fetchval_script:
            if needle in flat:
                return value
        return next(self._ids)

    async def fetchrow(self, sql, *params):
        flat = self._flat(sql)
        self.executed.append((flat, params))
        for needle, value in self.fetchrow_script:
            if needle in flat:
                return value
        return None

    async def fetch(self, sql, *params):
        return []


class FakeRunner:
    """Runner giả trả sẵn danh sách kết quả — lần gọi thứ n nhận phần tử n."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls = 0

    async def __call__(self, tool, args, stdin=None, docker_args=None):
        self.calls += 1
        return self.results.pop(0)


def _messages(pool):
    """Nội dung các dòng run_logs đã INSERT qua pool giả (params: run, level, msg)."""
    return [p[2] for sql, p in pool.executed if "INSERT INTO run_logs" in sql]


def _log_levels(pool):
    return [p[1] for sql, p in pool.executed if "INSERT INTO run_logs" in sql]


async def _no_sleep(monkeypatch):
    slept = []

    async def fake_sleep(delay):
        slept.append(delay)

    monkeypatch.setattr(guardrails.asyncio, "sleep", fake_sleep)
    return slept


# ── bảng phân loại lỗi (thuần) ──


def test_429_trong_stderr_là_rate_limit():
    assert classify(R(1, stderr="httpx: HTTP 429 Too Many Requests")) is ErrorKind.RATE_LIMIT


def test_too_many_requests_không_cần_mã_số_vẫn_rate_limit():
    assert classify(R(1, stderr="error: too many requests, slow down")) is ErrorKind.RATE_LIMIT


def test_exit_0_có_429_trong_stdout_là_dữ_liệu_không_phải_lỗi():
    # nuclei exit 0 với dòng "[429] https://…" là KẾT QUẢ quét, không phải tool
    # bị giới hạn — phản ứng với nó là retry vô nghĩa (bài học notebook)
    assert classify(R(0, stdout="[429] https://app.example.com")) is ErrorKind.NONE


def test_exit_124_là_timeout():
    assert classify(R(124, stderr="tool 'nuclei' quá hạn 900s — đã kill container")) is (
        ErrorKind.TIMEOUT
    )


def test_captcha_là_ban_signal_dù_exit_0():
    # WAF trả trang CAPTCHA và tool "chạy thành công" vẫn là bị cấm — ban signal
    # không phụ thuộc exit code
    assert classify(R(0, stdout="<title>Just a moment...</title> cf-challenge")) is (
        ErrorKind.BAN_SIGNAL
    )


def test_captcha_stderr_cũng_là_ban_signal():
    assert classify(R(1, stderr="CAPTCHA required to continue")) is ErrorKind.BAN_SIGNAL


def test_401_và_403_là_auth_error():
    assert classify(R(1, stderr="401 Unauthorized")) is ErrorKind.AUTH_ERROR
    assert classify(R(1, stderr="403 Forbidden")) is ErrorKind.AUTH_ERROR


def test_ban_ưu_tiên_trên_rate_limit():
    assert classify(R(1, stderr="429 too many requests — captcha challenge")) is (
        ErrorKind.BAN_SIGNAL
    )


def test_stderr_sạch_exit_đôi_là_không_có_tín_hiệu():
    assert classify(R(1, stderr="nuclei: no results found")) is ErrorKind.NONE


def test_mã_số_lồng_trong_số_khác_không_phải_tín_hiệu():
    # "1403" không phải mã 403 — phân loại theo ranh giới từ, không substring
    assert classify(R(1, stderr="latency 1403ms, retry 4029")) is ErrorKind.NONE


def test_cấu_hình_mặc_định_guardrails():
    assert config.settings.guardrail_max_concurrent == 4
    assert config.settings.guardrail_backoff_cap_s == 3600  # trần 1 giờ
    assert config.settings.guardrail_auth_max_retries == 3


# ── RunGuard: backoff luỹ thừa + chuỗi 40x + timeout (thuần) ──


def test_backoff_rate_limit_x2_trần_1_giờ():
    guard = RunGuard(7, base_s=30, cap_s=3600, rate_max=99)
    delays = [guard.note_rate_limit() for _ in range(9)]
    assert delays == [30, 60, 120, 240, 480, 960, 1920, 3600, 3600]


def test_kết_quả_sạch_reset_backoff_về_mốc_đầu():
    guard = RunGuard(7, base_s=30, cap_s=3600)
    guard.note_rate_limit()
    guard.note_rate_limit()
    assert guard.note_rate_limit() == 120
    guard.note_clean()
    assert guard.note_rate_limit() == 30


def test_40x_liên_tiếp_đủ_ngưỡng_là_tín_hiệu_ban():
    guard = RunGuard(7, ban_threshold=5)
    for _ in range(4):
        guard.note_auth_like()
    assert not guard.ban_triggered()
    guard.note_auth_like()
    assert guard.ban_triggered()


def test_40x_đứt_bởi_kết_quả_sạch_thì_không_còn_liên_tiếp():
    guard = RunGuard(7, ban_threshold=5)
    for _ in range(4):
        guard.note_auth_like()
    guard.note_clean()
    guard.note_auth_like()
    guard.note_auth_like()
    assert not guard.ban_triggered()


def test_auth_retry_tối_đa_3_lần():
    guard = RunGuard(7, auth_max=3)
    for _ in range(3):
        assert guard.auth_retry_left()
        guard.note_auth_retry()
    assert not guard.auth_retry_left()


def test_timeout_kéo_dài_x2_chặn_trần():
    guard = RunGuard(7, timeout_max_s=3600)
    assert guard.timeout_s == config.settings.tool_timeout_s
    assert guard.note_timeout() == 2 * config.settings.tool_timeout_s
    assert guard.note_timeout() == 3600
    assert guard.note_timeout() == 3600  # không vượt trần


def test_timeout_chỉ_retry_2_lần():
    guard = RunGuard(7, timeout_max_retries=2)
    assert guard.timeout_retry_left()
    guard.note_timeout()
    assert guard.timeout_retry_left()
    guard.note_timeout()
    assert not guard.timeout_retry_left()


def test_for_run_tái_dùng_cùng_guard_cho_cùng_run():
    g1 = guardrails.for_run(7)
    g1.note_rate_limit()
    assert guardrails.for_run(7) is g1
    assert guardrails.for_run(8) is not g1


# ── DynamicCap: concurrency ≤ limit, hạ limit lúc chạy được ──


async def _burn(cap, n, hold=0.01):
    async def one():
        await cap.acquire()
        await asyncio.sleep(hold)
        await cap.release()

    await asyncio.gather(*(one() for _ in range(n)))


@pytest.mark.asyncio
async def test_cap_concurrency_không_vượt_giới_hạn():
    cap = DynamicCap(4)
    await _burn(cap, 10)
    assert cap.max_active == 4  # bão hoà đúng mức trần, không vượt


@pytest.mark.asyncio
async def test_cap_hạ_limit_điều_chỉnh_động():
    cap = DynamicCap(4)
    cap.limit = 1
    await _burn(cap, 5)
    assert cap.max_active == 1


# ── react(): áp strategy — retry có ngủ backoff / halt / cho qua ──


@pytest.mark.asyncio
async def test_react_rate_limit_ngủ_đúng_backoff_và_báo_retry(monkeypatch):
    slept = await _no_sleep(monkeypatch)
    guard = RunGuard(7, base_s=45, cap_s=3600)
    assert await guardrails.react(GuardFakePool(), 7, "httpx", ErrorKind.RATE_LIMIT, guard) is True
    assert slept == [45]


@pytest.mark.asyncio
async def test_react_rate_limit_hết_lượt_thì_không_retry_nữa():
    guard = RunGuard(7, rate_max=1)
    guard.note_rate_limit()  # dùng hết lượt duy nhất
    assert await guardrails.react(GuardFakePool(), 7, "httpx", ErrorKind.RATE_LIMIT, guard) is False


@pytest.mark.asyncio
async def test_react_ban_halts_run_và_raise(monkeypatch):
    await _no_sleep(monkeypatch)  # ban KHÔNG được ngủ/retry — dừng ngay
    pool = GuardFakePool(fetchrow_script=[("UPDATE runs SET status = 'halted'", {"id": 7})])
    with pytest.raises(RunHalted):
        await guardrails.react(pool, 7, "httpx", ErrorKind.BAN_SIGNAL, RunGuard(7))
    assert any("status = 'halted'" in sql for sql, _ in pool.executed)


@pytest.mark.asyncio
async def test_react_403_liên_tiếp_đủ_ngưỡng_cũng_halt():
    pool = GuardFakePool(fetchrow_script=[("UPDATE runs SET status = 'halted'", {"id": 7})])
    guard = RunGuard(7, ban_threshold=3)
    guard.note_auth_like()  # 2 lần 403 trước đó đã nằm trong guard
    guard.note_auth_like()
    with pytest.raises(RunHalted):  # lần thứ 3 (liên tiếp) chạm ngưỡng → HALT
        await guardrails.react(pool, 7, "httpx", ErrorKind.AUTH_ERROR, guard)


@pytest.mark.asyncio
async def test_react_auth_trong_ngưỡng_thì_retry_và_nhắc_refresh_credential():
    pool = GuardFakePool()
    guard = RunGuard(7, ban_threshold=5, auth_max=3)
    assert await guardrails.react(pool, 7, "httpx", ErrorKind.AUTH_ERROR, guard) is True
    assert any("refresh credential" in m for m in _messages(pool))


@pytest.mark.asyncio
async def test_react_timeout_giảm_cap_toàn_cục_và_kéo_dài_timeout():
    guardrails.CAP.limit = 4
    guard = RunGuard(7)
    assert await guardrails.react(GuardFakePool(), 7, "nuclei", ErrorKind.TIMEOUT, guard) is True
    assert guardrails.CAP.limit == 3  # giảm parallelism
    assert guard.timeout_s == 2 * config.settings.tool_timeout_s  # kéo dài timeout


# ── halt_run / resume_run: dừng Run, chỉ người bấm resume mới chạy lại ──


@pytest.mark.asyncio
async def test_halt_run_ghi_trạng_thái_halted_và_log_đỏ():
    pool = GuardFakePool(fetchrow_script=[("UPDATE runs SET status = 'halted'", {"id": 7})])
    assert await guardrails.halt_run(pool, 7, "chuỗi 403 liên tiếp") is True
    assert any("status = 'halted'" in sql for sql, _ in pool.executed)
    assert "error" in _log_levels(pool)


@pytest.mark.asyncio
async def test_halt_run_run_không_tồn_tại_trả_false():
    assert await guardrails.halt_run(GuardFakePool(), 7, "x") is False


@pytest.mark.asyncio
async def test_resume_chuyển_halted_về_pending_xếp_hàng_lại_và_reset_guard():
    pool = GuardFakePool(fetchrow_script=[("UPDATE runs SET status = 'pending'", {"id": 7})])
    guard = guardrails.for_run(7)
    guard.note_rate_limit()
    assert await guardrails.resume_run(pool, 7) is True
    assert any("INSERT INTO jobs" in sql for sql, _ in pool.executed)
    assert guardrails.for_run(7).rate_stage == 0  # guard bắt đầu lại sạch sẽ


@pytest.mark.asyncio
async def test_resume_chỉ_nhận_run_đang_halted():
    # fetchrow không match → UPDATE không trả row (Run không ở trạng thái halted)
    assert await guardrails.resume_run(GuardFakePool(), 7) is False


# ── execute_tool: cửa ắt MỌI Tool Execution đi qua ──


def _ctx():
    from app.tools import ToolContext

    return ToolContext(run_id=7, limiter=None, ident={}, snapshot=[])


@pytest.mark.asyncio
async def test_execute_tool_429_backoff_rồi_thành_công():
    from app import tools

    guard = guardrails.for_run(7)
    guard.base_s = 0.001  # test không ngủ thật
    guard.cap_s = 0.002
    runner = FakeRunner(R(1, stderr="httpx: 429 Too Many Requests"), R(0, "data", ""))
    pool = GuardFakePool()
    result = await tools.execute_tool(pool, _ctx(), "httpx", ["-u", "x"], runner=runner)
    assert result.exit_code == 0
    assert runner.calls == 2  # chạy lại đúng 1 lần sau backoff
    assert any("rate limit" in m for m in _messages(pool))
    updates = [p for sql, p in pool.executed if "UPDATE tool_executions SET status" in sql]
    assert updates[-1][2] == 0  # row tool ghi kết quả CUỐI (exit 0)


@pytest.mark.asyncio
async def test_execute_tool_captcha_halt_toàn_bộ_run():
    from app import tools

    runner = FakeRunner(R(0, "<html>captcha</html>", ""))
    pool = GuardFakePool(fetchrow_script=[("UPDATE runs SET status = 'halted'", {"id": 7})])
    with pytest.raises(RunHalted):
        await tools.execute_tool(pool, _ctx(), "httpx", ["-u", "x"], runner=runner)
    assert runner.calls == 1  # dừng NGAY, không retry
    assert any("status = 'halted'" in sql for sql, _ in pool.executed)


@pytest.mark.asyncio
async def test_execute_tool_kết_quả_sạch_không_phản_ứng_gì():
    from app import tools

    runner = FakeRunner(R(0, "ok", ""))
    pool = GuardFakePool()
    result = await tools.execute_tool(pool, _ctx(), "dnsx", ["x"], runner=runner)
    assert result.exit_code == 0
    assert runner.calls == 1
    assert not any("status = 'halted'" in sql for sql, _ in pool.executed)


@pytest.mark.asyncio
async def test_nhiều_run_được_đời_song_song_không_vượt_cap():
    """AC #19: đãi nhiều Run song song — tổng Tool Execution đồng thời ≤ 4."""
    from app import tools
    from app.tools import ToolContext

    class SlowRunner:
        async def __call__(self, tool, args, stdin=None, docker_args=None):
            await asyncio.sleep(0.03)
            return R(0, "ok", "")

    pool = GuardFakePool()

    async def one_run(rid: int):
        ctx = ToolContext(run_id=rid, limiter=None, ident={}, snapshot=[])
        return await tools.execute_tool(pool, ctx, "httpx", ["-u", "x"], runner=SlowRunner())

    await asyncio.gather(*(one_run(100 + i) for i in range(8)))
    assert guardrails.CAP.max_active <= 4  # không bao giờ vượt cap
    assert guardrails.CAP.max_active == 4  # và bão hoà — cap không vô dụng


# ── job reclaim trên Run 'halted' — KHÔNG được tự chạy lại (auto-resume trộm) ──


@pytest.mark.asyncio
async def test_job_reclaim_trên_run_halted_không_tự_chạy_lại(monkeypatch):
    from app import runner as runner_mod

    pool = GuardFakePool(
        fetchrow_script=[
            (
                "FROM runs r",
                {"id": 18, "program_name": "p", "platform": "hackerone", "platform_name": "H1"},
            )
        ],
        fetchval_script=[("SELECT status FROM runs", "halted")],
    )

    async def _boom(*a, **k):
        raise AssertionError("phase KHÔNG được chạy khi Run đang 'halted'")

    monkeypatch.setattr(runner_mod.recon, "run_recon_phase", _boom)
    monkeypatch.setattr(runner_mod.detect, "run_detection_phase", _boom)
    job = {"id": 1, "run_id": 18, "attempts": 1, "max_attempts": 3}
    await runner_mod.execute_run(pool, job)  # return sớm, không ném, không đổi status
    assert not any("DELETE FROM tool_executions" in sql for sql, _ in pool.executed)
    assert not any("status = 'completed'" in sql for sql, _ in pool.executed)


# ── scope violation: chặn như cũ + blacklist asset (ticket #19) ──


_SNAPSHOT = [{"asset_type": "URL", "asset_identifier": "example.com"}]
_WILDCARD = [{"asset_type": "WILDCARD", "asset_identifier": "*.example.com"}]


def _ctx_scope(snapshot, program_id=5, allow_non_prod=False):
    from app.tools import ToolContext

    return ToolContext(
        run_id=7,
        limiter=None,
        ident={},
        snapshot=snapshot,
        allow_non_prod=allow_non_prod,
        program_id=program_id,
    )


@pytest.mark.asyncio
async def test_validate_ngoài_scope_chặn_như_cũ_và_blacklist_asset():
    from app.tools import TargetBlockedError

    # không có dòng nào trong asset_blacklist
    pool = GuardFakePool(fetchval_script=[("FROM asset_blacklist", None)])
    with pytest.raises(TargetBlockedError):
        await _ctx_scope(_SNAPSHOT).validate(pool, "https://evil.com/x", tool="httpx")
    assert any("INSERT INTO asset_blacklist" in sql for sql, _ in pool.executed)


@pytest.mark.asyncio
async def test_validate_target_đã_blacklist_bị_chặn_trước_khi_lookup_scope():
    from app.tools import TargetBlockedError

    # fetchval SELECT 1 FROM asset_blacklist → có dòng (1)
    pool = GuardFakePool(fetchval_script=[("FROM asset_blacklist", 1)])
    with pytest.raises(TargetBlockedError) as ei:
        await _ctx_scope(_SNAPSHOT).validate(pool, "https://example.com/x", tool="httpx")
    assert "blacklist" in str(ei.value)
    assert any("INSERT INTO scope_audit_log" in sql for sql, _ in pool.executed)


@pytest.mark.asyncio
async def test_validate_non_prod_chặn_không_blacklist_vĩnh_viễn():
    # non-prod có thể được phép ở Run sau (allow_non_prod=True) — blacklist chỉ
    # dành cho target NGOÀI Scope
    from app.tools import TargetBlockedError

    # không có dòng nào trong asset_blacklist
    pool = GuardFakePool(fetchval_script=[("FROM asset_blacklist", None)])
    with pytest.raises(TargetBlockedError):
        await _ctx_scope(_WILDCARD).validate(pool, "https://dev.example.com", tool="httpx")
    assert not any("INSERT INTO asset_blacklist" in sql for sql, _ in pool.executed)
