"""Test Sandbox bridge (ticket #11, ADR-0003) — worker quay container --rm MỚI
TINH cho mỗi lần verify, chặn target ngoài Scope TẠI BRIDGE, enforce timeout,
ghi verify session + egress log vào DB.

Chạy trong container worker:
    docker compose exec worker python -m pytest tests/test_sandbox.py -q
"""

import pytest

from app.egress import EgressRegistry, parse_proxy_user, proxy_credentials
from app.sandbox import (
    SandboxResult,
    SandboxSpec,
    build_docker_args,
    clamp_timeout,
    is_docker_env_failure,
    resolve_run,
    run_verify_session,
)

SCOPE = [
    {"asset_identifier": "agilebits.com", "asset_type": "URL"},
    {"asset_identifier": "*.1password.com", "asset_type": "WILDCARD"},
]

RUN = {
    "id": 7,
    "rate_limit_rps": 2.0,
    "ident_header_name": "X-Bug-Bounty",
    "ident_header_value": "HackerOne-tester",
    "scope_snapshot": SCOPE,
    "allow_non_prod": False,
}


class FakeSandboxRunner:
    """Sandbox runner giả: ghi lại spec, trả kết quả định sẵn — không đụng docker."""

    def __init__(self, result: SandboxResult | None = None):
        self.result = result or SandboxResult(0, "payload output", "", False)
        self.specs: list[SandboxSpec] = []

    async def __call__(self, spec: SandboxSpec) -> SandboxResult:
        self.specs.append(spec)
        return self.result


class RecordingPool:
    """Pool giả ghi lại SQL + params để test âm tính (không container, không request)."""

    def __init__(self):
        self.executes: list[tuple[str, tuple]] = []
        self.ids = iter(range(1, 10_000))
        self.fetchrows: list = []  # hàng trả về cho fetchrow (theo thứ tự)
        self.fetch_result: list = []

    def acquire(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, sql, *params):
        self.executes.append((sql, params))

    async def fetchval(self, sql, *params):
        self.executes.append((sql, params))
        return next(self.ids)

    async def fetchrow(self, sql, *params):
        self.executes.append((sql, params))
        return self.fetchrows.pop(0) if self.fetchrows else None

    async def fetch(self, sql, *params):
        self.executes.append((sql, params))
        return self.fetch_result

    def statements(self):
        return [sql for sql, _ in self.executes]


@pytest.fixture()
def registry():
    reg = EgressRegistry()
    yield reg
    reg.clear()


# ── helpers thuần ──


def test_clamp_timeout():
    assert clamp_timeout(None, default=120.0, maximum=600.0) == 120.0
    assert clamp_timeout(5, default=120.0, maximum=600.0) == 5.0
    assert clamp_timeout(9999, default=120.0, maximum=600.0) == 600.0
    assert clamp_timeout(1, default=120.0, maximum=600.0) == 5.0  # sàn 5s


def test_proxy_credentials_roundtrip():
    user, token = proxy_credentials(42, "tok")
    assert user == "sbx-42" and token == "tok"
    assert parse_proxy_user(user) == 42
    assert parse_proxy_user("someone-else") is None
    assert parse_proxy_user("") is None


def test_docker_env_failure_classification():
    """125 + stderr 'docker:' = lỗi môi trường; script exit 127/126 (lệnh lạ
    trong payload) là DỮ LIỆU verify, không đượcraise thành lỗi hạ tầng."""
    assert is_docker_env_failure(125, "docker: Error response from daemon: ...")
    assert not is_docker_env_failure(127, "sh: 1: foo: not found")
    assert not is_docker_env_failure(126, "sh: 1: /x: Permission denied")
    assert not is_docker_env_failure(125, "script tự viết chữ docker nhưng exit 125")
    assert not is_docker_env_failure(0, "")
    assert not is_docker_env_failure(None, "")


def test_build_docker_args():
    spec = SandboxSpec(
        session_id=42,
        container_name="vulhunt-sbx-42",
        network_name="vulhunt-sbx-net-42",
        image="vulhunt-tooling:latest",
        script="echo hi",
        timeout_s=60.0,
        proxy_url="http://sbx-42:tok@sbx-proxy:8765",
        target="agilebits.com",
        ident={"X-Bug-Bounty": "HackerOne-tester"},
    )
    args = build_docker_args(spec)
    # container mới TINH cho mỗi call, tự huỷ khi thoát
    assert "--rm" in args
    assert "--pull" in args and "never" in args
    # name + network riêng cho session — docker ps truy được theo verify session
    assert args[args.index("--name") + 1] == "vulhunt-sbx-42"
    assert args[args.index("--network") + 1] == "vulhunt-sbx-net-42"
    assert args[args.index("--label") + 1] == "vulhunt.sandbox=42"
    # egress proxy qua env (đủ cả biến hoa lẫn thường — curl/python đọc khác nhau)
    envs = [a[2:] for a in args if a.startswith("--env")] + [
        a[2:] for a in args if a.startswith("--env=")
    ]
    joined = " ".join(args)
    assert "HTTP_PROXY=http://sbx-42:tok@sbx-proxy:8765" in joined
    assert "http_proxy=http://sbx-42:tok@sbx-proxy:8765" in joined
    assert "HTTPS_PROXY=http://sbx-42:tok@sbx-proxy:8765" in joined
    assert "SANDBOX_TARGET=agilebits.com" in joined
    assert "SANDBOX_SESSION_ID=42" in joined
    assert "X-Bug-Bounty" in joined  # header định danh truyền vào env cho script
    # script chạy qua sh đọc stdin; image đứng TRƯỚC argv
    assert args[-3:] == ["vulhunt-tooling:latest", "sh", "-s"]


# ── vòng đời verify session ──


@pytest.mark.asyncio
async def test_blocked_out_of_scope_no_container_no_request(registry):
    """Target ngoài Scope → chặn TẠI BRIDGE: không container, không runner call,
    session ghi 'blocked' + scope audit log."""
    pool = RecordingPool()
    runner = FakeSandboxRunner()

    result = await run_verify_session(
        pool, RUN, "curl http://evil.com", "evil.com", runner=runner, registry=registry
    )

    assert result["status"] == "blocked"
    assert result["session_id"] > 0
    assert runner.specs == []  # KHÔNG có container nào được quay
    assert "không thuộc Scope" in result["reason"]
    sqls = " ".join(pool.statements())
    assert "sandbox_sessions" in sqls
    assert "scope_audit_log" in sqls  # audit ghi cả lần bị chặn
    assert registry.resolve(result["session_id"]) is None  # không đăng ký egress ctx


@pytest.mark.asyncio
async def test_allowed_target_runs_ephemeral_container(registry):
    pool = RecordingPool()
    runner = FakeSandboxRunner(SandboxResult(0, "hello from sandbox", "", False))

    result = await run_verify_session(
        pool, RUN, "curl -s http://agilebits.com", "agilebits.com", timeout=30,
        runner=runner, registry=registry,
    )

    assert result["status"] == "ok"
    assert result["exit_code"] == 0
    assert result["stdout"] == "hello from sandbox"
    assert len(runner.specs) == 1
    spec = runner.specs[0]
    assert spec.script == "curl -s http://agilebits.com"
    assert spec.container_name.startswith("vulhunt-sbx-")
    assert spec.network_name.startswith("vulhunt-sbx-net-")
    # ctx egress phải được đăng ký cho proxy VÀ dọn sạch sau khi xong
    assert registry.resolve(spec.session_id) is None
    sqls = " ".join(pool.statements())
    assert "INSERT INTO sandbox_sessions" in sqls
    assert "UPDATE sandbox_sessions" in sqls
    # activity đổ vào log stream của Run để UI thấy
    assert any("run_logs" in sql for sql in pool.statements())


@pytest.mark.asyncio
async def test_timeout_enforced(registry):
    """Script quá hạn → status 'timeout', exit 124 — runner kill container."""
    pool = RecordingPool()
    runner = FakeSandboxRunner(SandboxResult(124, "", "quá hạn 30s — đã kill", True))

    result = await run_verify_session(
        pool, RUN, "sleep 1000", "agilebits.com", timeout=30,
        runner=runner, registry=registry,
    )

    assert result["status"] == "timeout"
    assert result["exit_code"] == 124


@pytest.mark.asyncio
async def test_timeout_clamped_to_max(registry):
    """timeout arg vượt cap → runner nhận giá trị đã clamp (container không sống quá hạn)."""
    pool = RecordingPool()
    runner = FakeSandboxRunner()

    await run_verify_session(
        pool, RUN, "sleep 1", "agilebits.com", timeout=100_000,
        runner=runner, registry=registry,
    )
    assert runner.specs[0].timeout_s <= 600.0


@pytest.mark.asyncio
async def test_wildcard_target_allowed_and_ident_passed(registry):
    pool = RecordingPool()
    runner = FakeSandboxRunner()

    result = await run_verify_session(
        pool, RUN, "true", "api.1password.com", runner=runner, registry=registry
    )
    assert result["status"] == "ok"
    assert runner.specs[0].target == "api.1password.com"  # full host, đã chuẩn hoá
    assert runner.specs[0].ident == {"X-Bug-Bounty": "HackerOne-tester"}


# ── resolve run cho MCP tool (run_id tường minh hoặc Run mới nhất) ──


@pytest.mark.asyncio
async def test_resolve_run_explicit_id():
    pool = RecordingPool()
    pool.fetchrows = [{"id": 3}]

    run = await resolve_run(pool, 3)
    assert run == {"id": 3}
    sql, params = pool.executes[0]
    assert "$1" in sql and params == (3,)
    assert "ORDER BY" not in sql


@pytest.mark.asyncio
async def test_resolve_run_latest_fallback():
    pool = RecordingPool()
    pool.fetchrows = [{"id": 9}]

    run = await resolve_run(pool, None)
    assert run == {"id": 9}
    sql, _ = pool.executes[0]
    assert "ORDER BY id DESC" in sql


@pytest.mark.asyncio
async def test_resolve_run_none_when_no_runs():
    pool = RecordingPool()
    assert await resolve_run(pool, None) is None
