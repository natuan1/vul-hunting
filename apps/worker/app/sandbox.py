"""Sandbox bridge (ticket #11, ADR-0003) — xác minh Candidate trong container
ephemeral do worker sở hữu, agent KHÔNG BAO GIỜ giữ shell lâu dài.

Một lần gọi `run_in_sandbox` = MỘT verify session = MỘT container
`docker run --rm` mới tinh từ tooling image:

- Scope Validator chặn cứng target TẠI BRIDGE — target ngoài Scope snapshot
  của Run thì KHÔNG có container nào được quay (có audit log);
- container chạy trong docker network `--internal` riêng (không route ra
  ngoài) — LUẬT RA NGOÀI duy nhất là egress proxy trong worker (egress.py),
  đối chiếu từng destination với Scope, chèn header định danh, giữ nhịp rate
  limit và ghi egress log vào sandbox_egress;
- timeout được enforce: quá hạn → `docker rm -f` kill container (container
  không sống sót quá hạn, `--rm` tự dọn);
- stdout/stderr/exit code ghi vào sandbox_sessions, hoạt động đổ vào
  run_logs để UI stream.
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Protocol

import asyncpg

from .config import settings
from .egress import EgressContext, EgressRegistry, proxy_credentials
from .scope_validator import target_host
from .tools import DB_STDOUT_CAP, TargetBlockedError, add_log, build_context

log = logging.getLogger("sandbox")

# sàn timeout: dưới 5s coi như cấu hình nhầm
MIN_TIMEOUT_S = 5.0

# registry toàn cục của các verify session đang sống — egress proxy cùng worker
# tra theo session_id; main.py khởi tạo proxy trên cùng object này
session_registry = EgressRegistry()

# cap số dòng egress nhúng vào kết quả trả cho agent — bản đầy đủ trong DB
EGRESS_INLINE_CAP = 100


@dataclass
class SandboxSpec:
    """Mọi thứ runner cần để quay đúng 1 container cho 1 verify session."""

    session_id: int
    container_name: str
    network_name: str
    image: str
    script: str
    timeout_s: float
    proxy_url: str  # http://sbx-<sid>:<token>@sbx-proxy:<port>
    target: str
    ident: dict[str, str]


@dataclass
class SandboxResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool


class SandboxRunner(Protocol):
    """Seam thực thi: quay container (hoặc giả lập trong test)."""

    async def __call__(self, spec: SandboxSpec) -> SandboxResult: ...


def clamp_timeout(timeout: float | None, default: float, maximum: float) -> float:
    """None → mặc định; dưới sàn → sàn; trên cap → cap (container không sống
    quá hạn tối đa cho phép)."""
    value = default if timeout is None else float(timeout)
    return max(MIN_TIMEOUT_S, min(value, maximum))


def build_docker_args(spec: SandboxSpec) -> list[str]:
    """Flags cho `docker run --rm`: name/network/label riêng của session,
    proxy qua env (cả HOA lẫn thường — curl/python đọc khác nhau), target +
    header định danh truyền vào env cho script đọc. Image + argv đứng cuối."""
    proxy = spec.proxy_url
    args = [
        "--rm",  # container tự huỷ khi thoát — KHÔNG có container sót sau session
        "--pull", "never",
        "--name", spec.container_name,
        "--network", spec.network_name,
        "--label", f"vulhunt.sandbox={spec.session_id}",
    ]
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"):
        args += ["--env", f"{var}={proxy}"]
    args += [
        "--env", "NO_PROXY=",
        "--env", "no_proxy=",
        "--env", f"SANDBOX_SESSION_ID={spec.session_id}",
        "--env", f"SANDBOX_TARGET={spec.target}",
    ]
    for name, value in (spec.ident or {}).items():
        args += ["--env", f"IDENT_HEADER_NAME={name}", "--env", f"IDENT_HEADER_VALUE={value}"]
    args += [spec.image, "sh", "-s"]  # script đọc từ stdin
    return args


# ───────────────────────────── vòng đời verify session ─────────────────────────────


def _as_snapshot(snapshot) -> list[dict]:
    if isinstance(snapshot, str):
        return json.loads(snapshot)
    return snapshot


def _base_result(session_id: int, run_id: int, host: str, status: str,
                 egress: list[dict]) -> dict:
    """Khung kết quả chung của mọi nhánh verify session."""
    return {
        "session_id": session_id,
        "run_id": run_id,
        "target": host,
        "status": status,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "reason": None,
        "egress": egress,
        "blocked": sum(1 for e in egress if e["decision"] != "allowed"),
    }


async def run_verify_session(
    pool: asyncpg.Pool,
    run: asyncpg.Record | dict,
    script: str,
    target: str,
    timeout: float | None = None,
    runner=None,
    registry: EgressRegistry | None = None,
) -> dict:
    """Một verify session: chặn scope tại bridge → quay container → thu
    stdout + egress → container tự huỷ. `run` cần id, rate_limit_rps,
    ident_header_name/value, scope_snapshot, allow_non_prod (như detect.py).
    Trả dict tóm tắt cho agent (đủ để đọc kết quả + bị chặn vì sao).
    `registry` để test nhảy vào — mặc định dùng session_registry toàn cục."""
    if not (script or "").strip():
        raise ValueError("script trống — agent phải gửi payload thật cần chạy")
    run_id = run["id"]
    snapshot = _as_snapshot(run["scope_snapshot"])
    host = target_host(target)
    ctx = build_context(
        run_id,
        run["rate_limit_rps"],
        run["ident_header_name"],
        run["ident_header_value"],
        snapshot,
        bool(run["allow_non_prod"]),
    )
    reg = registry if registry is not None else session_registry

    async with pool.acquire() as conn:
        session_id = await conn.fetchval(
            "INSERT INTO sandbox_sessions (run_id, target, script) "
            "VALUES ($1, $2, $3) RETURNING id",
            run_id, host, script,
        )
    container_name = f"vulhunt-sbx-{session_id}"
    network_name = f"vulhunt-sbx-net-{session_id}"

    # ── cửa ắt: Scope Validator chặn TẠI BRIDGE, không container nào được quay ──
    try:
        decision = await ctx.validate(pool, target, tool="run_in_sandbox")
    except TargetBlockedError as exc:
        reason = str(exc)
        await _finish_session(pool, session_id, status="blocked", reason=reason)
        await add_log(pool, run_id, f"Sandbox #{session_id}: chặn {host} TẠI BRIDGE — {reason}", level="error")
        return {**_base_result(session_id, run_id, host, "blocked", []),
                "reason": reason}

    # đăng ký egress ctx TRƯỚC khi container chạy — proxy tra theo session_id
    # (kèm token: proxy credentials thiếu/sai token sẽ bị từ chối)
    token = uuid.uuid4().hex
    proxy_user, _ = proxy_credentials(session_id, token)
    proxy_url = (
        f"http://{proxy_user}:{token}"
        f"@{settings.sandbox_proxy_host}:{settings.sandbox_proxy_port}"
    )
    reg.register(
        EgressContext(
            session_id=session_id,
            run_id=run_id,
            target=host,
            snapshot=snapshot,
            allow_non_prod=bool(run["allow_non_prod"]),
            limiter=ctx.limiter,
            ident=ctx.ident,
            token=token,
        )
    )

    spec = SandboxSpec(
        session_id=session_id,
        container_name=container_name,
        network_name=network_name,
        image=settings.tooling_image,
        script=script,
        timeout_s=clamp_timeout(timeout, settings.sandbox_default_timeout_s,
                                settings.sandbox_max_timeout_s),
        proxy_url=proxy_url,
        target=host,
        ident=ctx.ident,
    )
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE sandbox_sessions SET container_name = $2, network_name = $3 WHERE id = $1",
            session_id, container_name, network_name,
        )
    await add_log(
        pool, run_id,
        f"Sandbox #{session_id}: quay container {container_name} (network internal "
        f"{network_name}) cho {host} · timeout {spec.timeout_s:.0f}s",
    )

    started = time.monotonic()
    try:
        if runner is None:
            runner = DockerSandboxRunner()
        result = await runner(spec)
    except Exception as exc:
        elapsed = time.monotonic() - started
        await _finish_session(pool, session_id, status="error",
                              stderr=str(exc)[:5000])
        await add_log(pool, run_id,
                      f"Sandbox #{session_id}: lỗi môi trường sau {elapsed:.1f}s: {exc}",
                      level="error")
        egress = await _egress_entries(pool, session_id)
        return {**_base_result(session_id, run_id, host, "error", egress),
                "stderr": str(exc)[:5000],
                "reason": f"lỗi môi trường: {exc}"}
    finally:
        reg.unregister(session_id)

    elapsed = time.monotonic() - started
    # chạy xong (kể cả exit ≠ 0 — script không xác minh được là dữ liệu, không
    # phải lỗi hạ tầng); chỉ quá hạn là 'timeout'
    status = "timeout" if result.timed_out else "ok"
    await _finish_session(
        pool, session_id,
        status=status,
        exit_code=result.exit_code,
        stdout=result.stdout[:DB_STDOUT_CAP],
        stderr=result.stderr[:DB_STDOUT_CAP],
    )
    await add_log(
        pool, run_id,
        f"Sandbox #{session_id}: xong · exit {result.exit_code} · {elapsed:.1f}s"
        + (f" · stderr: {result.stderr.strip()[:300]}" if result.stderr.strip() else ""),
        level="info" if result.exit_code == 0 else "error",
    )
    egress = await _egress_entries(pool, session_id)
    return {**_base_result(session_id, run_id, host, status, egress),
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr}


async def _finish_session(pool: asyncpg.Pool, session_id: int, *, status: str,
                          exit_code: int | None = None, stdout: str | None = None,
                          stderr: str | None = None, reason: str | None = None) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE sandbox_sessions SET status = $2, exit_code = $3, stdout = $4, "
            "stderr = $5, reason = $6, finished_at = now() WHERE id = $1",
            session_id, status, exit_code, stdout, stderr, reason,
        )


async def _egress_entries(pool: asyncpg.Pool, session_id: int) -> list[dict]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT destination, scheme, decision, reason FROM sandbox_egress "
            "WHERE session_id = $1 ORDER BY id LIMIT $2",
            session_id, EGRESS_INLINE_CAP,
        )
    return [dict(r) for r in rows]


# ───────────────────────────── API truy verify session ─────────────────────────────


_SESSION_COLS = (
    "id, run_id, target, status, exit_code, reason, container_name, "
    "network_name, started_at, finished_at"
)


async def record_egress(
    pool: asyncpg.Pool,
    session_id: int,
    destination: str,
    scheme: str,
    decision: str,
    reason: str | None,
) -> None:
    """Ghi 1 dòng egress log (main.py kết hàm này vào EgressProxy)."""
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO sandbox_egress (session_id, destination, scheme, decision, reason) "
            "VALUES ($1, $2, $3, $4, $5)",
            session_id, destination, scheme, decision, reason,
        )


async def list_sessions(
    pool: asyncpg.Pool,
    run_id: int | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """Verify session gần nhất, filter theo Run và/hoặc status — truy được
    theo verify session cả ở mức list."""
    clauses: list[str] = []
    params: list = []
    if run_id is not None:
        params.append(run_id)
        clauses.append(f"run_id = ${len(params)}")
    if status:
        params.append(status)
        clauses.append(f"status = ${len(params)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT {_SESSION_COLS} FROM sandbox_sessions {where} "
            f"ORDER BY id DESC LIMIT ${len(params)}",
            *params,
        )
    return [dict(r) for r in rows]


async def get_session(pool: asyncpg.Pool, session_id: int) -> dict | None:
    """Chi tiết 1 verify session: script + stdout/stderr đầy đủ + TOÀN BỘ
    egress log (destination mỗi request ra ngoài, kể cả bị chặn)."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"SELECT {_SESSION_COLS}, script, stdout, stderr "
            f"FROM sandbox_sessions WHERE id = $1",
            session_id,
        )
        if row is None:
            return None
        egress = await conn.fetch(
            "SELECT id, destination, scheme, decision, reason, ts "
            "FROM sandbox_egress WHERE session_id = $1 ORDER BY id",
            session_id,
        )
    return {**dict(row), "egress": [dict(e) for e in egress]}


# ───────────────────────────── resolve Run cho MCP tool ─────────────────────────────


_RUN_COLS = (
    "id, rate_limit_rps, ident_header_name, ident_header_value, "
    "scope_snapshot, allow_non_prod"
)


async def resolve_run(pool: asyncpg.Pool, run_id: int | None):
    """Run áp dụng cho verify session: run_id tường minh nếu agent chỉ định,
    không thì Run MỚI NHẤT (agent hầu như verify candidate của run vừa quét).
    Không có Run nào → None → caller fail-closed."""
    if run_id is not None:
        return await pool.fetchrow(
            f"SELECT {_RUN_COLS} FROM runs WHERE id = $1", run_id
        )
    return await pool.fetchrow(
        f"SELECT {_RUN_COLS} FROM runs ORDER BY id DESC LIMIT 1"
    )


# ───────────────────────────── Docker runner (production) ─────────────────────────────


def is_docker_env_failure(exit_code: int | None, stderr: str) -> bool:
    """Exit 125 + stderr 'docker: ...' = DOCKER lỗi (môi trường, phải raise để
    thấy rõ); 126/127 với `sh -s` là DOANH SCRIPT tự lỗi (lệnh không tồn tại
    ...) — dữ liệu verify, KHÔNG phải lỗi hạ tầng."""
    return exit_code == 125 and stderr.lstrip().lower().startswith("docker")


class DockerSandboxRunner:
    """Quay container thật: network --internal riêng → gắn worker vào network
    (egress proxy đạt được) → docker run --rm → dọn sạch trong mọi trường hợp."""

    async def _docker(self, *args: str, timeout: float = 60.0) -> tuple[int, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.docker_bin, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"không chạy được docker CLI '{settings.docker_bin}': {exc}") from exc
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError(f"docker {' '.join(args[:2])} quá {timeout:.0f}s không phản hồi")
        return proc.returncode or 0, err.decode(errors="replace")

    async def _ignore(self, *args: str) -> None:
        try:
            await self._docker(*args)
        except Exception as exc:  # dọn dẹp best-effort, không che lỗi gốc
            log.info("docker %s: %s (bỏ qua)", args[0], exc)

    async def __call__(self, spec: SandboxSpec) -> SandboxResult:
        args = build_docker_args(spec)
        image, argv = args[-3], args[-2:]
        flags = args[:-3]

        rc, err = await self._docker(
            "network", "create", "--internal", "--attachable",
            "--label", f"vulhunt.sandbox={spec.session_id}", spec.network_name,
        )
        if rc != 0:
            raise RuntimeError(f"không tạo được network {spec.network_name}: {err.strip()[:300]}")
        rc, err = await self._docker(
            "network", "connect", "--alias", settings.sandbox_proxy_host,
            spec.network_name, settings.worker_container_name,
        )
        if rc != 0:
            await self._ignore("network", "rm", spec.network_name)
            raise RuntimeError(
                f"không gắn được {settings.worker_container_name} vào {spec.network_name}: "
                f"{err.strip()[:300]} (worker phải chạy trong compose với docker.sock)"
            )

        comm: asyncio.Task | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.docker_bin, "run", "-i", *flags, image, *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            comm = asyncio.ensure_future(proc.communicate(spec.script.encode()))
            try:
                out, err_bytes = await asyncio.wait_for(
                    asyncio.shield(comm), timeout=spec.timeout_s
                )
            except asyncio.TimeoutError:
                # container KHÔNG được sống quá hạn: kill bằng docker rm -f
                # (chỉ kill CLI thì container vẫn còn chạy detached)
                await self._ignore("rm", "-f", spec.container_name)
                try:
                    out, err_bytes = await asyncio.wait_for(comm, timeout=30.0)
                except (asyncio.TimeoutError, Exception):
                    proc.kill()
                    await proc.wait()
                    out, err_bytes = b"", b""
                return SandboxResult(
                    124,
                    out.decode(errors="replace"),
                    f"script quá hạn {spec.timeout_s:.0f}s — đã kill container",
                    True,
                )
        finally:
            await self._ignore("rm", "-f", spec.container_name)
            await self._ignore("network", "disconnect", spec.network_name,
                               settings.worker_container_name)
            await self._ignore("network", "rm", spec.network_name)

        stdout = out.decode(errors="replace")
        stderr = err_bytes.decode(errors="replace")
        if is_docker_env_failure(proc.returncode, stderr):
            raise RuntimeError(
                f"docker lỗi khi chạy sandbox (exit {proc.returncode}): {stderr.strip()[:300]}"
            )
        return SandboxResult(proc.returncode or 0, stdout, stderr, False)


# ───────────────────────────── dọn rác khi worker khởi động ─────────────────────────────


async def cleanup_stale() -> None:
    """Worker crash giữa chừng có thể bỏ lại container/network sandbox — quét
    theo label và dọn best-effort lúc khởi động (không có DB, không raise)."""
    r = DockerSandboxRunner()
    try:
        proc = await asyncio.create_subprocess_exec(
            settings.docker_bin, "ps", "-aq",
            "--filter", "label=vulhunt.sandbox",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        for cid in out.decode().split():
            await r._ignore("rm", "-f", cid)
        proc = await asyncio.create_subprocess_exec(
            settings.docker_bin, "network", "ls",
            "--filter", "label=vulhunt.sandbox", "--format", "{{.Name}}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        for name in out.decode().split():
            await r._ignore("network", "disconnect", name, settings.worker_container_name)
            await r._ignore("network", "rm", name)
    except Exception as exc:
        log.warning("cleanup sandbox cũ lỗi (bỏ qua): %s", exc)
