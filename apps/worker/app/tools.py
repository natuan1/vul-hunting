"""Thực thi Tool Execution (ticket #8) — chạy CLI thật trong container tooling.

Worker gọi docker CLI qua docker.sock mount (sibling container, đúng mô hình
ADR-0003): `docker run --rm` một container ephemeral từ TOOLING_IMAGE cho mỗi
lần chạy tool. Cơ chế an toàn kế thừa từ ticket #6/#7 giữ nguyên:

- rate limit (req/s) và header định danh nằm trong Run config, MỌI Tool
  Execution đều kế thừa (limiter chờ trước khi launch);
- Scope Validator chặn cứng mọi target không thuộc Scope snapshot —
  TargetBlockedError tường minh, KHÔNG có request nào đi ra;
- mọi target đều ghi audit log (cả allowed lẫn blocked) vào scope_audit_log;
- stdout/stderr/exit code/thời gian ghi vào tool_executions, stdout thô lưu
  artifact trên filesystem (docker volume) và đổ vào run_logs để UI stream.
"""

import asyncio
import json
import logging
import shlex
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import asyncpg

from . import audit
from .config import settings
from .ratelimit import RateLimiter
from .scope_validator import ScopeDecision, check_target, target_host

log = logging.getLogger("tools")

# exit code của CHÍNH DOCKER (không phải của tool): 125 daemon lỗi,
# 126/127 không chạy được lệnh — đây là lỗi môi trường phải raise để queue retry
DOCKER_FAILURE_EXITS = {125, 126, 127}

# cap lưu DB/đổ vào log stream — bản đầy đủ luôn nằm trong artifact file
DB_STDOUT_CAP = 100_000
MAX_STREAM_LINES = 200
MAX_LINE_CHARS = 2_000


class TargetBlockedError(Exception):
    """Scope Validator chặn target — tool nhận lỗi này tường minh."""


def jsonl_lines(stdout: str) -> list[dict]:
    """Trích các dòng JSON hợp lệ (mỗi dòng 1 object) từ stdout của tool."""
    out: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


async def filter_scope(
    pool: asyncpg.Pool, ctx: "ToolContext", targets: list[str], tool: str
) -> tuple[list[str], int]:
    """Lọc danh sách target qua Scope Validator theo HOST — mỗi host duy nhất
    xuất hiện 1 lần trong audit. Trả (target được phép, số target bị chặn);
    target bị chặn đều có audit log (fail-closed của ctx.validate giữ nguyên)."""
    hosts: list[str] = []
    seen: set[str] = set()
    for t in targets:
        h = target_host(t)
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)
    ok_hosts: set[str] = set()
    blocked = 0
    for h in hosts:
        try:
            await ctx.validate(pool, h, tool=tool)
        except TargetBlockedError as exc:
            blocked += 1
            await add_log(pool, ctx.run_id, f"BLOCKED: {exc}", level="error")
            continue
        ok_hosts.add(h)
    return [t for t in targets if target_host(t) in ok_hosts], blocked


@dataclass
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str


class ToolRunner(Protocol):
    """Seam thực thi tool: gọi container (hoặc giả lập trong test)."""

    async def __call__(
        self,
        tool: str,
        args: list[str],
        stdin: str | None = None,
        docker_args: list[str] | None = None,
    ) -> ToolResult: ...


@dataclass
class ToolContext:
    """Cái MỌI Tool Execution của Run đều kế thừa: rate limit, header định danh,
    Scope snapshot + config non-prod. validate() là cửa ắt BẮT BUỘC trước khi
    chạm target — audit log ghi cả lần được phép lẫn lần bị chặn."""

    run_id: int
    limiter: RateLimiter | None
    ident: dict[str, str]
    snapshot: list[dict]
    allow_non_prod: bool = False
    _seq: int = field(default=0, repr=False)

    def next_seq(self) -> int:
        """Số thứ tự Tool Execution trong Run (mỗi attempt đếm lại từ 1)."""
        self._seq += 1
        return self._seq

    async def validate(self, pool: asyncpg.Pool, target: str, tool: str,
                       allow_wildcard_base: bool = False) -> ScopeDecision:
        """Cửa ra ngoài duy nhất của tool — ghi audit TRƯỚC khi quyết định.

        `tool` là tool sắp chạm target (để audit log rõ phần tử chịu trách nhiệm).
        `allow_wildcard_base`: chỉ cho passive discovery trên base của wildcard
        đã khai báo (subfinder/amass), không bao giờ dùng cho probe chủ động.
        Fail-closed: nếu chính lần ghi audit lỗi (DB trục trặc), exception
        đẩy lên để Run retry — không có request nào ra ngoài mà thiếu audit.
        """
        d = check_target(
            target,
            self.snapshot,
            allow_non_prod=self.allow_non_prod,
            allow_wildcard_base=allow_wildcard_base,
        )
        await audit.record(
            pool, self.run_id, tool, target_host(target), d.decision, d.reason
        )
        if not d.allowed:
            raise TargetBlockedError(d.reason)
        return d


def build_context(
    run_id: int,
    rate_limit_rps: float | None,
    ident_header_name: str | None,
    ident_header_value: str | None,
    snapshot: list[dict],
    allow_non_prod: bool,
) -> ToolContext:
    limiter = RateLimiter(1.0 / rate_limit_rps) if rate_limit_rps and rate_limit_rps > 0 else None
    ident: dict[str, str] = {}
    if ident_header_name and ident_header_value:
        ident[ident_header_name] = ident_header_value
    return ToolContext(
        run_id=run_id,
        limiter=limiter,
        ident=ident,
        snapshot=snapshot,
        allow_non_prod=bool(allow_non_prod),
    )


class DockerToolRunner:
    """Callable chạy 1 tool CLI trong container ephemeral từ tooling image."""

    def __init__(self, image: str | None = None, timeout_s: float | None = None) -> None:
        self.image = image or settings.tooling_image
        self.timeout_s = timeout_s or settings.tool_timeout_s

    async def __call__(
        self,
        tool: str,
        args: list[str],
        stdin: str | None = None,
        docker_args: list[str] | None = None,
    ) -> ToolResult:
        cmd = [settings.docker_bin, "run", "--rm", "--pull", "never"]
        cmd += docker_args or []
        if stdin is not None:
            cmd.append("-i")
        cmd += [self.image, tool, *args]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:  # không có docker CLI — lỗi môi trường
            raise RuntimeError(f"không chạy được docker CLI '{settings.docker_bin}': {exc}") from exc
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(stdin.encode() if stdin is not None else None),
                timeout=self.timeout_s,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(
                124, "", f"tool '{tool}' quá hạn {self.timeout_s:.0f}s — đã kill container"
            )
        stdout = out.decode(errors="replace")
        stderr = err.decode(errors="replace")
        if proc.returncode in DOCKER_FAILURE_EXITS:
            raise RuntimeError(
                f"docker lỗi khi chạy '{tool}' (exit {proc.returncode}): {stderr.strip()[:300]}"
            )
        return ToolResult(proc.returncode or 0, stdout, stderr)


def _looks_jsonl(stdout: str) -> bool:
    return stdout.lstrip()[:1] in ("{", "[")


def write_artifact(run_id: int, seq: int, tool: str, result: ToolResult) -> str | None:
    """Lưu stdout thô vào artifact trên volume; trả path hoặc None nếu IO lỗi.

    Volume chết không được làm chết Run — tool đã chạy xong, dữ liệu vẫn còn
    trong DB (đã cap); chỉ mất file thô.
    """
    try:
        base = Path(settings.artifacts_dir) / str(run_id)
        base.mkdir(parents=True, exist_ok=True)
        ext = ".jsonl" if _looks_jsonl(result.stdout) else ".log"
        path = base / f"{seq:02d}-{tool}{ext}"
        path.write_text(result.stdout, encoding="utf-8")
        return str(path)
    except OSError as exc:
        log.warning("run %d: không ghi được artifact (%s)", run_id, exc)
        return None


def clear_artifacts(run_id: int) -> None:
    """Xoá artifact của Run trước khi attempt mới bắt đầu — đồng bộ với việc
    tool_executions bị xoá mỗi attempt; tránh file cũ của lần thử trước còn
    nằm lại gây hiểu lầm là kết quả của lần này."""
    shutil.rmtree(Path(settings.artifacts_dir) / str(run_id), ignore_errors=True)


async def add_log(pool: asyncpg.Pool, run_id: int, message: str, level: str = "info") -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO run_logs (run_id, level, message) VALUES ($1, $2, $3)",
            run_id,
            level,
            message,
        )


async def execute_tool(
    pool: asyncpg.Pool,
    ctx: ToolContext,
    tool: str,
    args: list[str],
    stdin: str | None = None,
    runner: ToolRunner | None = None,
    docker_args: list[str] | None = None,
) -> ToolResult:
    """Một Tool Execution: tạo row 'running' → chờ rate limit → chạy tool →
    ghi exit code/stdout/stderr/thời gian + artifact. Exit code khác 0 KHÔNG
    raise (tool lỗi là dữ liệu recon, không phải lỗi hạ tầng) — chỉ lỗi môi
    trường docker mới raise để jobqueue retry."""
    seq = ctx.next_seq()
    args_text = " ".join(shlex.quote(a) for a in args)
    header_note = " ".join(f"[{k}: {v}]" for k, v in ctx.ident.items())
    async with pool.acquire() as conn:
        exec_id = await conn.fetchval(
            "INSERT INTO tool_executions (run_id, seq, tool, args) "
            "VALUES ($1, $2, $3, $4) RETURNING id",
            ctx.run_id,
            seq,
            tool,
            args_text,
        )
    await add_log(pool, ctx.run_id, f"$ {tool} {args_text} {header_note}".rstrip())

    if ctx.limiter is not None:
        await ctx.limiter.wait()  # mọi launch của Run đều đi qua đây
    started = time.monotonic()
    if runner is None:
        runner = DockerToolRunner()
    try:
        result = await runner(tool, args, stdin, docker_args)
    except Exception as exc:
        elapsed = time.monotonic() - started
        await pool.execute(
            "UPDATE tool_executions SET status = 'failed', stderr = $2, "
            "finished_at = now() WHERE id = $1",
            exec_id,
            str(exc)[:5000],
        )
        await add_log(
            pool, ctx.run_id, f"{tool} lỗi môi trường sau {elapsed:.1f}s: {exc}", level="error"
        )
        raise

    elapsed = time.monotonic() - started
    status = "ok" if result.exit_code == 0 else "failed"
    artifact_path = write_artifact(ctx.run_id, seq, tool, result)
    stdout_db = result.stdout[:DB_STDOUT_CAP]
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE tool_executions SET status = $2, exit_code = $3, stdout = $4, "
            "stderr = $5, artifact_path = $6, finished_at = now() WHERE id = $1",
            exec_id,
            status,
            result.exit_code,
            stdout_db,
            result.stderr[:DB_STDOUT_CAP],
            artifact_path,
        )

    lines = result.stdout.splitlines()
    for line in lines[:MAX_STREAM_LINES]:
        await add_log(pool, ctx.run_id, line[:MAX_LINE_CHARS])
    if len(lines) > MAX_STREAM_LINES:
        await add_log(
            pool,
            ctx.run_id,
            f"… {len(lines) - MAX_STREAM_LINES} dòng nữa — xem artifact {artifact_path or '(không lưu được)'}",
        )
    note = "" if result.exit_code == 0 else f" · stderr: {result.stderr.strip()[:300] or '(trống)'}"
    await add_log(
        pool, ctx.run_id, f"→ {tool} xong · exit {result.exit_code} · {elapsed:.1f}s{note}",
        level="info" if result.exit_code == 0 else "error",
    )
    return result
