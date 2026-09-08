"""MCP server của worker (ticket #11, ADR-0003) — expose tool
`run_in_sandbox` cho hermes qua MCP toolset.

hermes cấu hình (config/hermes/config.yaml):

    mcp_servers:
      sandbox:
        url: "http://worker:8000/mcp"
        headers:
          Authorization: "Bearer ${SANDBOX_MCP_KEY}"

Hermes nhận tool với prefix toolset: `mcp_sandbox_run_in_sandbox`. Mỗi lần
gọi = 1 verify session = 1 container --rm mới tinh (app/sandbox.py); agent
không bao giờ giữ shell lâu dài. Endpoint require bearer key — rỗng thì
fail-closed (401 mọi call).
"""

import hashlib
import hmac
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from . import sandbox
from .config import settings

log = logging.getLogger("sandbox_mcp")

# cap stdout/stderr nhúng vào kết quả trả cho agent — bản đầy đủ nằm trong DB
# (sandbox_sessions) và agent đọc thêm qua /sandbox/sessions/{id} khi cần
TOOL_OUTPUT_CAP = 20_000

_pool = None  # asyncpg.Pool — main.py bind trong lifespan (tránh import vòng)


def bind_pool(pool) -> None:
    global _pool
    _pool = pool


async def _run_in_sandbox(
    script: str,
    target: str,
    timeout: int | None = None,
    run_id: int | None = None,
) -> dict[str, Any]:
    """Phần thực thi của tool (tách khỏi decorator để test monkeypatch được)."""
    if _pool is None:
        raise RuntimeError("worker chưa sẵn sàng (pool chưa bind)")
    run = await sandbox.resolve_run(_pool, run_id)
    if run is None:
        return {
            "status": "error",
            "reason": "không có Run nào — hãy tạo Run cho Program trước khi verify",
        }
    result = await sandbox.run_verify_session(
        _pool, run, script, target, timeout=timeout
    )
    return {
        **result,
        "stdout": (result.get("stdout") or "")[:TOOL_OUTPUT_CAP],
        "stderr": (result.get("stderr") or "")[:TOOL_OUTPUT_CAP],
        "note": (
            f"stdout/stderr đầy đủ: GET /sandbox/sessions/{result['session_id']} "
            f"· egress log truy theo verify session #{result['session_id']}"
        ),
    }


def build_mcp() -> FastMCP:
    """Tạo FastMCP server (mỗi instance chỉ chạy lifespan 1 lần — production
    dùng singleton bên dưới, test tạo instance riêng khi cần)."""
    server = FastMCP(
        "sandbox",
        stateless_http=True,   # không giữ session MCP — mỗi call tự đứng vững
        json_response=True,    # trả JSON thay vì SSE stream — qua proxy đơn giản hơn
        streamable_http_path="/",  # mount tại /mcp trong main.py
        # endpoint đã require bearer key + chỉ lắng nghe trong compose network
        # → tắt DNS-rebinding guard của SDK (mặc định chỉ cho Host localhost,
        # gây 421 cho Host 'worker:8000' từ hermes)
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        ),
    )

    @server.tool()
    async def run_in_sandbox(
        script: str,
        target: str,
        timeout: int | None = None,
        run_id: int | None = None,
    ) -> dict[str, Any]:
        """Chạy 1 payload script (POSIX shell) trong container sandbox ephemeral
        nhắm vào `target` đã nằm trong Scope.

        Container mới tinh cho mỗi lần gọi, tự huỷ khi xong; mọi request ra
        ngoài đi qua egress proxy (chỉ cho phép target trong Scope, tự chèn
        header định danh, rate limit theo Run) và được ghi egress log.

        Args:
            script: nội dung shell script cần chạy (vd `curl -sS https://target/`).
            target: host/URL đích chính của payload — PHẢI thuộc Scope của Run.
            timeout: giây tối đa cho script (mặc định 120, cap 600); quá hạn
              container bị kill.
            run_id: Run áp dụng Scope/rate limit (bỏ trống → Run mới nhất).

        Returns JSON: session_id, run_id, target, status
        (ok|timeout|blocked|error), exit_code, stdout, stderr, egress (mỗi
        destination + decision), blocked (số destination bị chặn).
        """
        return await _run_in_sandbox(script, target, timeout, run_id)

    return server


# singleton production — lifespan của main.py chạy session manager đúng 1 lần
mcp = build_mcp()


class BearerAuthMiddleware:
    """ASGI middleware chặn mọi request thiếu/sai bearer key.
    Key chưa cấu hình → từ chối TẤT CẢ (fail-closed)."""

    def __init__(self, app, key: str) -> None:
        self.app = app
        self.key = key

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":  # lifespan/... đi thẳng
            await self.app(scope, receive, send)
            return
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        provided = headers.get(b"authorization", b"")
        # so khớp constant-time — tránh đoán key qua timing
        expected = hashlib.sha256(f"Bearer {self.key}".encode()).digest()
        ok = bool(self.key) and hmac.compare_digest(
            expected, hashlib.sha256(provided).digest()
        )
        if not ok:
            body = b'{"error": "unauthorized"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (b"www-authenticate", b"Bearer"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


def mcp_asgi_app():
    """ASGI app mount vào FastAPI tại /mcp — MCP streamable HTTP + bearer auth."""
    return BearerAuthMiddleware(mcp.streamable_http_app(), settings.sandbox_mcp_key)
