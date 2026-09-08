"""Egress proxy của Sandbox bridge (ticket #11, ADR-0003).

Container sandbox chạy trong docker network `--internal` (không có route ra
ngoài) — LUẬT RA NGOÀI duy nhất là egress proxy chạy trong worker, được gắn
vào network riêng của từng verify session. Proxy đối chiếu MỌI destination
với Scope snapshot của session (cùng check_target với Scope Validator), chèn
header định danh, giữ nhịp rate limit của Run và ghi egress log (một dòng
mỗi connection) vào sandbox_egress — request nhắm ngoài Scope bị TỪ CHỐI
forward: có dòng log decision 'blocked*' nhưng không có packet nào đi ra.

Sandbox container trỏ HTTP(S)_PROXY về proxy kèm thông tin đăng nhập
`sbx-<session_id>:<token>` (HTTP Proxy-Authorization) — nhờ đó proxy biết
mỗi connection thuộc verify session nào mà không cần dò IP.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field

from .ratelimit import RateLimiter
from .scope_validator import ScopeDecision, check_target

log = logging.getLogger("egress")

# connection relay quá hạn không đọc được gì → coi như chết, nhả socket
RELAY_IDLE_TIMEOUT_S = 60.0


@dataclass
class EgressContext:
    """Trạng thái an toàn của MỘT verify session mà proxy dựa vào để ra quyết
    định: scope snapshot + flag non-prod của Run, rate limit và header định
    danh kế thừa từ Run config."""

    session_id: int
    run_id: int
    target: str  # host đã chuẩn hoá của verify session (đã qua validator)
    snapshot: list[dict]
    allow_non_prod: bool
    limiter: RateLimiter | None
    ident: dict[str, str] = field(default_factory=dict)
    token: str = ""  # secret của session — proxy credentials phải khớp

    def token_matches(self, password: str) -> bool:
        """So khớp secret của session (constant-time; token rỗng → không khớp)."""
        if not self.token or not password:
            return False
        return hmac.compare_digest(
            hashlib.sha256(self.token.encode()).digest(),
            hashlib.sha256(password.encode()).digest(),
        )


class EgressRegistry:
    """Đăng ký session đang sống: proxy tra theo session_id (lấy từ
    Proxy-Authorization) để có scope/rate limit của connection hiện tại.
    Sandbox bridge đăng ký trước khi quay container và huỷ trong `finally`."""

    def __init__(self) -> None:
        self._sessions: dict[int, EgressContext] = {}

    def register(self, ctx: EgressContext) -> None:
        self._sessions[ctx.session_id] = ctx

    def unregister(self, session_id: int) -> None:
        self._sessions.pop(session_id, None)

    def resolve(self, session_id: int) -> EgressContext | None:
        return self._sessions.get(session_id)

    def clear(self) -> None:
        self._sessions.clear()


def proxy_credentials(session_id: int, token: str) -> tuple[str, str]:
    """Cặp đăng nhập proxy của session — username mã hoá session_id để proxy
    nhận diện connection thuộc verify session nào."""
    return f"sbx-{session_id}", token


def parse_proxy_user(user: str) -> int | None:
    """'sbx-42' → 42; mọi định dạng khác → None (fail-closed: 407)."""
    prefix = "sbx-"
    if not user.startswith(prefix):
        return None
    tail = user[len(prefix):]
    return int(tail) if tail.isdigit() else None


def decide_destination(
    host: str, ctx: EgressContext
) -> ScopeDecision:
    """Quyết định cho 1 destination — CÙNG check_target với Scope Validator,
    áp cho từng connection của sandbox (payload có thể tự trỏ chỗ khác)."""
    return check_target(host, ctx.snapshot, allow_non_prod=ctx.allow_non_prod)


def _parse_authority(authority: str) -> tuple[str, int]:
    """'host:port' từ CONNECT / absolute-URI → (host, port); port mặc định theo
    scheme do caller đặt trước. IPv6 [..]:port cũng xử lý."""
    authority = authority.strip()
    if authority.startswith("["):  # [v6]:port
        host, _, rest = authority[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else 443
        return host.lower(), port
    host, _, port = authority.partition(":")
    return host.lower(), int(port) if port.isdigit() else 0


class EgressProxy:
    """HTTP proxy (CONNECT + absolute-URI) chèn giữa sandbox và thế giới ngoài.

    `record` là seam ghi egress log (async callback — main kết vào DB);
    `connect_upstream` là seam mở kết nối ra ngoài (giả lập trong test).
    """

    def __init__(
        self,
        registry: EgressRegistry,
        record,
        connect_upstream=None,
        relay_idle_timeout_s: float = RELAY_IDLE_TIMEOUT_S,
    ) -> None:
        self.registry = registry
        self.record = record
        self.connect_upstream = connect_upstream or self._open_connection
        self.relay_idle_timeout_s = relay_idle_timeout_s

    @staticmethod
    async def _open_connection(host: str, port: int):
        return await asyncio.open_connection(host, port)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=30.0
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            writer.close()
            return
        try:
            await self._route(head.decode(errors="replace"), reader, writer)
        except Exception:
            log.exception("egress proxy lỗi xử lý connection")
        finally:
            writer.close()

    # ── định tuyến theo dạng request ──

    async def _route(self, head: str, reader, writer) -> None:
        request_line, _, rest = head.partition("\r\n")
        parts = request_line.split()
        if len(parts) != 3:
            await self._reject(writer, 400, "bad request")
            return
        method, target, _version = parts
        ctx = self._session_from_headers(rest)
        if ctx is None:
            await self._reject(writer, 407, "proxy authentication required")
            return

        if method == "CONNECT":
            await self._handle_connect(ctx, target, reader, writer)
        else:
            await self._handle_http(ctx, method, target, rest, reader, writer)

    def _session_from_headers(self, head_rest: str):
        """Session từ Proxy-Authorization: Basic base64(sbx-<sid>:<token>) —
        CẢ username LẪN token phải khớp (session_id tuần tự, token là thứ
        duy nhất chặn session khác mượn danh để log hộ egress)."""
        for line in head_rest.split("\r\n"):
            name, _, value = line.partition(":")
            if name.strip().lower() != "proxy-authorization":
                continue
            scheme, _, creds = value.strip().partition(" ")
            if scheme.lower() != "basic":
                return None
            try:
                user, _, password = base64.b64decode(creds).decode().partition(":")
            except (ValueError, UnicodeDecodeError):
                return None
            session_id = parse_proxy_user(user)
            if session_id is None:
                return None
            ctx = self.registry.resolve(session_id)
            if ctx is None or not ctx.token_matches(password):
                return None
            return ctx
        return None

    # ── CONNECT (HTTPS / TCP tuỳ ý) ──

    async def _handle_connect(self, ctx, authority: str, reader, writer) -> None:
        host, port = _parse_authority(authority)
        scheme = "https" if port == 443 else "tcp"
        up_reader, up_writer = await self._authorize_and_connect(
            ctx, host, port, scheme, writer
        )
        if up_writer is None:
            return
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        await self._relay(reader, writer, up_reader, up_writer)

    # ── HTTP thường (absolute-URI) ──

    async def _handle_http(self, ctx, method: str, url: str, head_rest: str, reader, writer) -> None:
        scheme, _, rest = url.partition("://")
        if scheme.lower() != "http" or not rest:
            await self._reject(writer, 400, "chỉ hỗ trợ http qua proxy thường")
            return
        authority, _, path = rest.partition("/")
        host, port = _parse_authority(authority)
        up_reader, up_writer = await self._authorize_and_connect(
            ctx, host, port or 80, "http", writer
        )
        if up_writer is None:
            return
        try:
            headers, content_length = self._rewrite_request(head_rest, ctx)
            body = b""
            if content_length:
                body = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=30.0
                )
            request = (
                f"{method} /{path} HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                f"{headers}"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + body
            up_writer.write(request)
            await up_writer.drain()
            await self._relay(reader, writer, up_reader, up_writer)
        finally:
            up_writer.close()

    async def _authorize_and_connect(self, ctx, host: str, port: int, scheme: str, writer):
        """Đường chung của 2 dạng request: đối chiếu Scope → log egress →
        (được phép mới) chờ rate limit → mở kết nối ra ngoài. Trả (reader,
        writer) hoặc (None, None) nếu đã trả lỗi cho client (blocked/502)."""
        decision = decide_destination(host, ctx)
        await self._log_egress(ctx, f"{host}:{port}", scheme, decision)
        if not decision.allowed:
            await self._reject(writer, 403, decision.reason)
            return None, None
        if ctx.limiter is not None:
            await ctx.limiter.wait()
        try:
            return await asyncio.wait_for(
                self.connect_upstream(host, port), timeout=30.0
            )
        except (OSError, asyncio.TimeoutError) as exc:
            await self._reject(writer, 502, f"không kết nối được {host}:{port}: {exc}")
            return None, None

    def _rewrite_request(self, head_rest: str, ctx: EgressContext) -> tuple[str, int | None]:
        """Bỏ header proxy hop-by-hop, chèn header định danh (ghi đè nếu script
        đã tự đặt); trả (headers_text, content_length) — body do caller đọc từ
        client reader theo Content-Length."""
        lines = head_rest.split("\r\n")
        kept: list[str] = []
        content_length: int | None = None
        skip = {"proxy-authorization", "proxy-connection", "connection", "host", "content-length"}
        for line in lines:
            name, _, value = line.partition(":")
            key = name.strip().lower()
            if key == "content-length" and value.strip().isdigit():
                content_length = int(value.strip())
            if key in skip or not line:
                continue
            kept.append(line)
        for name, value in (ctx.ident or {}).items():
            kept = [
                ln for ln in kept if ln.partition(":")[0].strip().lower() != name.lower()
            ]
            kept.append(f"{name}: {value}")
        return "\r\n".join(kept) + "\r\n", content_length

    # ── chung ──

    async def _relay(self, reader, writer, up_reader, up_writer) -> None:
        """Đẩy 2 chiều cho tới khi một bên đóng; idle quá hạn thì buộc nhả."""
        async def pump(src, dst):
            try:
                while True:
                    chunk = await asyncio.wait_for(
                        src.read(65536), timeout=self.relay_idle_timeout_s
                    )
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (asyncio.TimeoutError, ConnectionError):
                pass
            finally:
                dst.close()

        await asyncio.gather(
            pump(reader, up_writer), pump(up_reader, writer), return_exceptions=True
        )
        up_writer.close()

    async def _reject(self, writer, status: int, reason: str) -> None:
        phrases = {
            400: "Bad Request",
            403: "Forbidden",
            407: "Proxy Authentication Required",
            502: "Bad Gateway",
        }
        body = json.dumps({"error": reason})
        writer.write(
            (
                f"HTTP/1.1 {status} {phrases.get(status, 'Error')}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n{body}"
            ).encode()
        )
        await writer.drain()

    async def _log_egress(self, ctx: EgressContext, destination: str, scheme: str, decision: ScopeDecision) -> None:
        try:
            await self.record(ctx.session_id, destination, scheme, decision.decision, decision.reason)
        except Exception:
            log.exception("ghi egress log lỗi (session %s)", ctx.session_id)
