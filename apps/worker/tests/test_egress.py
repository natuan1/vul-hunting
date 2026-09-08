"""Test Egress proxy (ticket #11) — MỌI destination của sandbox đi qua đây:
được phép mới forward (có rate limit + header định danh), ngoài Scope thì
TỪ CHỐI forward (không có packet nào đi ra), và MỌI lần đều có egress log.

Proxy chạy bằng socket thật trong loopback; origin/upstream là server giả.

Chạy trong container worker:
    docker compose exec worker python -m pytest tests/test_egress.py -q
"""

import asyncio
import base64

import pytest

from app.egress import (
    EgressContext,
    EgressProxy,
    EgressRegistry,
    _parse_authority,
    decide_destination,
)

SCOPE = [
    {"asset_identifier": "agilebits.com", "asset_type": "URL"},
    {"asset_identifier": "*.1password.com", "asset_type": "WILDCARD"},
]

AUTH_OK = base64.b64encode(b"sbx-42:tok").decode()


class CountingLimiter:
    """Rate limiter giả: đếm số lần chờ nhịp (phải là 0 khi bị chặn)."""

    def __init__(self):
        self.n = 0

    async def wait(self):
        self.n += 1


class FakeUpstream:
    """Kết nối ra 'ngoài' giả: ghi lại (host, port) rồi nối tới origin thật
    trên loopback để test relay 2 chiều bằng socket thật."""

    def __init__(self, origin_port: int | None):
        self.origin_port = origin_port
        self.calls: list[tuple[str, int]] = []

    async def __call__(self, host: str, port: int):
        self.calls.append((host, port))
        assert self.origin_port is not None, "không được có kết nối nào khi bị chặn"
        return await asyncio.open_connection("127.0.0.1", self.origin_port)


def make_ctx(limiter=None, session_id: int = 42, token: str = "tok") -> EgressContext:
    return EgressContext(
        session_id=session_id,
        run_id=7,
        snapshot=SCOPE,
        allow_non_prod=False,
        limiter=limiter,
        ident={"X-Bug-Bounty": "HackerOne-tester"},
        token=token,
    )


async def start_proxy(registry: EgressRegistry, upstream: FakeUpstream):
    """Proxy thật trên loopback + callback ghi egress log vào list."""
    rows: list[tuple] = []

    async def record(session_id, destination, scheme, decision, reason):
        rows.append((session_id, destination, scheme, decision, reason))

    proxy = EgressProxy(registry=registry, record=record, connect_upstream=upstream)
    server = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port, rows


async def start_origin(handler):
    """Server origin giả trên loopback; trả (server, port)."""
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def proxy_auth() -> str:
    return f"Proxy-Authorization: Basic {AUTH_OK}\r\n"


# ── helpers thuần ──


def test_parse_authority():
    assert _parse_authority("agilebits.com:8080") == ("agilebits.com", 8080)
    assert _parse_authority("agilebits.com") == ("agilebits.com", 0)
    assert _parse_authority("[::1]:8443") == ("::1", 8443)


def test_decide_destination_uses_scope():
    assert decide_destination("agilebits.com", make_ctx()).allowed
    assert decide_destination("api.1password.com", make_ctx()).allowed
    assert not decide_destination("evil.com", make_ctx()).allowed


# ── CONNECT (HTTPS / TCP tuỳ ý) ──


@pytest.mark.asyncio
async def test_connect_allowed_relays_bytes():
    """CONNECT tới target trong Scope: relay 2 chiều, egress log 'allowed',
    rate limiter đúng 1 lần/connection."""
    relay_received = asyncio.Queue()

    async def echo_handler(reader, writer):
        relay_received.put_nowait(await reader.readexactly(5))
        writer.write(b"pong!")
        await writer.drain()
        await writer.wait_closed()

    origin_server, origin_port = await start_origin(echo_handler)
    registry = EgressRegistry()
    ctx = make_ctx(limiter=CountingLimiter())
    registry.register(ctx)
    upstream = FakeUpstream(origin_port)
    server, port, rows = await start_proxy(registry, upstream)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            (
                "CONNECT agilebits.com:443 HTTP/1.1\r\n"
                "Host: agilebits.com:443\r\n" + proxy_auth() + "\r\n"
            ).encode()
        )
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        assert b"200" in head
        writer.write(b"hello")
        await writer.drain()
        assert await asyncio.wait_for(relay_received.get(), 5) == b"hello"
        assert await asyncio.wait_for(reader.readexactly(5), 5) == b"pong!"
        assert upstream.calls == [("agilebits.com", 443)]
        assert rows == [(42, "agilebits.com:443", "https", "allowed", rows[0][4])]
        assert ctx.limiter.n == 1
        writer.close()
    finally:
        server.close()
        origin_server.close()


@pytest.mark.asyncio
async def test_connect_out_of_scope_blocked_no_request_goes_out():
    """CONNECT tới host ngoài Scope → 403, KHÔNG có kết nối nào đi ra,
    egress log vẫn ghi destination bị chặn."""
    registry = EgressRegistry()
    ctx = make_ctx(limiter=CountingLimiter())
    registry.register(ctx)
    upstream = FakeUpstream(None)  # không có origin — call nào sẽ nát test
    server, port, rows = await start_proxy(registry, upstream)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            (
                "CONNECT evil.com:443 HTTP/1.1\r\n"
                "Host: evil.com:443\r\n" + proxy_auth() + "\r\n"
            ).encode()
        )
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert b"403" in head
        assert upstream.calls == []  # KHÔNG có request đi ra
        assert rows[0][:4] == (42, "evil.com:443", "https", "blocked_out_of_scope")
        assert ctx.limiter.n == 0  # bị chặn thì không tốn nhịp
        writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_connect_wildcard_target_blocked_via_proxy():
    """Payload tự trỏ sang host KHÁC trong verify session vẫn bị đối chiếu
    Scope theo từng connection (đúng cơ chế 'chặn tại bridge')."""
    registry = EgressRegistry()
    registry.register(make_ctx())
    upstream = FakeUpstream(None)
    server, port, rows = await start_proxy(registry, upstream)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            (
                "CONNECT dev.1password.com:443 HTTP/1.1\r\n"
                "Host: dev.1password.com:443\r\n" + proxy_auth() + "\r\n"
            ).encode()
        )
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert b"403" in head  # non-prod flag qua wildcard → chặn
        assert rows[0][3] == "blocked_non_prod"
        assert upstream.calls == []
        writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_no_proxy_auth_rejected_407():
    """Không có/không hiểu Proxy-Authorization → 407, không log egress (không
    thuộc session nào), không có kết nối đi ra."""
    registry = EgressRegistry()
    registry.register(make_ctx())
    upstream = FakeUpstream(None)
    server, port, rows = await start_proxy(registry, upstream)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert b"407" in head
        assert upstream.calls == []
        assert rows == []
        writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_wrong_token_rejected_fail_closed():
    """Token sai (session khác đoán session_id — tuần tự!) → 407: không forward,
    không mượn danh log hộ egress của session khác."""
    registry = EgressRegistry()
    registry.register(make_ctx())  # token thật = 'tok'
    upstream = FakeUpstream(None)
    server, port, rows = await start_proxy(registry, upstream)
    try:
        bad_auth = base64.b64encode(b"sbx-42:guessed").decode()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            (
                "CONNECT agilebits.com:443 HTTP/1.1\r\n"
                f"Proxy-Authorization: Basic {bad_auth}\r\n\r\n"
            ).encode()
        )
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert b"407" in head
        assert upstream.calls == []  # KHÔNG có kết nối đi ra
        assert rows == []  # không log hộ session 42
        writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_unknown_session_rejected():
    """Credentials của session không tồn tại (đã kết thúc) → 407 fail-closed."""
    registry = EgressRegistry()  # không đăng ký session 999
    upstream = FakeUpstream(None)
    server, port, rows = await start_proxy(registry, upstream)
    try:
        auth = base64.b64encode(b"sbx-999:tok").decode()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            (
                "CONNECT agilebits.com:443 HTTP/1.1\r\n"
                f"Proxy-Authorization: Basic {auth}\r\n\r\n"
            ).encode()
        )
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert b"407" in head
        assert upstream.calls == []
        writer.close()
    finally:
        server.close()


# ── HTTP thường (absolute-URI) ──


@pytest.mark.asyncio
async def test_plain_http_rewrites_injects_ident_and_logs():
    """GET absolute-URI tới target trong Scope: origin-form request line, bỏ
    header proxy, chèn/ghi đè header định danh, forward body, relay response,
    egress log 'allowed'."""
    seen: list[bytes] = []

    async def origin_handler(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        length = 0
        for line in head.decode().split("\r\n"):
            if line.lower().startswith("content-length:"):
                length = int(line.split(":")[1])
        body = await reader.readexactly(length) if length else b""
        seen.append(head + body)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        await writer.drain()
        writer.close()

    origin_server, origin_port = await start_origin(origin_handler)
    registry = EgressRegistry()
    ctx = make_ctx(limiter=CountingLimiter())
    registry.register(ctx)
    upstream = FakeUpstream(origin_port)
    server, port, rows = await start_proxy(registry, upstream)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            (
                "GET http://agilebits.com/api?v=1 HTTP/1.1\r\n"
                "Host: agilebits.com\r\n" + proxy_auth() +
                "X-Bug-Bounty: spoofed\r\n"
                "Accept: */*\r\n\r\n"
            ).encode()
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert b"200 OK" in response
        await asyncio.sleep(0.1)
        request = seen[0].decode()
        assert request.startswith("GET /api?v=1 HTTP/1.1\r\n")  # origin-form
        assert "Host: agilebits.com\r\n" in request
        assert "Proxy-Authorization" not in request
        # header định danh được chèn ĐÈ lên giá trị script tự đặt
        assert request.count("X-Bug-Bounty: HackerOne-tester") == 1
        assert "spoofed" not in request
        assert "Accept: */*" in request
        assert upstream.calls == [("agilebits.com", 80)]
        assert rows[0][:4] == (42, "agilebits.com:80", "http", "allowed")
        assert ctx.limiter.n == 1
        writer.close()
    finally:
        server.close()
        origin_server.close()


@pytest.mark.asyncio
async def test_plain_http_out_of_scope_blocked():
    """GET nhắm ngoài Scope → 403 JSON, không forward, có egress log."""
    registry = EgressRegistry()
    registry.register(make_ctx())
    upstream = FakeUpstream(None)
    server, port, rows = await start_proxy(registry, upstream)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            (
                "GET http://evil.example/payload HTTP/1.1\r\n"
                "Host: evil.example\r\n" + proxy_auth() + "\r\n"
            ).encode()
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert b"403" in response
        assert upstream.calls == []
        assert rows[0][:4] == (42, "evil.example:80", "http", "blocked_out_of_scope")
        writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_plain_http_forwards_body():
    """POST có body: body đọc theo Content-Length rồi forward nguyên vẹn."""
    seen: list[bytes] = []

    async def origin_handler(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        body = await reader.readexactly(11)
        seen.append(head + body)
        writer.write(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    origin_server, origin_port = await start_origin(origin_handler)
    registry = EgressRegistry()
    registry.register(make_ctx())
    upstream = FakeUpstream(origin_port)
    server, port, rows = await start_proxy(registry, upstream)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            (
                "POST http://agilebits.com/submit HTTP/1.1\r\n" + proxy_auth() +
                "Content-Length: 11\r\n\r\nhello world"
            ).encode()
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        assert b"201" in response
        await asyncio.sleep(0.1)
        assert seen[0].endswith(b"hello world")
        writer.close()
    finally:
        server.close()
        origin_server.close()
