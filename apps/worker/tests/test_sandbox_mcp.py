"""Test MCP server của sandbox bridge (ticket #11).

Tool `run_in_sandbox` (qua FastMCP) + bearer auth middleware + ROUND-TRIP
protocol thật (streamable HTTP client ↔ server mounted trong FastAPI).

Chạy trong container worker:
    docker compose exec worker python -m pytest tests/test_sandbox_mcp.py -q
"""

import asyncio
import base64
import json
from contextlib import asynccontextmanager

import pytest

mcp_sdk = pytest.importorskip("mcp")  # môi trường thiếu mcp SDK → bỏ qua module

import uvicorn  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamablehttp_client  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from app import sandbox_mcp  # noqa: E402

RUN = {
    "id": 7,
    "rate_limit_rps": 2.0,
    "ident_header_name": "X-Bug-Bounty",
    "ident_header_value": "HackerOne-tester",
    "scope_snapshot": [{"asset_identifier": "agilebits.com", "asset_type": "URL"}],
    "allow_non_prod": False,
}


class StubPool:
    """Đủ vỏ cho resolve_run — sandbox core bị thay bằng stub khi cần."""

    async def fetchrow(self, sql, *params):
        return RUN


async def _serve(app: FastAPI):
    """Uvicorn thật trên port ngẫu nhiên; trả (task, port) — caller stop task."""
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    return server, task, server.servers[0].sockets[0].getsockname()[1]


async def _mcp_app(monkeypatch, verify_impl, key="test-key"):
    """FastAPI app fresh (FastMCP instance riêng — session manager chỉ chạy 1
    lần/instance) với run_in_sandbox được thay bằng `verify_impl`."""
    sandbox_mcp.bind_pool(StubPool())
    monkeypatch.setattr(sandbox_mcp, "_run_in_sandbox", verify_impl)
    monkeypatch.setattr(sandbox_mcp.settings, "sandbox_mcp_key", key)

    server = sandbox_mcp.build_mcp()

    @asynccontextmanager
    async def lifespan(app):
        async with server.session_manager.run():
            yield

    app = FastAPI(lifespan=lifespan)
    app.mount("/mcp", sandbox_mcp.BearerAuthMiddleware(
        server.streamable_http_app(), key
    ))
    return app


def _ok_verify(calls: list[dict]):
    async def verify(script, target, timeout=None, run_id=None):
        calls.append({"script": script, "target": target, "timeout": timeout,
                      "run_id": run_id})
        return {
            "session_id": 1, "run_id": run_id, "target": target,
            "status": "ok", "exit_code": 0, "stdout": "payload output",
            "stderr": "", "reason": None,
            "egress": [{"destination": "agilebits.com:443", "scheme": "https",
                        "decision": "allowed", "reason": None}],
            "blocked": 0,
        }

    return verify


# ───────────────────────────── auth middleware ─────────────────────────────


def test_mcp_asgi_app_rejects_without_bearer(monkeypatch):
    monkeypatch.setattr(sandbox_mcp.settings, "sandbox_mcp_key", "secret-key")
    client = TestClient(sandbox_mcp.mcp_asgi_app())
    assert client.post("/mcp", json={}).status_code == 401
    assert (
        client.post(
            "/mcp", json={}, headers={"Authorization": "Bearer wrong"}
        ).status_code
        == 401
    )
    # đúng key → đi vào MCP app (lỗi MCP, không còn 401 auth)
    res = client.post(
        "/mcp", json={}, headers={"Authorization": "Bearer secret-key"}
    )
    assert res.status_code != 401


def test_mcp_asgi_app_fail_closed_when_key_empty(monkeypatch):
    """SANDBOX_MCP_KEY rỗng → từ chối TẤT CẢ kể cả bearer rỗng."""
    monkeypatch.setattr(sandbox_mcp.settings, "sandbox_mcp_key", "")
    client = TestClient(sandbox_mcp.mcp_asgi_app())
    assert client.post("/mcp", json={}).status_code == 401


# ───────────────────── round-trip MCP protocol thật ─────────────────────


@pytest.mark.asyncio
async def test_run_in_sandbox_over_mcp_http(monkeypatch):
    """Hermes-side flow: MCP client (streamable HTTP) list_tools + call_tool
    run_in_sandbox → kết quả verify session dạng JSON."""
    calls: list[dict] = []
    app = await _mcp_app(monkeypatch, _ok_verify(calls))
    server, task, port = await _serve(app)
    try:
        headers = {"Authorization": "Bearer test-key"}
        async with streamablehttp_client(
            f"http://127.0.0.1:{port}/mcp", headers=headers
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert [t.name for t in tools.tools] == ["run_in_sandbox"]

                result = await session.call_tool(
                    "run_in_sandbox",
                    {"script": "curl -sS https://agilebits.com",
                     "target": "agilebits.com", "timeout": 60, "run_id": 7},
                )
                assert result.isError is False
                data = json.loads(result.content[0].text)
                assert data["status"] == "ok"
                assert data["run_id"] == 7
                assert data["egress"][0]["decision"] == "allowed"
                # tham số đi đủ vào sandbox core
                assert calls == [{
                    "script": "curl -sS https://agilebits.com",
                    "target": "agilebits.com",
                    "timeout": 60,
                    "run_id": 7,
                }]
    finally:
        server.should_exit = True
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_run_in_sandbox_reports_blocked_status(monkeypatch):
    """Target ngoài Scope: tool TRẢ JSON status 'blocked' (không raise) — agent
    đọc được lý do ngay trong hội thoại."""

    async def blocked_verify(script, target, timeout=None, run_id=None):
        return {
            "session_id": 2, "run_id": run_id, "target": target,
            "status": "blocked", "exit_code": None, "stdout": "", "stderr": "",
            "reason": "evil.com không thuộc Scope của Run", "egress": [],
            "blocked": 0,
        }

    app = await _mcp_app(monkeypatch, blocked_verify)
    server, task, port = await _serve(app)
    try:
        headers = {"Authorization": "Bearer test-key"}
        async with streamablehttp_client(
            f"http://127.0.0.1:{port}/mcp", headers=headers
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "run_in_sandbox",
                    {"script": "curl http://evil.com", "target": "evil.com"},
                )
                data = json.loads(result.content[0].text)
                assert data["status"] == "blocked"
                assert "không thuộc Scope" in data["reason"]
    finally:
        server.should_exit = True
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_run_in_sandbox_requires_auth_over_wire(monkeypatch):
    """Trên wire thật: MCP client thiếu bearer → không kết nối được tools."""
    app = await _mcp_app(monkeypatch, _ok_verify([]))
    server, task, port = await _serve(app)
    try:
        with pytest.raises(Exception):
            async with streamablehttp_client(
                f"http://127.0.0.1:{port}/mcp"  # không headers
            ) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
    finally:
        server.should_exit = True
        await asyncio.gather(task, return_exceptions=True)


def test_base64_payload_shape():
    # username mà proxy parse (hợp khối với egress.parse_proxy_user)
    from app.egress import parse_proxy_user

    user, token = "sbx-42", "abcd"
    raw = base64.b64encode(f"{user}:{token}".encode()).decode()
    decoded_user = base64.b64decode(raw).decode().partition(":")[0]
    assert parse_proxy_user(decoded_user) == 42
