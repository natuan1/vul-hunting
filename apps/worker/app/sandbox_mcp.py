"""MCP server của worker (ticket #11, #12, ADR-0003) — expose tool
`run_in_sandbox` + `verify_open_redirect` cho hermes qua MCP toolset.

hermes cấu hình (config/hermes/config.yaml):

    mcp_servers:
      sandbox:
        url: "http://worker:8000/mcp"
        headers:
          Authorization: "Bearer ${SANDBOX_MCP_KEY}"

Hermes nhận tool với prefix toolset: `mcp_sandbox_run_in_sandbox`,
`mcp_sandbox_verify_open_redirect`. Mỗi lần `run_in_sandbox` = 1 verify
session = 1 container --rm mới tinh (app/sandbox.py); `verify_open_redirect`
chạy trọn vòng baseline → PoC → diff → confidence (app/verify.py) — mọi
payload đều chạy trong sandbox, agent không bao giờ thực thi trực tiếp.
Endpoint require bearer key — rỗng thì fail-closed (401 mọi call).
"""

import hashlib
import hmac
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from . import detect, httpverify, oob, sandbox, takeover, verify
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


async def _verify_open_redirect(
    candidate_id: int,
    payload: str | None = None,
) -> dict[str, Any]:
    """Phần thực thi của tool verify (tách khỏi decorator để test monkeypatch)."""
    if _pool is None:
        raise RuntimeError("worker chưa sẵn sàng (pool chưa bind)")
    candidate = await detect.get_candidate(_pool, candidate_id)
    if candidate is None:
        return {
            "status": "error",
            "reason": f"Candidate #{candidate_id} không tồn tại",
        }
    if candidate["class"] != "redirect":
        return {
            "status": "error",
            "reason": (
                f"Candidate #{candidate_id} thuộc class '{candidate['class']}' — "
                "tool này chỉ dành cho class 'redirect' (open redirect)"
            ),
        }
    result = await verify.run_redirect_verification(_pool, candidate, payload=payload)
    sid = result.get("verify_session_id")
    return {
        **result,
        "note": (
            "evidence diff (baseline + PoC + pattern log): "
            f"GET /candidates/{candidate_id}/verify-evidence · egress log truy "
            f"theo verify session #{sid} · ngưỡng confidence: "
            f"{result.get('threshold')}"
        ),
    }


async def _verify_oob(candidate_id: int) -> dict[str, Any]:
    """Phần thực thi của tool verify OOB (tách khỏi decorator để test monkeypatch)."""
    if _pool is None:
        raise RuntimeError("worker chưa sẵn sàng (pool chưa bind)")
    candidate = await detect.get_candidate(_pool, candidate_id)
    if candidate is None:
        return {
            "status": "error",
            "reason": f"Candidate #{candidate_id} không tồn tại",
        }
    if candidate["class"] not in oob.OOB_VERIFY_CLASSES:
        return {
            "status": "error",
            "reason": (
                f"Candidate #{candidate_id} thuộc class '{candidate['class']}' — "
                "tool này chỉ dành cho class blind "
                f"{', '.join(oob.OOB_VERIFY_CLASSES)} (xác minh bằng callback OOB)"
            ),
        }
    result = await oob.run_oob_verification(_pool, candidate)
    return {
        **result,
        "note": (
            "evidence OOB (callbacks + phân tích): "
            f"GET /candidates/{candidate_id}/oob-evidence · domain payload "
            f"riêng của Run: {result.get('domain')} · ngưỡng confidence: "
            f"{result.get('threshold')}"
        ),
    }


async def _verify_takeover(candidate_id: int) -> dict[str, Any]:
    """Phần thực thi của tool verify takeover (tách khỏi decorator để test monkeypatch)."""
    if _pool is None:
        raise RuntimeError("worker chưa sẵn sàng (pool chưa bind)")
    candidate = await detect.get_candidate(_pool, candidate_id)
    if candidate is None:
        return {
            "status": "error",
            "reason": f"Candidate #{candidate_id} không tồn tại",
        }
    if candidate["class"] != "takeover":
        return {
            "status": "error",
            "reason": (
                f"Candidate #{candidate_id} thuộc class '{candidate['class']}' — "
                "tool này chỉ dành cho class 'takeover' (subdomain takeover)"
            ),
        }
    result = await takeover.run_takeover_verification(_pool, candidate)
    return {
        **result,
        "note": (
            "evidence takeover (fingerprint probe + PoC page + deploy + confirm): "
            f"GET /candidates/{candidate_id}/verify-evidence · PoC page chứa "
            f"username '{result.get('username')}' + token one-shot — Finding CHỈ khi "
            "PoC được phục vụ qua subdomain; report thiếu PoC hoạt động bị đóng N/A"
        ),
    }


async def _verify_http(candidate_id: int, payload: str | None = None) -> dict[str, Any]:
    """Phần thực thi của tool verify batch A (tách khỏi decorator để test monkeypatch)."""
    if _pool is None:
        raise RuntimeError("worker chưa sẵn sàng (pool chưa bind)")
    candidate = await detect.get_candidate(_pool, candidate_id)
    if candidate is None:
        return {
            "status": "error",
            "reason": f"Candidate #{candidate_id} không tồn tại",
        }
    if candidate["class"] not in httpverify.HTTP_VERIFY_CLASSES:
        return {
            "status": "error",
            "reason": (
                f"Candidate #{candidate_id} thuộc class '{candidate['class']}' — "
                "tool này chỉ dành cho 7 lớp HTTP-only: "
                f"{', '.join(httpverify.HTTP_VERIFY_CLASSES)}"
            ),
        }
    result = await httpverify.run_http_verification(_pool, candidate, payload=payload)
    informational = result.get("verdict") == "informational"
    return {
        **result,
        "note": (
            "evidence HTTP (baseline + PoC + phân tích): "
            f"GET /candidates/{candidate_id}/verify-evidence · egress log truy theo "
            f"verify session #{result.get('verify_session_id')} · ngưỡng confidence: "
            f"{result.get('threshold')}"
        ) + (
            " · class 'headers' CHỈ informational — KHÔNG tự tạo report, chỉ hiển thị"
            if informational else ""
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

    @server.tool()
    async def verify_open_redirect(
        candidate_id: int,
        payload: str | None = None,
    ) -> dict[str, Any]:
        """Xác minh agentic 1 Candidate class 'redirect' (open redirect) — đi
        trọn vòng: baseline capture (request vô hại) → soạn PoC từ param của
        Candidate → chạy CẢ HAI trong sandbox → response diff so với baseline
        (WAF block / payload bị escape / payload trong error log = false
        positive) → chấm confidence 0.0–1.0. Score ≥ ngưỡng (mặc định 0.85)
        → Candidate thành Finding (status `verified`) kèm evidence diff; dưới
        ngưỡng → `rejected` kèm lý do + pattern log. KHÔNG bao giờ chạy payload
        trực tiếp — mọi request đi qua container sandbox ephemeral.

        Args:
            candidate_id: id của Candidate class 'redirect' cần xác minh.
            payload: URL canary dùng làm payload PoC (bỏ trống → canary mặc định).

        Returns JSON: candidate_id, verdict (verified|rejected), score,
        threshold, reason, signals, patterns (pattern log), payload,
        evidence_path (file JSON baseline+PoC+diff), baseline_session_id,
        verify_session_id. Status 'error' nếu candidate không tồn tại/sai class.
        """
        return await _verify_open_redirect(candidate_id, payload)

    @server.tool()
    async def verify_oob_ssrf(candidate_id: int) -> dict[str, Any]:
        """Xác minh agentic 1 Candidate blind class 'ssrf' bằng OOB callback
        (ticket #13) — đi trọn vòng: đăng ký interactsh RIÊNG cho Run (domain
        payload xoay vòng per-Run, không tái sử dụng chéo) → payload
        `http://<token>.<domain>` chèn vào param của Candidate → baseline +
        PoC chạy TRONG sandbox (target có thể fetch payload bằng server-side)
        → chờ/poll callback từ Internet (~1 phút) → callback về = server-side
        đã fetch payload → `verified` kèm evidence OOB (source, protocol,
        timestamp, raw interaction); hết cửa sổ chờ không callback →
        `rejected` kèm lý do. KHÔNG bao giờ chạy payload trực tiếp.

        Args:
            candidate_id: id của Candidate class 'ssrf' cần xác minh.

        Returns JSON: candidate_id, verdict (verified|rejected), score,
        threshold, reason, signals, patterns, payload, token, domain,
        callbacks (danh sách callback đã gắn), evidence_path. Status 'error'
        nếu candidate không tồn tại/sai class.
        """
        return await _verify_oob(candidate_id)

    @server.tool()
    async def verify_subdomain_takeover(candidate_id: int) -> dict[str, Any]:
        """Xác minh agentic 1 Candidate class 'takeover' (subdomain takeover,
        ticket #14) — đi trọn vòng với tiêu chí "PHẢI chứng minh kiểm soát"
        (policy của nhiều Program, vd Goldman Sachs):
        1. Fingerprint probe trong sandbox: service còn bỏ hoang theo CNAME
           (GitHub Pages, S3, Heroku…)? Mất fingerprint → rejected.
        2. Soạn PoC page chứa USERNAME ĐỊNH DANH của user + token one-shot;
           deploy qua hosting khả dụng (TAKEOVER_HOSTING: github-pages/s3;
           chưa cấu hình → needs_manual kèm hướng dẫn xác minh tay).
        3. Confirm probe trong sandbox: PoC page được PHỤC VỤ QUA SUBDOMAIN →
           kiểm soát được chứng minh → `verified` (Finding). Fingerprint match
           nhưng không deploy/confirm được → `rejected` (claim_failed /
           no_control) — report takeover thiếu PoC hoạt động sẽ bị đóng N/A và
           ảnh hưởng reput, KHÔNG BAO GIỜ report khi chưa có PoC hoạt động.

        Args:
            candidate_id: id của Candidate class 'takeover' cần xác minh.

        Returns JSON: candidate_id, verdict (verified|rejected|needs_manual),
        score, threshold, reason, signals, patterns, cname, service, claim_host,
        poc_url, token, username, deploy, guidance, evidence_path,
        baseline_session_id, verify_session_id. Status 'error' nếu candidate
        không tồn tại/sai class.
        """
        return await _verify_takeover(candidate_id)

    @server.tool()
    async def verify_http_class(
        candidate_id: int,
        payload: str | None = None,
    ) -> dict[str, Any]:
        """Xác minh agentic 1 Candidate thuộc 1 trong 7 lớp HTTP-only của batch A
        (ticket #15): cors (CORS misconfig), dirlist (directory listing),
        graphql (introspection), crlf (CRLF injection), ssti, headers (missing
        security headers), disclosure (info disclosure/debug endpoints) — đi
        trọn vòng: baseline capture (request vô hại) → PoC tuỳ lớp (Origin
        canary cho cors, `__schema` cho graphql, `%0d%0a` + header canary cho
        crlf, `{{7*7}}` cho ssti, path con cho dirlist, root host cho
        disclosure) → chạy CẢ HAI trong sandbox → phân tích so baseline theo
        hướng khai thác được (WAF block / payload bị escape / marker có sẵn ở
        baseline = false positive) → confidence 0.0–1.0; score ≥ ngưỡng (mặc
        định 0.85) → Finding kèm evidence; dưới ngưỡng → `rejected` kèm lý do.
        RIÊNG class 'headers': CHỈ informational — thu evidence danh sách
        headers thiếu + ép severity thấp, KHÔNG đổi status, KHÔNG tự tạo report
        (chỉ hiển thị cho người dùng cân nhắc).

        Args:
            candidate_id: id của Candidate thuộc 1 trong 7 lớp HTTP-only.
            payload: payload tuỳ lớp (origin canary cho cors, giá trị chèn cho
              crlf/ssti; bỏ trống → canary mặc định).

        Returns JSON: candidate_id, class, verdict
        (verified|rejected|informational), score, threshold, reason, signals,
        patterns, detail (headers thiếu/marker trúng…), reportable,
        evidence_path, baseline_session_id, verify_session_id. Status 'error'
        nếu candidate không tồn tại/sai class.
        """
        return await _verify_http(candidate_id, payload)

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
