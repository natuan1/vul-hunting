"""Test pipeline verify batch A (ticket #15) — 7 lớp HTTP-only với probe giả.

Mỗi lớp: candidate class tương ứng → status verifying → baseline + PoC qua
sandbox (FakeProbe) → analyze → verdict + evidence. Dương tính: target mô
phỏng vulnerable → Finding (verified) kèm evidence; `headers` chỉ
informational (KHÔNG đổi status — không report). Âm tính: WAF/escaped/giống
baseline → rejected, không báo thật.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_httpverify_pipeline.py -q
"""

import json

import pytest

from app import config
from app.httpverify import HTTP_VERIFY_CLASSES, run_http_verification
from app.verify import PROBE_MARKER, ProbeBlocked
from fakes import FakePool

ORIGIN = "https://canary-vulhunt.example"

CANDIDATE = {
    "id": 11,
    "run_id": 1,
    "target": "https://app.other.com/page",
    "class": "cors",
    "param": "",
    "template_id": "cors-misconfig",
    "title": "CORS Misconfiguration",
    "severity": "high",
    "matcher_name": "regex",
    "status": "new",
    "evidence_path": None,
    "first_seen": "2026-01-01T00:00:00Z",
}

PARAM_CANDIDATE = {
    **CANDIDATE,
    "id": 12,
    "target": "https://app.other.com/search?q=x",
    "param": "q",
}


def _probe_stdout(status=200, headers=None, body="ok"):
    headers = headers or {"content-type": "text/html"}
    profile = {
        "url": "https://app.other.com/page",
        "status": status,
        "headers": headers,
        "content_type": headers.get("content-type", "text/html"),
        "body_length": len(body),
        "body": body,
    }
    return f"{PROBE_MARKER}\n{json.dumps(profile)}\n"


class FakeProbe:
    """Probe giả: thứ tự lần gọi → stdout; ghi lại (script, target)."""

    def __init__(self, stdouts):
        self.stdouts = stdouts
        self.calls = []
        self.next_id = iter(range(201, 300))

    async def __call__(self, script, target):
        self.calls.append((script, target))
        return {
            "session_id": next(self.next_id),
            "status": "ok",
            "stdout": self.stdouts[len(self.calls) - 1] if len(self.calls) <= len(self.stdouts) else "",
            "stderr": "",
        }


def _updates(pool):
    return [p for _, sql, p in pool.executes if "UPDATE candidates" in sql and "$2" in sql]


def _verdict_updates(pool):
    return [p for _, sql, p in pool.executes if "UPDATE candidates SET status" in sql]


def _info_updates(pool):
    return [p for _, sql, p in pool.executes if "UPDATE candidates SET severity" in sql]


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))
    monkeypatch.setattr(config.settings, "verify_confidence_threshold", 0.85)
    monkeypatch.setattr(config.settings, "verify_cors_origin", ORIGIN)


# ── dương tính từng lớp: target mô phỏng vulnerable → Finding ──


@pytest.mark.asyncio
async def test_cors_verified_khi_reflect_origin_và_credentials():
    probe = FakeProbe([
        _probe_stdout(200, body="home"),  # baseline
        _probe_stdout(200, headers={
            "content-type": "text/html",
            "access-control-allow-origin": ORIGIN,
            "access-control-allow-credentials": "true",
        }, body="home"),
    ])
    pool = FakePool()
    summary = await run_http_verification(pool, CANDIDATE, probe=probe)

    assert summary["verdict"] == "verified" and summary["score"] >= 0.85
    assert summary["class"] == "cors" and summary["reportable"] is True
    # PoC mang Origin canary — qua đúng 2 lần probe sandbox
    assert len(probe.calls) == 2
    assert f'"origin": "{ORIGIN}"' in probe.calls[1][0].replace(", ", ", ")
    verifying, final = _verdict_updates(pool)
    assert verifying[1] == "verifying"
    assert final[0] == 11 and final[1] == "verified"
    assert final[5] and "verify/011.json" in final[5]
    evidence = json.loads(open(final[5], encoding="utf-8").read())
    assert evidence["schema"] == "vulhunt.httpverify-evidence/1"
    assert evidence["analysis"]["signals"] == ["acao_reflects_origin", "acac_true"]


@pytest.mark.asyncio
async def test_dirlist_verified_khi_listing_baseline_không():
    probe = FakeProbe([
        _probe_stdout(404, body="not found"),  # baseline path con
        _probe_stdout(200, body="<title>Index of /backup</title><a href='x.sql'>x.sql</a>"),
    ])
    pool = FakePool()
    summary = await run_http_verification(
        pool, {**CANDIDATE, "class": "dirlist", "id": 13}, probe=probe
    )
    assert summary["verdict"] == "verified" and "listing_markers" in summary["signals"]
    assert _verdict_updates(pool)[-1][1] == "verified"


@pytest.mark.asyncio
async def test_graphql_verified_khi_introspection_mở():
    probe = FakeProbe([
        _probe_stdout(200, headers={"content-type": "application/json"},
                      body=json.dumps({"data": {"__typename": "Query"}})),
        _probe_stdout(200, headers={"content-type": "application/json"},
                      body=json.dumps({"data": {"__schema": {"types": [{"name": "User"}]}}})),
    ])
    pool = FakePool()
    summary = await run_http_verification(
        pool, {**CANDIDATE, "class": "graphql", "id": 14}, probe=probe
    )
    assert summary["verdict"] == "verified" and "introspection_enabled" in summary["signals"]
    assert "__schema" in probe.calls[1][0]  # PoC query schema qua sandbox


@pytest.mark.asyncio
async def test_crlf_verified_khi_header_canary_xuất_hiện():
    probe = FakeProbe([
        _probe_stdout(200, body="home"),
        _probe_stdout(302, headers={"location": "/", "x-vulhunt-injection": "1"}, body=""),
    ])
    pool = FakePool()
    summary = await run_http_verification(
        pool, {**PARAM_CANDIDATE, "class": "crlf", "id": 15}, probe=probe
    )
    assert summary["verdict"] == "verified" and "header_injected" in summary["signals"]
    # PoC URL chứa CRLF encoded trong param q
    assert "%0D%0A" in probe.calls[1][0].upper()


@pytest.mark.asyncio
async def test_ssti_verified_khi_math_evaluated():
    probe = FakeProbe([
        _probe_stdout(200, body="hello world"),
        _probe_stdout(200, body="hello 49 world"),
    ])
    pool = FakePool()
    summary = await run_http_verification(
        pool, {**PARAM_CANDIDATE, "class": "ssti", "id": 16}, probe=probe
    )
    assert summary["verdict"] == "verified" and "math_evaluated" in summary["signals"]
    assert "%7B%7B7%2A7%7D%7D" in probe.calls[1][0] or "{{7*7}}" in probe.calls[1][0]


@pytest.mark.asyncio
async def test_headers_chỉ_informational_không_đổi_status():
    probe = FakeProbe([
        _probe_stdout(200, body="home"),
        _probe_stdout(200, body="home"),
    ])
    pool = FakePool()
    summary = await run_http_verification(
        pool, {**CANDIDATE, "class": "headers", "id": 17}, probe=probe
    )
    # informational: KHÔNG verdict verified/rejected — chỉ hiển thị + evidence
    assert summary["verdict"] == "informational"
    assert summary["reportable"] is False
    assert summary["detail"]["missing"]  # CSP vắng trong probe stdout
    assert _verdict_updates(pool) == []  # không đổi status
    info = _info_updates(pool)[-1]
    assert info[0] == 17 and info[1] == "low"  # severity ép trần low
    assert "verify/017.json" in info[2]
    evidence = json.loads(open(info[2], encoding="utf-8").read())
    assert evidence["analysis"]["verdict"] == "informational"
    assert "content-security-policy" in evidence["analysis"]["detail"]["missing"]


@pytest.mark.asyncio
async def test_disclosure_verified_khi_secret_mới_xuất_hiện():
    probe = FakeProbe([
        _probe_stdout(200, body="<html>trang chủ</html>"),          # baseline root
        _probe_stdout(200, body="DB_PASSWORD=hunter2\nDEBUG=true"),  # /.env
    ])
    pool = FakePool()
    summary = await run_http_verification(
        pool, {**CANDIDATE, "class": "disclosure", "id": 18,
               "target": "https://app.other.com/.env"}, probe=probe
    )
    assert summary["verdict"] == "verified" and "sensitive_content" in summary["signals"]
    assert probe.calls[0][0].count("https://app.other.com/") == 1  # baseline là root


# ── âm tính từng lớp: WAF / escaped / giống baseline / có sẵn → rejected ──


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,stdouts,pattern", [
    ("cors",
     [{"status": 200, "body": "home"},
      {"status": 403, "body": "Request blocked — Cloudflare"}],
     "waf_block"),
    ("dirlist",
     [{"status": 404, "body": "not found"},
      {"status": 200, "body": "<html>trang thường</html>"}],
     "not_a_listing"),
    ("graphql",
     [{"status": 200, "headers": {"content-type": "application/json"},
       "body": json.dumps({"data": {"__typename": "Query"}})},
      {"status": 200, "headers": {"content-type": "application/json"},
       "body": json.dumps({"errors": [{"message": "GraphQL introspection is not allowed"}]})}],
     "introspection_disabled"),
    ("crlf",
     [{"status": 200, "body": "home"},
      {"status": 200, "body": "value %0d%0aX-Vulhunt-Injection%3A%201 echoed"}],
     "payload_escaped"),
    ("ssti",
     [{"status": 200, "body": "hello world"},
      {"status": 200, "body": "hello {{7*7}} world"}],
     "payload_escaped"),
    ("disclosure",
     [{"status": 200, "body": "<html>trang chủ</html>"},
      {"status": 404, "body": "not found"}],
     "endpoint_missing"),
])
async def test_âm_tính_từng_lớp_rejected_không_báo_thật(cls, stdouts, pattern):
    probe = FakeProbe([_probe_stdout(**s) for s in stdouts])
    candidate = {**(PARAM_CANDIDATE if cls in ("crlf", "ssti") else CANDIDATE),
                 "class": cls, "id": 19}
    pool = FakePool()
    summary = await run_http_verification(pool, candidate, probe=probe)
    assert summary["verdict"] == "rejected"
    assert pattern in summary["patterns"]
    assert summary["reportable"] is True
    assert _verdict_updates(pool)[-1][1] == "rejected"


@pytest.mark.asyncio
async def test_âm_tính_ssti_số_49_có_sẵn_ở_baseline():
    probe = FakeProbe([
        _probe_stdout(200, body="phòng 49"),   # baseline
        _probe_stdout(200, body="phòng 49"),
    ])
    pool = FakePool()
    summary = await run_http_verification(
        pool, {**PARAM_CANDIDATE, "class": "ssti", "id": 20}, probe=probe
    )
    assert summary["verdict"] == "rejected"
    assert "ambiguous_baseline" in summary["patterns"]


# ── lifecycle khác ──


@pytest.mark.asyncio
async def test_crlf_không_param_rejected_không_chạy_probe():
    probe = FakeProbe([])
    pool = FakePool()
    candidate = {**CANDIDATE, "class": "crlf", "param": ""}
    summary = await run_http_verification(pool, candidate, probe=probe)
    assert summary["verdict"] == "rejected"
    assert "no_param" in summary["patterns"]
    assert probe.calls == []


@pytest.mark.asyncio
async def test_probe_đọc_không_được_rejected_probe_error():
    probe = FakeProbe(["stdout rác", "cũng rác"])
    pool = FakePool()
    summary = await run_http_verification(pool, CANDIDATE, probe=probe)
    assert summary["verdict"] == "rejected"
    assert "probe_error" in summary["patterns"]
    assert _verdict_updates(pool)[-1][1] == "rejected"


@pytest.mark.asyncio
async def test_target_bị_chặn_trả_lifecycle_về_và_raise():
    async def blocked(script, target):
        return {"session_id": 9, "status": "blocked", "stdout": "", "stderr": "",
                "reason": "evil.example không thuộc Scope của Run"}

    pool = FakePool()
    with pytest.raises(ProbeBlocked):
        await run_http_verification(pool, CANDIDATE, probe=blocked)
    updates = _updates(pool)
    assert updates[-1][1] == "new"  # trả lifecycle về cũ, không verdict oan


@pytest.mark.asyncio
async def test_class_ngoài_batch_a_từ_chối():
    pool = FakePool()
    with pytest.raises(ValueError):
        await run_http_verification(pool, {**CANDIDATE, "class": "redirect"}, probe=FakeProbe([]))


def test_batch_a_đủ_7_lớp():
    assert len(HTTP_VERIFY_CLASSES) == 7
