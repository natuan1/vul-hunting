"""Test pipeline vòng xác minh open redirect (ticket #12) — orchestration.

Pipeline với probe giả (thay `run_verify_session`): Candidate class redirect
→ status verifying → baseline capture → PoC → diff → confidence ≥ ngưỡng
thành Finding (verified) kèm evidence diff; ngược lại rejected kèm lý do +
pattern log. Âm tính: WAF-block và escaped response KHÔNG được báo thật.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_verify_pipeline.py -q
"""

import json

import pytest

from app import config
from app.verify import PROBE_MARKER, run_redirect_verification
from fakes import FakePool

CANARY = "https://canary.example/vulhunt-poc"

CANDIDATE = {
    "id": 3,
    "run_id": 1,
    "target": "https://app.other.com/redirect?next=https://app.other.com/home",
    "class": "redirect",
    "param": "next",
    "template_id": "open-redirect",
    "title": "Open Redirect",
    "severity": "medium",
    "matcher_name": "regex",
    "status": "new",
    "evidence_path": None,
    "first_seen": "2026-01-01T00:00:00Z",
}


def _probe_stdout(status: int, location: str = "", body: str = "ok") -> str:
    profile = {
        "url": "https://app.other.com/redirect",
        "status": status,
        "headers": {"content-type": "text/html", **({"location": location} if location else {})},
        "content_type": "text/html",
        "body_length": len(body),
        "body": body,
    }
    return f"{PROBE_MARKER}\n{json.dumps(profile)}\n"


class FakeProbe:
    """Probe giả: map thứ tự lần gọi → stdout (baseline rồi PoC), ghi lại
    script + target để khẳng định mọi payload chạy qua seam sandbox."""

    def __init__(self, stdouts: list[str]):
        self.stdouts = stdouts
        self.calls: list[tuple[str, str]] = []
        self.next_id = iter(range(101, 200))

    async def __call__(self, script: str, target: str) -> dict:
        self.calls.append((script, target))
        return {
            "session_id": next(self.next_id),
            "status": "ok",
            "stdout": self.stdouts[len(self.calls) - 1] if len(self.calls) <= len(self.stdouts) else "",
            "stderr": "",
        }


def _candidate_updates(pool: FakePool) -> list[tuple]:
    return [p for _, sql, p in pool.executes if "UPDATE candidates" in sql and "status" in sql]


@pytest.fixture(autouse=True)
def _isolated_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))
    monkeypatch.setattr(config.settings, "verify_confidence_threshold", 0.85)


# ── dương tính: target mô phỏng vulnerable → Candidate thành Finding ──


@pytest.mark.asyncio
async def test_target_vulnerable_thành_finding_verified_có_evidence_diff():
    probe = FakeProbe([
        _probe_stdout(200, body="<html>home</html>"),                    # baseline
        _probe_stdout(302, location=CANARY, body=""),                    # PoC
    ])
    pool = FakePool()
    summary = await run_redirect_verification(pool, CANDIDATE, payload=CANARY, probe=probe)

    # đúng 2 lần probe (baseline + PoC), KHÔNG request nào chạy ngoài sandbox
    assert len(probe.calls) == 2
    scripts = [s for s, _ in probe.calls]
    assert all(PROBE_MARKER in s for s in scripts)
    # baseline vô hại (giá trị benign), PoC mang canary — cùng URL, khác giá trị param
    from app.verify import BENIGN_PARAM_VALUE, inject_param

    baseline_url = inject_param(CANDIDATE["target"], "next", BENIGN_PARAM_VALUE)
    poc_url = inject_param(CANDIDATE["target"], "next", CANARY)
    assert baseline_url in scripts[0] and poc_url not in scripts[0]
    assert poc_url in scripts[1]

    assert summary["verdict"] == "verified"
    assert summary["score"] >= 0.85
    assert summary["threshold"] == 0.85
    assert summary["baseline_session_id"] == 101
    assert summary["verify_session_id"] == 102

    # UPDATE lifecycle: verifying rồi verdict + confidence + evidence path
    updates = _candidate_updates(pool)
    assert len(updates) == 2
    verifying, final = updates
    assert verifying[1] == "verifying"
    assert final[0] == 3  # candidate id
    assert final[1] == "verified"
    assert final[2] >= 0.85  # confidence
    assert final[3] == 0.85  # threshold ghi lại theo lần chấm
    assert final[4] is None  # reject_reason
    assert final[5] and "verify/003.json" in final[5]
    assert final[6] == 102  # verify_session_id (PoC)
    assert final[7] == 101  # baseline_session_id

    # evidence file thật: baseline + PoC + diff
    content = json.loads(open(final[5], encoding="utf-8").read())
    assert content["baseline"]["status"] == 200
    assert content["poc"]["status"] == 302
    assert content["analysis"]["diff"]["location"]["poc"] == CANARY
    assert content["analysis"]["patterns"]  # pattern log


# ── âm tính: WAF-block và escaped response → rejected đúng ──


@pytest.mark.asyncio
async def test_âm_tính_waf_block_rejected_không_báo_thật():
    probe = FakeProbe([
        _probe_stdout(200, body="<html>home</html>"),
        _probe_stdout(403, body="Request blocked — Cloudflare Ray ID"),
    ])
    pool = FakePool()
    summary = await run_redirect_verification(pool, CANDIDATE, payload=CANARY, probe=probe)

    assert summary["verdict"] == "rejected"
    assert "waf_block" in summary["patterns"]
    assert summary["score"] < 0.85
    verifying, final = _candidate_updates(pool)
    assert verifying[1] == "verifying"
    assert final[1] == "rejected"
    assert "WAF" in final[4] or "waf" in final[4].lower()  # reject_reason


@pytest.mark.asyncio
async def test_âm_tính_payload_escaped_rejected_không_báo_thật():
    from urllib.parse import quote

    body = f"redirect to {quote(CANARY, safe='')} is not allowed"
    probe = FakeProbe([
        _probe_stdout(200, body="<html>home</html>"),
        _probe_stdout(200, body=body),
    ])
    pool = FakePool()
    summary = await run_redirect_verification(pool, CANDIDATE, payload=CANARY, probe=probe)

    assert summary["verdict"] == "rejected"
    assert "payload_escaped" in summary["patterns"]
    assert _candidate_updates(pool)[-1][1] == "rejected"


# ── các nhánh lifecycle khác ──


@pytest.mark.asyncio
async def test_probe_đọc_không_được_rejected_probe_error():
    probe = FakeProbe(["stdout rác không có marker", "cũng rác"])
    pool = FakePool()
    summary = await run_redirect_verification(pool, CANDIDATE, payload=CANARY, probe=probe)
    assert summary["verdict"] == "rejected"
    assert "probe_error" in summary["patterns"]
    assert _candidate_updates(pool)[-1][1] == "rejected"


@pytest.mark.asyncio
async def test_candidate_không_có_param_rejected_không_chạy_probe():
    probe = FakeProbe([])
    pool = FakePool()
    candidate = {**CANDIDATE, "param": ""}
    summary = await run_redirect_verification(pool, candidate, payload=CANARY, probe=probe)
    assert summary["verdict"] == "rejected"
    assert "no_param" in summary["patterns"]
    assert probe.calls == []  # không có gì cả baseline lẫn PoC


@pytest.mark.asyncio
async def test_target_bị_block_trả_verifying_về_new_và_raise():
    from app.verify import ProbeBlocked

    async def blocked(script, target):
        return {"session_id": 9, "status": "blocked", "stdout": "",
                "stderr": "", "reason": "evil.com không thuộc Scope của Run"}

    pool = FakePool()
    with pytest.raises(ProbeBlocked):
        await run_redirect_verification(pool, CANDIDATE, payload=CANARY, probe=blocked)
    updates = _candidate_updates(pool)
    assert updates[-1][1] == "new"  # trả lifecycle về như cũ, KHÔNG verdict


@pytest.mark.asyncio
async def test_payload_mặc_định_lấy_canary_từ_settings(monkeypatch):
    monkeypatch.setattr(config.settings, "verify_canary_url", "https://mac-dinh.example/c")
    probe = FakeProbe([
        _probe_stdout(200, body="x"),
        _probe_stdout(302, location="https://mac-dinh.example/c", body=""),
    ])
    pool = FakePool()
    summary = await run_redirect_verification(pool, CANDIDATE, probe=probe)
    assert summary["payload"] == "https://mac-dinh.example/c"
    assert summary["verdict"] == "verified"


@pytest.mark.asyncio
async def test_class_khác_redirect_chấp_nhận_nhưng_endpoint_tự_chặn():
    # pipeline không phân biệt class (endpoint/MCP mới chặn) — smoke: vẫn chạy
    probe = FakeProbe([
        _probe_stdout(200, body="x"),
        _probe_stdout(302, location=CANARY, body=""),
    ])
    pool = FakePool()
    candidate = {**CANDIDATE, "class": "xss"}
    summary = await run_redirect_verification(pool, candidate, payload=CANARY, probe=probe)
    assert summary["verdict"] == "verified"
