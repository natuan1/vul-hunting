"""Test sinh report draft theo mẫu platform (ticket #18) — phần thuần + pipeline.

Finding (verified) → draft theo mẫu HackerOne (## Summary / ## Steps to
Reproduce / ## Impact / ## Supporting Material/References) hoặc Intigriti
(### Description / ### Steps to Reproduce / ### Impact / ### Proof of
Concept) — title, severity, steps, impact, PoC/evidence nhúng đúng chỗ.
Preview sửa + copy từng phần (lưu JSONB theo platform); đánh dấu `reported`
kèm link + ngày nộp. TRIPWIRE: module report KHÔNG import HTTP client nào —
không có đường code nào tự POST report lên platform (auto-submit là v2).

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_report.py -q
"""

import ast
import json
from pathlib import Path

import pytest

from app import config, report
from app.report import (
    PLATFORMS,
    ReportError,
    build_curl,
    build_draft,
    extract_bundle,
    format_markdown,
    get_report,
    mark_reported,
    save_report_draft,
)
from fakes import FakePool

# ─────────────────────────── fixtures dùng chung ───────────────────────────

CANDIDATE = {
    "id": 7,
    "run_id": 1,
    "target": "https://app.example.com/redirect?next=https://app.example.com/home",
    "class": "redirect",
    "param": "next",
    "template_id": "open-redirect",
    "title": "Open Redirect",
    "severity": "medium",
    "matcher_name": "regex",
    "status": "verified",
    "confidence": 0.95,
    "first_seen": "2026-01-01T00:00:00Z",
}

CANARY = "https://canary.example/poc"

BASELINE_URL = "https://app.example.com/redirect?next=https%3A//example.com/"
POC_URL = "https://app.example.com/redirect?next=https%3A//canary.example/poc"

VERIFY_EVIDENCE = {
    "schema": "vulhunt.verify-evidence/1",
    "target": CANDIDATE["target"],
    "param": "next",
    "payload": CANARY,
    "baseline": {
        "url": BASELINE_URL, "status": 200, "headers": {"content-type": "text/html"},
        "content_type": "text/html", "body_length": 1234, "body": "home",
        "error": None,
    },
    "poc": {
        "url": POC_URL, "status": 302,
        "headers": {"location": CANARY, "content-type": "text/html"},
        "content_type": "text/html", "body_length": 0, "body": "", "error": None,
    },
    "analysis": {
        "signals": ["location_redirect"],
        "patterns": ["location_redirect"],
        "score": 0.95,
        "verdict": "verified",
        "reason": "PoC được redirect thẳng tới payload",
        "diff": {"status": {"baseline": 200, "poc": 302}},
    },
}


@pytest.fixture(autouse=True)
def _isolated_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))
    return tmp_path


def _candidate_with(**over) -> dict:
    return {**CANDIDATE, **over}


# ─────────────────── extract_bundle: chuẩn hoá evidence ───────────────────


def test_extract_bundle_từ_verify_evidence_redirect():
    b = extract_bundle(None, VERIFY_EVIDENCE, None)
    assert b["poc_url"] == POC_URL
    assert b["baseline_url"] == BASELINE_URL
    assert b["poc_status"] == 302
    assert b["baseline_status"] == 200
    assert b["poc_location"] == CANARY
    assert b["payload"] == CANARY
    assert "location_redirect" in b["signals"]
    assert b["curl"]  # có curl command cho PoC


def test_extract_bundle_từ_takeover_evidence():
    take = {
        "schema": "vulhunt.takeover-evidence/1",
        "target": "lost.example.com",
        "cname": ["lost.example.com.cdn.github.io"],
        "fingerprint": {"service": "github-pages", "claim_host": "natuan1.github.io"},
        "poc": {"username": "natuan1", "token": "tok-1", "page": "<html>vulhunt</html>"},
        "deploy": {"provider": "github-pages", "url": "https://natuan1.github.io/tok-1/"},
        "confirm": {"status": 200, "url": "http://lost.example.com"},
        "analysis": {"signals": ["poc_served_via_subdomain"], "verdict": "verified", "score": 0.95},
    }
    b = extract_bundle(None, take, None)
    assert b["takeover"]["service"] == "github-pages"
    assert b["takeover"]["cname"] == ["lost.example.com.cdn.github.io"]
    assert b["takeover"]["poc_url"] == "https://natuan1.github.io/tok-1/"
    assert b["takeover"]["confirm_status"] == 200
    assert b["curl"]  # curl cho PoC page


def test_extract_bundle_từ_oob_evidence():
    oob = {
        "schema": "vulhunt.oob-evidence/1",
        "payload": "http://abc123.e.example.com",
        "registration": {"domain": "e.example.com"},
        "callbacks": [
            {"protocol": "http", "source": "1.2.3.4", "occurred_at": "2026-01-01T00:00:00Z"},
        ],
        "analysis": {"signals": ["oob_callback"], "verdict": "verified", "score": 0.9},
    }
    b = extract_bundle(None, None, oob)
    assert b["payload"] == "http://abc123.e.example.com"
    assert b["oob_domain"] == "e.example.com"
    assert len(b["callbacks"]) == 1
    assert b["callbacks"][0]["protocol"] == "http"


def test_extract_bundle_không_evidence_nào_vẫn_trả_bundle_rỗng():
    b = extract_bundle(None, None, None)
    assert b["poc_url"] is None
    assert b["callbacks"] == []
    assert b["takeover"] is None


# ─────────────────────── build_draft: 2 mẫu platform ───────────────────────


def test_build_draft_hackerone_đúng_mẫu():
    bundle = extract_bundle(None, VERIFY_EVIDENCE, None)
    draft = build_draft(_candidate_with(), bundle, "hackerone")
    assert draft["platform"] == "hackerone"
    assert set(draft["sections"]) == {
        "title", "severity", "summary", "steps_to_reproduce", "impact", "evidence",
    }
    md = draft["markdown"]
    assert "## Summary" in md
    assert "## Steps to Reproduce" in md
    assert "## Impact" in md
    assert "## Supporting Material/References" in md
    # title: label class + param + host
    assert "Open Redirect" in draft["sections"]["title"]
    assert "app.example.com" in draft["sections"]["title"]
    assert "`next`" in draft["sections"]["title"]


def test_build_draft_intigriti_đúng_mẫu():
    bundle = extract_bundle(None, VERIFY_EVIDENCE, None)
    draft = build_draft(_candidate_with(), bundle, "intigriti")
    assert draft["platform"] == "intigriti"
    md = draft["markdown"]
    assert "### Description" in md
    assert "### Steps to Reproduce" in md
    assert "### Impact" in md
    assert "### Proof of Concept" in md


def test_build_draft_platform_lạ_ném_lỗi():
    with pytest.raises(ReportError):
        build_draft(_candidate_with(), {}, "bugcrowd")


def test_build_draft_severity_được_map_cho_platform():
    # 'info' không tồn tại trên 2 platform → map về low
    draft = build_draft(_candidate_with(severity="info"), {}, "hackerone")
    assert draft["sections"]["severity"] == "low"
    draft = build_draft(_candidate_with(severity="critical"), {}, "intigriti")
    assert draft["sections"]["severity"] == "critical"


def test_build_draft_evidence_nhúng_đúng_chỗ():
    bundle = extract_bundle(None, VERIFY_EVIDENCE, None)
    draft = build_draft(_candidate_with(), bundle, "hackerone")
    steps = draft["sections"]["steps_to_reproduce"]
    evidence = draft["sections"]["evidence"]
    # PoC URL nằm trong steps
    assert POC_URL in steps
    assert CANARY in steps  # payload được nêu trong steps
    # curl + response diff nằm trong evidence
    assert "curl" in evidence
    assert POC_URL in evidence
    assert "302" in evidence  # status PoC
    assert "200" in evidence  # status baseline
    assert CANARY in evidence  # Location header PoC


def test_build_draft_không_có_verify_evidence_vẫn_sinh_draft_từ_candidate():
    draft = build_draft(_candidate_with(), extract_bundle(None, None, None), "hackerone")
    assert draft["sections"]["title"]
    assert draft["sections"]["steps_to_reproduce"]  # fallback từ target/matcher
    assert draft["sections"]["impact"]


def test_build_draft_takeover_dùng_poc_page_làm_steps():
    take = {
        "schema": "vulhunt.takeover-evidence/1",
        "target": "lost.example.com",
        "cname": ["lost.example.com.cdn.github.io"],
        "fingerprint": {"service": "github-pages", "claim_host": "natuan1.github.io"},
        "poc": {"username": "natuan1", "token": "tok-1"},
        "deploy": {"provider": "github-pages", "url": "https://natuan1.github.io/tok-1/"},
        "confirm": {"status": 200},
        "analysis": {"signals": ["poc_served_via_subdomain"], "verdict": "verified"},
    }
    draft = build_draft(
        _candidate_with(class_="takeover", target="http://lost.example.com"),
        extract_bundle(None, take, None), "hackerone",
    )
    steps = draft["sections"]["steps_to_reproduce"]
    assert "lost.example.com" in steps
    assert "github-pages" in steps
    assert "https://natuan1.github.io/tok-1/" in steps


def test_build_draft_oob_nêu_callback_trong_evidence():
    oob = {
        "schema": "vulhunt.oob-evidence/1",
        "payload": "http://abc123.e.example.com",
        "registration": {"domain": "e.example.com"},
        "callbacks": [{"protocol": "dns", "source": "10.0.0.1"}],
        "analysis": {"signals": ["oob_callback"], "verdict": "verified"},
    }
    draft = build_draft(
        _candidate_with(class_="ssrf", target="https://app.example.com/fetch"),
        extract_bundle(None, None, oob), "hackerone",
    )
    evidence = draft["sections"]["evidence"]
    assert "abc123.e.example.com" in evidence
    assert "dns" in evidence


# ───────────────────────────── format_markdown ─────────────────────────────


def test_format_markdown_theo_heading_platform():
    sections = {
        "title": "T", "severity": "high", "summary": "S", "steps_to_reproduce": "1. X",
        "impact": "I", "evidence": "E",
    }
    h1 = format_markdown(sections, "hackerone")
    assert "## Summary" in h1 and "## Supporting Material/References" in h1
    ig = format_markdown(sections, "intigriti")
    assert "### Description" in ig and "### Proof of Concept" in ig
    # severity line nằm trong markdown cả 2
    assert "high" in h1 and "high" in ig


# ─────────────────────────────── build_curl ────────────────────────────────


def test_build_curl_quote_url():
    cmd = build_curl("https://a.com/x?q=a b&y=1")
    assert cmd.startswith("curl")
    assert "'https://a.com/x?q=a b&y=1'" in cmd  # bọc quote đơn


# ────────────── tripwire: KHÔNG có đường code tự POST lên platform ──────────


def test_module_report_không_import_http_client_nào():
    """Auto-submit là v2 (phải hỏi user + quyền API write) — v1 KHÔNG được có
    bất kỳ đường code nào gửi report ra Internet. Chặn từ tầng import."""
    banned = {"httpx", "requests", "urllib", "urllib3", "aiohttp", "socket",
              "h1_client", "intigriti_client", "subprocess", "os"}
    src = Path(report.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in banned, f"report.py import '{alias.name}' — cấm"
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root not in banned, f"report.py import from '{node.module}' — cấm"


# ─────────────────────────── pipeline (async) ───────────────────────────


class ReportFakePool(FakePool):
    """FakePool biết trả candidate row cho SELECT report và ghi lại UPDATE.
    __aenter__ trả CHÍNH pool (không phải FakeConn) để override fetchrow."""

    def __init__(self, row: dict | None):
        super().__init__()
        self.row = row
        self.updates: list[tuple[str, tuple]] = []

    async def __aenter__(self):
        return self

    async def fetchval(self, sql, *params):
        # detect.read_evidence: SELECT <path_column> FROM candidates WHERE id = $1
        sql_low = " ".join(sql.split()).lower()
        for col in ("verify_evidence_path", "oob_evidence_path", "evidence_path"):
            if f"select {col} from candidates" in sql_low:
                return (self.row or {}).get(col)
        return None

    async def fetchrow(self, sql, *params):
        sql_low = " ".join(sql.split()).lower()
        if "from candidates c" in sql_low and "join" in sql_low:
            return self.row
        if "update candidates" in sql_low:
            self.updates.append((sql_low, params))
            return {
                **(self.row or {}),
                "status": params[1] if "status = $2" in sql_low else (self.row or {}).get("status"),
            }
        return self.row


def _row(**over) -> dict:
    base = dict(
        program_platform="hackerone",
        evidence_path=None,
        verify_evidence_path=None,
        oob_evidence_path=None,
        report_drafts=None,
        report_url=None,
        report_notes=None,
        reported_at=None,
    )
    base.update(over)
    return _candidate_with(**base)


@pytest.mark.asyncio
async def test_get_report_candidate_chưa_verified_ném_lỗi():
    pool = ReportFakePool(_row(status="new"))
    with pytest.raises(ReportError):
        await get_report(pool, 7)
    # rejected cũng không được sinh report
    pool = ReportFakePool(_row(status="rejected"))
    with pytest.raises(ReportError):
        await get_report(pool, 7)


@pytest.mark.asyncio
async def test_get_report_candidate_không_tồn_tại_trả_none():
    pool = ReportFakePool(None)
    assert await get_report(pool, 999) is None


@pytest.mark.asyncio
async def test_get_report_sinh_draft_mới_từ_evidence_file():
    vdir = Path(config.settings.evidence_dir) / "1" / "verify"
    vdir.mkdir(parents=True)
    ve = vdir / "007.json"
    ve.write_text(json.dumps(VERIFY_EVIDENCE), encoding="utf-8")

    pool = ReportFakePool(_row(verify_evidence_path=str(ve)))
    out = await get_report(pool, 7)
    assert out["source"] == "generated"
    assert out["platform"] == "hackerone"  # mặc định theo platform của Program
    assert out["program_platform"] == "hackerone"
    assert "## Summary" in out["markdown"]
    assert POC_URL in out["markdown"]
    # GET KHÔNG tự lưu draft — không UPDATE nào cả
    assert pool.updates == []


@pytest.mark.asyncio
async def test_get_report_đổi_platform_theo_query():
    pool = ReportFakePool(_row())
    out = await get_report(pool, 7, platform="intigriti")
    assert out["platform"] == "intigriti"
    assert "### Description" in out["markdown"]
    with pytest.raises(ReportError):
        await get_report(pool, 7, platform="bugcrowd")


@pytest.mark.asyncio
async def test_get_report_trả_draft_đã_lưu_khi_có():
    saved = {
        "hackerone": {
            "platform": "hackerone",
            "sections": {"title": "Tiêu đề đã sửa", "severity": "high",
                         "summary": "s", "steps_to_reproduce": "1. x",
                         "impact": "i", "evidence": "e"},
            "markdown": "# Tiêu đề đã sửa — bản đã lưu",
        },
    }
    pool = ReportFakePool(_row(report_drafts=saved))
    out = await get_report(pool, 7)
    assert out["source"] == "saved"
    assert out["markdown"] == "# Tiêu đề đã sửa — bản đã lưu"
    # refresh=1 → sinh lại từ evidence dù đã lưu
    out2 = await get_report(pool, 7, refresh=True)
    assert out2["source"] == "generated"
    # platform không có draft lưu → generated
    out3 = await get_report(pool, 7, platform="intigriti")
    assert out3["source"] == "generated"


@pytest.mark.asyncio
async def test_save_report_draft_lưu_jsonb_theo_platform():
    pool = ReportFakePool(_row())
    sections = {"title": "T", "severity": "high", "summary": "s",
                "steps_to_reproduce": "1. x", "impact": "i", "evidence": "e"}
    out = await save_report_draft(pool, 7, "intigriti", sections, "md-đã-sửa")
    assert out is not None
    assert len(pool.updates) == 1
    sql, params = pool.updates[0]
    assert "report_drafts" in sql
    # JSONB merge theo platform: {"intigriti": {...}}
    payload = json.loads(params[-1])
    assert "intigriti" in payload
    assert payload["intigriti"]["markdown"] == "md-đã-sửa"


@pytest.mark.asyncio
async def test_save_report_draft_chưa_verified_ném_lỗi():
    pool = ReportFakePool(_row(status="new"))
    with pytest.raises(ReportError):
        await save_report_draft(pool, 7, "hackerone", {}, "")


@pytest.mark.asyncio
async def test_mark_reported_từ_verified_đặt_status_ngày_ghi_chú():
    pool = ReportFakePool(_row())
    out = await mark_reported(
        pool, 7,
        report_url="https://hackerone.com/reports/123",
        report_notes="Đã nộp ngày 10/9",
    )
    assert out is not None
    sql, params = pool.updates[0]
    assert "status = 'reported'" in sql
    assert "reported_at = now()" in sql
    assert "report_url = coalesce($2" in sql
    assert "report_notes = coalesce($3" in sql
    assert params[1] == "https://hackerone.com/reports/123"
    assert params[2] == "Đã nộp ngày 10/9"


@pytest.mark.asyncio
async def test_mark_reported_chưa_verified_ném_lỗi():
    pool = ReportFakePool(_row(status="rejected"))
    with pytest.raises(ReportError):
        await mark_reported(pool, 7, report_url="x", report_notes="y")
