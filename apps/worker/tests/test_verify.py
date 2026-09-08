"""Test vòng xác minh open redirect (ticket #12) — phần thuần.

Seam thuần: probe script builder (request vô hại + PoC), parser profile
response từ stdout sandbox, phân tích response diff SO VỚI BASELINE ("khác
theo hướng khai thác được?" — KHÔNG phải "payload có xuất hiện?"), chấm
confidence score + ngưỡng quyết định, inject param vào URL, ghi evidence diff.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_verify.py -q
"""

import json
from pathlib import Path

import pytest

from app import config
from app.verify import (
    PROBE_MARKER,
    ProbeProfile,
    analyze_redirect,
    build_probe_script,
    decide_verdict,
    inject_param,
    parse_probe,
    run_redirect_verification,
    write_verify_evidence,
)

CANARY = "https://canary.example/vulhunt-poc"


def _profile(
    status: int = 200,
    location: str = "",
    content_type: str = "text/html; charset=utf-8",
    body: str = "<html>hello</html>",
) -> ProbeProfile:
    headers = {"content-type": content_type}
    if location:
        headers["location"] = location
    return ProbeProfile(
        status=status,
        headers=headers,
        content_type=content_type,
        body_length=len(body.encode()),
        body=body,
    )


@pytest.fixture(autouse=True)
def _isolated_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))


# ── probe script builder: request vô hại / PoC chạy TRONG sandbox ──


def test_build_probe_script_nhúng_url_và_chặn_follow_redirect():
    script = build_probe_script("https://app.other.com/redirect?next=https://example.com/")
    assert "https://app.other.com/redirect?next=https://example.com/" in script
    # KHÔNG follow redirect — 302 phải được nhìn thấy nguyên bản để diff
    assert "redirect_request" in script
    # header định danh đọc từ env do bridge truyền vào
    assert "IDENT_HEADER_NAME" in script and "IDENT_HEADER_VALUE" in script
    # kết quả in ra dạng JSON sau marker để parse_probe đọc
    assert PROBE_MARKER in script
    assert "json.dumps" in script


def test_build_probe_script_url_có_ký_tự_lạ_vẫn_an_toàn():
    weird = "https://app.other.com/x?q=it's&a=1"
    script = build_probe_script(weird)
    assert weird in script  # literal python (json.dumps) giữ nguyên
    # script phải parse được (không break cú pháp) — compile kiểm tra
    compile(script.replace('python3 - <<', '#'), "<probe>", "exec")


# ── parse_probe: đọc profile JSON từ stdout sandbox ──


def test_parse_probe_đọc_marker_rồi_json():
    profile = {
        "url": "https://a.com/", "status": 302,
        "headers": {"content-type": "text/html", "location": "https://canary.example/"},
        "content_type": "text/html", "body_length": 0, "body": "",
    }
    stdout = f"stderr linh tinh\n{PROBE_MARKER}\n{json.dumps(profile)}\n"
    got = parse_probe(stdout)
    assert got is not None
    assert got.status == 302
    assert got.headers["location"] == "https://canary.example/"
    assert got.content_type == "text/html"


def test_parse_probe_không_marker_hoặc_json_đứt_trả_none():
    assert parse_probe("không có gì") is None
    assert parse_probe(f"{PROBE_MARKER}\n{{đứt}}") is None
    assert parse_probe("") is None


# ── inject_param: chèn giá trị vào URL cho baseline / PoC ──


def test_inject_param_thay_param_có_sẵn():
    out = inject_param("https://a.com/r?next=https://a.com/&x=1", "next", CANARY)
    assert out.startswith("https://a.com/r?")
    assert f"next={CANARY}" not in out  # giá trị bị percent-encode trong query
    from urllib.parse import parse_qsl, urlsplit

    pairs = dict(parse_qsl(urlsplit(out).query))
    assert pairs["next"] == CANARY
    assert pairs["x"] == "1"


def test_inject_param_thêm_mới_khi_thiếu():
    out = inject_param("https://a.com/r", "next", CANARY)
    assert "?" in out
    from urllib.parse import parse_qsl, urlsplit

    assert dict(parse_qsl(urlsplit(out).query))["next"] == CANARY


# ── analyze_redirect: diff SO VỚI BASELINE theo hướng khai thác được ──


def test_âm_tính_location_redirect_tới_payload_thành_verified():
    baseline = _profile(200)
    poc = _profile(302, location=CANARY, body="")
    a = analyze_redirect(baseline, poc, CANARY)
    assert a.verdict == "verified"
    assert a.score >= 0.85
    assert "location_redirect" in a.signals
    # diff ghi rõ baseline vs poc
    assert a.diff["status"]["baseline"] == 200
    assert a.diff["status"]["poc"] == 302
    assert a.diff["location"]["poc"] == CANARY


def test_âm_tính_meta_refresh_thành_verified():
    body = f'<html><meta http-equiv="refresh" content="0; url={CANARY}"></html>'
    a = analyze_redirect(_profile(200), _profile(200, body=body), CANARY)
    assert a.verdict == "verified"
    assert a.score >= 0.85
    assert "meta_refresh" in a.signals


def test_js_redirect_đúng_ngưỡng_085():
    body = f'<script>location.href = "{CANARY}";</script>'
    a = analyze_redirect(_profile(200), _profile(200, body=body), CANARY)
    assert a.verdict == "verified"
    assert a.score == pytest.approx(0.85)
    assert "js_redirect" in a.signals


def test_âm_tính_token_js_đâu_đó_không_gần_payload_không_báo_thật():
    # payload chỉ bị reflect thuần; token redirect đứng xa (>200 ký tự) trong
    # trang — đúng dạng false positive "payload có xuất hiện" mà đề bài cấm
    filler = "<p>" + "lorem ipsum dolor sit amet " * 20 + "</p>"
    body = (
        f"<html>Thank you, redirect to {CANARY} failed.</html>"
        f"{filler}"
        "<script>window.location = '/home';</script>"
    )
    a = analyze_redirect(_profile(200), _profile(200, body=body), CANARY)
    assert a.verdict == "rejected"
    assert "js_redirect" not in a.signals
    assert "body_reflection" in a.patterns


def test_âm_tính_meta_refresh_đâu_đó_không_gần_payload_không_báo_thật():
    filler = "<p>" + "consectetur adipiscing elit " * 20 + "</p>"
    body = (
        f"<html>see {CANARY} for details</html>"
        f"{filler}"
        '<meta http-equiv="refresh" content="0; url=/home">'
    )
    a = analyze_redirect(_profile(200), _profile(200, body=body), CANARY)
    assert a.verdict == "rejected"
    assert "meta_refresh" not in a.signals


def test_âm_tính_waf_block_page_không_báo_thật():
    baseline = _profile(200)
    poc = _profile(403, body="Request blocked. Cloudflare Ray ID: 123")
    a = analyze_redirect(baseline, poc, CANARY)
    assert a.verdict == "rejected"
    assert a.score < 0.85
    assert "waf_block" in a.patterns


def test_âm_tính_payload_bị_escape_không_báo_thật():
    from urllib.parse import quote

    encoded = quote(CANARY, safe="")
    body = f"<html>redirect to {encoded} not allowed</html>"
    a = analyze_redirect(_profile(200), _profile(200, body=body), CANARY)
    assert CANARY not in body  # chỉ bản encode xuất hiện
    assert a.verdict == "rejected"
    assert "payload_escaped" in a.patterns


def test_âm_tính_302_nhưng_location_bị_encode_vẫn_rejected():
    from urllib.parse import quote

    poc = _profile(302, location=quote(CANARY, safe=""), body="")
    a = analyze_redirect(_profile(200), poc, CANARY)
    assert a.verdict == "rejected"
    assert "payload_escaped" in a.patterns


def test_âm_tính_payload_trong_error_log_không_báo_thật():
    body = (
        "Traceback (most recent call last):\n"
        f'  File "app.py", line 9, in handler\nValueError: invalid redirect {CANARY}'
    )
    a = analyze_redirect(_profile(200), _profile(200, body=body), CANARY)
    assert a.verdict == "rejected"
    assert "payload_in_error" in a.patterns


def test_âm_tính_response_giống_hệt_baseline_không_diff():
    same = _profile(200)
    a = analyze_redirect(same, _profile(200), CANARY)
    assert a.verdict == "rejected"
    assert a.score == 0.0
    assert "no_diff" in a.patterns


def test_reflection_thuần_trong_body_dưới_ngưỡng():
    body = f"Sorry, we do not redirect to {CANARY} anymore."
    a = analyze_redirect(_profile(200), _profile(200, body=body), CANARY)
    assert a.verdict == "rejected"
    assert a.score < 0.85
    assert "body_reflection" in a.patterns


def test_probe_lỗi_mạng_ra_rejected_probe_error():
    a = analyze_redirect(
        ProbeProfile(0, {}, "", 0, "", error="connection refused"),
        _profile(302, location=CANARY, body=""),
        CANARY,
    )
    assert a.verdict == "rejected"
    assert "probe_error" in a.patterns


# ── decide_verdict: ngưỡng 0.85 cấu hình được ──


def test_decide_verdict_theo_ngưỡng():
    assert decide_verdict(0.95, 0.85) == "verified"
    assert decide_verdict(0.85, 0.85) == "verified"  # ≥ ngưỡng
    assert decide_verdict(0.84, 0.85) == "rejected"
    # ngưỡng cấu hình lại thấp hơn → cùng score thành verified
    assert decide_verdict(0.5, 0.4) == "verified"


def test_ngưỡng_mặc_định_từ_settings(monkeypatch):
    from app.verify import default_threshold

    monkeypatch.setattr(config.settings, "verify_confidence_threshold", 0.6)
    assert default_threshold() == pytest.approx(0.6)


# ── write_verify_evidence: baseline + PoC + diff + pattern log ──


def test_write_verify_evidence_ghi_file_json_đầy_dữ_liệu(tmp_path):
    baseline = _profile(200)
    poc = _profile(302, location=CANARY, body="")
    a = analyze_redirect(baseline, poc, CANARY)
    path = write_verify_evidence(
        run_id=7,
        candidate_id=3,
        record={
            "payload": CANARY,
            "threshold": 0.85,
            "baseline": baseline.to_dict(),
            "poc": poc.to_dict(),
            "baseline_session_id": 11,
            "verify_session_id": 12,
            "analysis": {
                "signals": a.signals,
                "patterns": a.patterns,
                "score": a.score,
                "verdict": a.verdict,
                "reason": a.reason,
                "diff": a.diff,
            },
        },
    )
    assert path is not None
    content = json.loads(open(path, encoding="utf-8").read())
    assert content["baseline"]["status"] == 200
    assert content["poc"]["status"] == 302
    assert content["baseline_session_id"] == 11
    assert content["verify_session_id"] == 12
    assert content["analysis"]["verdict"] == "verified"
    assert content["analysis"]["diff"]["location"]["poc"] == CANARY


# ── pipeline: evidence khi probe chạy mà stdout không parse được ──


class _FakePool:
    """Pool giả: fetchrow trả None (không cần đọc verdict row), execute no-op."""

    def acquire(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, sql, *params):
        pass

    async def fetchrow(self, sql, *params):
        return None


_CANDIDATE = {
    "id": 3,
    "run_id": 7,
    "class": "redirect",
    "target": "https://app.other.com/redirect",
    "param": "next",
    "status": "new",
}


def _probe_stdout(profile: dict) -> str:
    return f"{PROBE_MARKER}\n{json.dumps(profile)}\n"


def _evidence_content() -> dict:
    (path,) = Path(config.settings.evidence_dir).rglob("*.json")
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.asyncio
async def test_probe_đứt_json_evidence_ghi_stdout_thô_của_chính_probe_đó():
    """Baseline parse được, PoC trả stdout đứt → evidence: baseline vẫn là
    profile thường; slot poc ghi parse_error với STDOUT THÔ CỦA CHÍNH PoC —
    không được nhét body/dữ liệu của baseline vào (nhầm nó thì evidence mất
    đúng thứ cần debug)."""
    scripts: list[str] = []

    async def probe(script: str, target: str) -> dict:
        scripts.append(script)
        if len(scripts) == 1:  # lần 1 = baseline
            return {
                "status": "ok", "session_id": 11,
                "stdout": _probe_stdout({
                    "url": target, "status": 200, "headers": {},
                    "content_type": "text/html", "body_length": 0,
                    "body": "baseline body gốc",
                }),
            }
        return {"status": "ok", "session_id": 12,
                "stdout": f"{PROBE_MARKER}\n{{json đứt giữa chừng"}

    summary = await run_redirect_verification(_FakePool(), dict(_CANDIDATE), probe=probe)
    assert summary["verdict"] == "rejected"
    assert "probe_error" in summary["patterns"]

    content = _evidence_content()
    assert content["baseline"].get("status") == 200  # baseline parse bình thường
    assert content["poc"].get("parse_error") is True
    head = content["poc"].get("stdout_head") or ""
    assert "đứt" in head  # stdout thô của PoC
    assert "baseline body gốc" not in head  # KHÔNG phải dữ liệu của baseline


@pytest.mark.asyncio
async def test_cả_hai_probe_đều_đứt_evidence_không_ghi_skipped():
    """Cả baseline lẫn PoC đều chạy thật nhưng stdout không parse được → hai
    slot đều parse_error kèm stdout thô TƯƠNG ỨNG — không được ghi 'skipped'
    (skipped chỉ dành cho probe KHÔNG hề chạy, ví dụ candidate thiếu param)."""

    async def probe(script: str, target: str) -> dict:
        return {"status": "ok", "session_id": 13, "stdout": "stdout rác không marker"}

    summary = await run_redirect_verification(_FakePool(), dict(_CANDIDATE), probe=probe)
    assert summary["verdict"] == "rejected"
    assert "probe_error" in summary["patterns"]

    content = _evidence_content()
    assert content["baseline"] == {
        "parse_error": True, "stdout_head": "stdout rác không marker",
    }
    assert content["poc"] == {
        "parse_error": True, "stdout_head": "stdout rác không marker",
    }
