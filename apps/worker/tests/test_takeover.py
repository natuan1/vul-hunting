"""Test phần thuần lớp subdomain takeover (ticket #14).

Fingerprint service (khớp CNAME), parse output subzy (--output JSON), soạn PoC
page chứa username định danh, xác nhận PoC được phục vụ qua subdomain, hướng
dẫn xác minh tay + cảnh báo report thiếu PoC → N/A, SigV4 của S3 deployer,
deployer GitHub Pages (httpx MockTransport — không chạm mạng thật).

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_takeover.py -q
"""

import base64
import json

import httpx
import pytest

from app import config
from app.takeover import (
    DeployResult,
    FINGERPRINTS,
    GitHubPagesDeployer,
    S3Deployer,
    TakeoverFingerprint,
    TakeoverHostingError,
    analyze_confirmation,
    build_poc_page,
    claim_host_for,
    claim_name,
    confirming_profile,
    fingerprint_for_cname,
    fingerprint_present,
    identifying_username,
    manual_guidance,
    new_takeover_token,
    parse_subzy_output,
    probe_url,
    sigv4_headers,
    write_takeover_evidence,
)


@pytest.fixture(autouse=True)
def _isolated_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))


# ── fingerprint_for_cname: nhận diện service từ CNAME ──


def test_fingerprint_nhận_diện_github_pages():
    fp = fingerprint_for_cname("someuser.github.io.")
    assert fp is not None
    assert fp.service == "GitHub Pages"
    assert fp.claimable
    assert fp.hosting == "github-pages"
    assert any("GitHub Pages" in m or "isn't" in m for m in fp.markers)


def test_fingerprint_nhận_diện_s3_hai_dạng_suffix():
    for cname in ("mybucket.s3.amazonaws.com", "mybucket.s3-website-us-east-1.amazonaws.com"):
        fp = fingerprint_for_cname(cname)
        assert fp is not None, cname
        assert fp.service == "S3"
        assert fp.hosting == "s3"
        assert any("NoSuchBucket" in m for m in fp.markers)


def test_fingerprint_heroku_claimable_nhưng_không_tự_động_được():
    fp = fingerprint_for_cname("quiet-app.herokuapp.com")
    assert fp is not None
    assert fp.claimable
    assert fp.hosting is None  # chỉ claim tay


def test_fingerprint_cloudfront_không_claim_được():
    fp = fingerprint_for_cname("d1a2b3.cloudfront.net")
    assert fp is not None
    assert not fp.claimable


def test_fingerprint_cname_lạ_trả_none():
    assert fingerprint_for_cname("random.host.example.com") is None
    assert fingerprint_for_cname("") is None
    assert fingerprint_for_cname(None) is None


def test_claim_name_github_vs_s3():
    assert claim_name("someuser.github.io") == "someuser"
    # S3: bucket = TOÀN BỘ phần trước suffix (chứa được dấu chấm — bucket name
    # = host nạn nhân, chìa khoá của takeover S3)
    assert claim_name("sub.victim.com.s3.amazonaws.com") == "sub.victim.com"


def test_claim_host_for_chuẩn_hoá_chấm_cuối():
    assert claim_host_for("app.victim.com.", "someuser.github.io") == "someuser.github.io"


def test_bộ_fingerprint_không_trùng_suffix():
    suffixes = [s for fp in FINGERPRINTS for s in fp.cname_suffixes]
    assert len(suffixes) == len(set(suffixes))
    for fp in FINGERPRINTS:
        assert fp.markers and fp.statuses
        assert fp.claim_guide.strip()


# ── parse_subzy_output: JSON --output của subzy (+ fallback) ──


def _subzy_entry(sub, service, vuln=True):
    return {
        "subdomain": sub,
        "status": "vulnerable" if vuln else "secure",
        "engine": service,
        "cname": [f"{sub.split('.')[0]}.example.io"],
        "fingerprint": "marker-of-service",
        "http_status": 404,
        "vulnerable": vuln,
    }


def test_parse_subzy_json_array_chỉ_lấy_vulnerable():
    out = json.dumps([_subzy_entry("a.victim.com", "GitHub Pages", True),
                      _subzy_entry("b.victim.com", "S3", False)])
    got = parse_subzy_output(out)
    assert len(got) == 1
    assert got[0]["target"] == "a.victim.com"
    assert got[0]["service"] == "GitHub Pages"
    assert got[0]["cname"]


def test_parse_subzy_fallback_jsonl_và_dòng_ansi():
    jsonl = json.dumps(_subzy_entry("c.victim.com", "Heroku")) + "\n"
    assert parse_subzy_output(jsonl)[0]["target"] == "c.victim.com"

    ansi = (
        "[ \x1b[32mVULNERABLE\x1b[0m ]  -  d.victim.com  [ \x1b[36mGitHub Pages\x1b[0m ]\n"
        "[ secure ]  -  e.victim.com\n"
    )
    got = parse_subzy_output(ansi)
    assert [g["target"] for g in got] == ["d.victim.com"]
    assert got[0]["service"] == "GitHub Pages"


def test_parse_subzy_stdout_rác_trả_rỗng():
    assert parse_subzy_output("") == []
    assert parse_subzy_output("không có gì hữu ích") == []
    assert parse_subzy_output("{đứt}") == []


# ── PoC page: bằng chứng kiểm soát chứa username định danh ──


def test_build_poc_page_chứa_username_token_và_cảnh_báo():
    page = build_poc_page("natuan1", "vulhunt-takeover-c7-abc", "sub.victim.com", "GitHub Pages")
    assert "natuan1" in page
    assert "vulhunt-takeover-c7-abc" in page
    assert "sub.victim.com" in page
    # lời khuyên đề bài yêu cầu: report thiếu PoC hoạt động → N/A + ảnh hưởng reput
    assert "N/A" in page
    assert "PoC" in page


def test_new_takeover_token_định_dạng_xác_định_theo_nonce():
    token = new_takeover_token(7, "abc123")
    assert token == "vulhunt-takeover-c7-abc123"
    assert token in build_poc_page("u", token, "t.com", "S3")


def test_confirming_profile_body_chứa_đủ_username_và_token():
    body = build_poc_page("natuan1", "tok-1", "sub.victim.com", "S3")
    profile = _profile(200, body)
    assert confirming_profile(profile, "natuan1", "tok-1")
    assert not confirming_profile(
        _profile(200, "hello natuan1"), "natuan1", "tok-1"
    )


# ── fingerprint_present: probe sandbox xác nhận service còn bỏ hoang ──


def _profile(status=404, body="There isn't a GitHub Pages site here."):
    from app.verify import ProbeProfile

    return ProbeProfile(status=status, headers={}, content_type="text/html",
                        body_length=len(body), body=body)


def test_fingerprint_present_status_và_marker():
    fp = FINGERPRINTS[0]
    assert fingerprint_present(fp, _profile(fp.statuses[0], fp.markers[0]))
    assert not fingerprint_present(fp, _profile(200, "trang bình thường"))
    assert not fingerprint_present(fp, _profile(fp.statuses[0], "status khớp nhưng body lạ"))


def test_probe_url_là_http_host_trần():
    assert probe_url("http://sub.victim.com/x") == "http://sub.victim.com/"
    assert probe_url("sub.victim.com") == "http://sub.victim.com/"


# ── analyze_confirmation: xác nhận kiểm soát / từ chối ──


def test_analyze_confirmation_poc_được_phục_vụ_verified():
    token = "vulhunt-takeover-c7-t"
    body = build_poc_page("natuan1", token, "sub.victim.com", "GitHub Pages")
    a = analyze_confirmation(_profile(200, body), "natuan1", token)
    assert a.verdict == "verified"
    assert a.score >= 0.85
    assert "poc_served" in a.signals


def test_analyze_confirmation_không_kiểm_soát_được_rejected():
    a = analyze_confirmation(_profile(404, "There isn't a GitHub Pages site here."),
                             "natuan1", "tok")
    assert a.verdict == "rejected"
    assert "no_control" in a.patterns
    assert "fingerprint" in a.reason.lower() or "kiểm soát" in a.reason.lower()


def test_analyze_confirmation_probe_lỗi_rejected():
    a = analyze_confirmation(_profile(0, ""), "natuan1", "tok")
    assert a.verdict == "rejected"
    assert a.error is not None


# ── identifying_username + hướng dẫn xác minh tay ──


def test_identifying_username_ưu_tiên_hackerone(monkeypatch):
    monkeypatch.setattr(config.settings, "hackerone_username", "natuan1")
    monkeypatch.setattr(config.settings, "intigriti_username", "tuannn")
    assert identifying_username() == "natuan1"
    monkeypatch.setattr(config.settings, "hackerone_username", "")
    assert identifying_username() == "tuannn"
    monkeypatch.setattr(config.settings, "intigriti_username", "")
    assert identifying_username() == ""


def test_manual_guidance_đủ_yếu_tố():
    fp = fingerprint_for_cname("someuser.github.io")
    guide = manual_guidance(fp, "sub.victim.com", "someuser.github.io", "natuan1")
    assert "someuser" in guide          # tài nguyên cần claim
    assert "GitHub Pages" in guide      # service
    assert "natuan1" in guide           # PoC page phải chứa username
    assert "N/A" in guide               # cảnh báo reput


# ── SigV4 (S3 deployer) — thuần, xác định theo thời gian truyền vào ──


def test_sigv4_headers_xác_định_và_đúng_cấu_trúc():
    from datetime import datetime, timezone

    now = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)
    h1 = sigv4_headers("PUT", "mybucket.s3.amazonaws.com", "/", b"poc",
                       "us-east-1", "AKID", "SECRET", now=now)
    h2 = sigv4_headers("PUT", "mybucket.s3.amazonaws.com", "/", b"poc",
                       "us-east-1", "AKID", "SECRET", now=now)
    assert h1 == h2
    assert h1["x-amz-date"] == "20260909T120000Z"
    auth = h1["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 ")
    assert "Credential=AKID/20260909/us-east-1/s3/aws4_request" in auth
    assert "SignedHeaders=" in auth and "Signature=" in auth
    assert h1["x-amz-content-sha256"]


# ── GitHub Pages deployer (httpx MockTransport — không chạm mạng thật) ──


def _github_handler(calls, *, repo_exists=False, file_sha=None):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        url = request.url.path
        method = request.method
        if url == "/user/repos" and method == "POST":
            return httpx.Response(201, json={"full_name": "me/me.github.io"})
        if url.startswith("/repos/me/me.github.io") and method == "GET":
            if url == "/repos/me/me.github.io":
                return (httpx.Response(200, json={"default_branch": "main"})
                        if repo_exists else httpx.Response(404, json={}))
            if "/contents/" in url:
                if file_sha:
                    return httpx.Response(200, json={"sha": file_sha})
                return httpx.Response(404, json={})
            if url.endswith("/pages") and method == "GET":
                return httpx.Response(404, json={})
        if url == "/repos/me/me.github.io/contents/index.html" and method == "PUT":
            return httpx.Response(201, json={"commit": {"sha": "c1"}})
        if url == "/repos/me/me.github.io/contents/CNAME" and method == "PUT":
            return httpx.Response(201, json={"commit": {"sha": "c2"}})
        if url == "/repos/me/me.github.io/pages" and method == "POST":
            return httpx.Response(201, json={"status": "built"})
        return httpx.Response(500, json={"message": "boom"})

    return handler


@pytest.mark.asyncio
async def test_github_deployer_tạo_repo_và_đẩy_poc():
    calls: list[httpx.Request] = []
    http = httpx.AsyncClient(
        base_url="https://api.github.com",
        transport=httpx.MockTransport(_github_handler(calls)),
    )
    d = GitHubPagesDeployer("tok", "me", http=http)
    result = await d.deploy("me.github.io", "<html>POC</html>", "sub.victim.com")
    await http.aclose()

    assert isinstance(result, DeployResult)
    assert result.provider == "github-pages"
    assert result.url == "http://sub.victim.com/"
    paths = [(r.method, r.url.path) for r in calls]
    assert ("POST", "/user/repos") in paths                      # tạo repo claim
    assert ("PUT", "/repos/me/me.github.io/contents/index.html") in paths
    assert ("PUT", "/repos/me/me.github.io/contents/CNAME") in paths  # trỏ custom domain
    assert ("POST", "/repos/me/me.github.io/pages") in paths     # bật Pages
    put_index = next(
        r for r in calls if r.method == "PUT" and r.url.path.endswith("index.html")
    )
    body = json.loads(put_index.content)
    assert base64.b64decode(body["content"]).decode() == "<html>POC</html>"


@pytest.mark.asyncio
async def test_github_deployer_owner_không_khớp_hostname_claim_lỗi():
    http = httpx.AsyncClient(
        base_url="https://api.github.com",
        transport=httpx.MockTransport(_github_handler([])),
    )
    d = GitHubPagesDeployer("tok", "me", http=http)
    with pytest.raises(TakeoverHostingError):
        await d.deploy("someuser.github.io", "<html/>", "sub.victim.com")
    await http.aclose()


# ── S3 deployer (MockTransport) ──


def test_s3_deployer_put_bucket_với_acl_public():
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    d = S3Deployer("AKID", "SECRET", "us-east-1",
                   http=httpx.Client(transport=httpx.MockTransport(handler)))
    result = d.deploy_sync("sub.victim.com", "<html>POC</html>", "sub.victim.com")
    assert result.provider == "s3"
    assert result.url == "http://sub.victim.com/"
    assert len(calls) == 3
    # (1) object key rỗng tại '/' (REST endpoint), (2) index.html, (3) website config
    assert calls[0].url.host == "sub.victim.com.s3.amazonaws.com"
    assert calls[0].content == b"<html>POC</html>"
    assert calls[1].url.path == "/index.html"
    assert calls[1].headers["x-amz-acl"] == "public-read"
    assert calls[1].content == b"<html>POC</html>"
    assert calls[2].url.query == b"website="
    assert b"IndexDocument" in calls[2].content
    # SigV4 có query: Authorization vẫn đúng dạng (canonical query riêng)
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in calls[2].headers["Authorization"]


@pytest.mark.asyncio
async def test_s3_deployer_async_bọc_sync():
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(403, json={"message": "AccessDenied"})

    d = S3Deployer("AKID", "SECRET", "us-east-1",
                   http=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(TakeoverHostingError):
        await d.deploy("sub.victim.com", "<html/>", "sub.victim.com")


# ── evidence writer ──


def test_write_takeover_evidence_ghi_file_dưới_run():
    path = write_takeover_evidence(3, 12, {"schema": "vulhunt.takeover-evidence/1", "x": 1})
    assert path and f"{config.settings.evidence_dir}/3/takeover/012.json" in path
    assert json.loads(open(path, encoding="utf-8").read())["x"] == 1


def test_takeover_fingerprint_là_frozen_dataclass():
    fp = TakeoverFingerprint(service="X", cname_suffixes=("x.io",), markers=("m",),
                             statuses=(404,), claimable=True, hosting=None,
                             claim_guide="guide")
    with pytest.raises(Exception):
        fp.service = "Y"  # type: ignore[misc]
