"""Test phần thuần verify batch A (ticket #15) — 7 lớp HTTP-only.

build_http_probe_script (method/headers/body tuỳ ý, không follow redirect) +
7 analyze_*: confirm tool output + baseline diff → confidence score 0–1.
Âm tính của từng lớp: WAF block, payload bị escape, marker có sẵn ở baseline,
introspection disabled… → rejected. Class headers chỉ informational.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_httpverify.py -q
"""

import json

import pytest

from app.config import settings
from app.httpverify import (
    HTTP_VERIFY_CLASSES,
    analyze_cors,
    analyze_crlf,
    analyze_disclosure,
    analyze_dirlist,
    analyze_graphql,
    analyze_headers,
    analyze_ssti,
    build_graphql_cop_args,
    build_graphw00f_args,
    build_http_probe_script,
    cap_headers_severity,
    default_cors_origin,
    default_ssti_payload,
    parse_crlfuzz,
    parse_graphql_cop,
    parse_graphw00f,
    parse_sstimap,
)
from app.verify import PROBE_MARKER, ProbeProfile


def _profile(
    status: int = 200,
    headers: dict | None = None,
    body: str = "ok",
    error: str | None = None,
) -> ProbeProfile:
    return ProbeProfile(
        status=status,
        headers=headers or {},
        content_type=str((headers or {}).get("content-type", "text/html")),
        body_length=len(body),
        body=body,
        error=error,
    )


# ── build_http_probe_script ──


def test_probe_script_giao_thức_get_mặc_định_không_follow_redirect():
    script = build_http_probe_script("https://t.example/x")
    assert PROBE_MARKER in script
    assert "https://t.example/x" in script
    assert '"GET"' in script and "redirect_request" in script  # _NoRedirect


def test_probe_script_post_json_body_và_header_tuỳ_ý():
    script = build_http_probe_script(
        "https://t.example/graphql",
        method="POST",
        headers={"content-type": "application/json"},
        body=json.dumps({"query": "{ __typename }"}),
    )
    assert '"POST"' in script
    assert "content-type" in script
    assert "__typename" in script


def test_probe_script_waf_không_liên_quan_môi_trường_định_danh_từ_env():
    script = build_http_probe_script("https://t.example/", headers={"origin": "https://e.example"})
    assert "IDENT_HEADER_NAME" in script  # bridge chèn header định danh


# ── defaults ──


def test_default_payload_từng_lớp():
    assert default_cors_origin() == settings.verify_cors_origin
    assert default_ssti_payload() == "{{7*7}}"
    assert sorted(HTTP_VERIFY_CLASSES) == [
        "cors", "crlf", "dirlist", "disclosure", "graphql", "headers", "ssti",
    ]


# ── analyze_cors ──


def test_cors_reflect_origin_và_credentials_verified():
    baseline = _profile(200, {"content-type": "text/html"}, "<html>home</html>")
    poc = _profile(200, {
        "content-type": "text/html",
        "access-control-allow-origin": "https://evil.example",
        "access-control-allow-credentials": "true",
    }, "<html>home</html>")
    analysis = analyze_cors(baseline, poc, "https://evil.example", 0.85)
    assert analysis.verdict == "verified" and analysis.score >= 0.85
    assert "acao_reflects_origin" in analysis.signals
    assert "acac_true" in analysis.signals


def test_cors_reflect_nhưng_không_credentials_dưới_ngưỡng_rejected():
    baseline = _profile(200, {}, "home")
    poc = _profile(200, {"access-control-allow-origin": "https://evil.example"}, "home")
    analysis = analyze_cors(baseline, poc, "https://evil.example", 0.85)
    assert analysis.verdict == "rejected"
    assert "acao_reflects_origin" in analysis.signals


def test_cors_âm_tính_wildcard_không_reflect_waf():
    baseline = _profile(200, {}, "home")
    poc_star = _profile(200, {"access-control-allow-origin": "*"}, "home")
    assert analyze_cors(baseline, poc_star, "https://evil.example", 0.85).verdict == "rejected"
    assert "wildcard_only" in analyze_cors(baseline, poc_star, "https://evil.example", 0.85).patterns

    poc_none = _profile(200, {}, "<html>trang khác baseline</html>")
    a = analyze_cors(baseline, poc_none, "https://evil.example", 0.85)
    assert a.verdict == "rejected"
    assert "origin_not_reflected" in a.patterns

    poc_same = _profile(200, {}, "home")  # giống hệt baseline
    a = analyze_cors(baseline, poc_same, "https://evil.example", 0.85)
    assert a.verdict == "rejected" and "no_diff" in a.patterns

    poc_waf = _profile(403, {}, "Request blocked — Cloudflare")
    a = analyze_cors(baseline, poc_waf, "https://evil.example", 0.85)
    assert a.verdict == "rejected" and "waf_block" in a.patterns

    a = analyze_cors(_profile(error="dns chết"), poc_none, "https://evil.example", 0.85)
    assert a.verdict == "rejected" and "probe_error" in a.patterns


# ── analyze_dirlist ──


def test_dirlist_poc_listing_baseline_không_listing_verified():
    baseline = _profile(404, {}, "not found")
    poc = _profile(200, {"content-type": "text/html"},
                   "<html><head><title>Index of /backup</title></head>"
                   '<body><a href="../">../</a><a href="secret.sql">secret.sql</a></body></html>')
    analysis = analyze_dirlist(baseline, poc, "", 0.85)
    assert analysis.verdict == "verified" and analysis.score >= 0.85
    assert "listing_markers" in analysis.signals


def test_dirlist_âm_tính_không_listing_waf_baseline_cũng_listing():
    baseline_ok = _profile(404, {}, "not found")
    poc_plain = _profile(200, {}, "<html>trang bình thường</html>")
    a = analyze_dirlist(baseline_ok, poc_plain, "", 0.85)
    assert a.verdict == "rejected" and "not_a_listing" in a.patterns

    poc_missing = _profile(404, {}, "not found")
    a = analyze_dirlist(baseline_ok, poc_missing, "", 0.85)
    assert a.verdict == "rejected" and "endpoint_missing" in a.patterns

    baseline_listing = _profile(200, {}, "<title>Index of /</title>")
    a = analyze_dirlist(baseline_listing, poc_plain, "", 0.85)
    assert a.verdict == "rejected" and "baseline_also_listing" in a.patterns

    poc_waf = _profile(403, {}, "Access Denied — Imperva")
    a = analyze_dirlist(baseline_ok, poc_waf, "", 0.85)
    assert a.verdict == "rejected" and "waf_block" in a.patterns


# ── analyze_graphql ──


def _graphql_body(data=None, errors=None):
    payload = {}
    if data is not None:
        payload["data"] = data
    if errors:
        payload["errors"] = errors
    return json.dumps(payload)


def test_graphql_baseline_là_graphql_poc_introspection_verified():
    baseline = _profile(200, {"content-type": "application/json"},
                        _graphql_body(data={"__typename": "Query"}))
    poc = _profile(200, {"content-type": "application/json"},
                   _graphql_body(data={"__schema": {"types": [{"name": "User"}]}}))
    analysis = analyze_graphql(baseline, poc, "", 0.85)
    assert analysis.verdict == "verified" and analysis.score >= 0.85
    assert "introspection_enabled" in analysis.signals


def test_graphql_âm_tính_introspection_disabled_và_not_graphql():
    baseline = _profile(200, {"content-type": "application/json"},
                        _graphql_body(data={"__typename": "Query"}))
    poc_disabled = _profile(
        200, {"content-type": "application/json"},
        _graphql_body(errors=[{"message": "GraphQL introspection is not allowed by Apollo Server"}]),
    )
    a = analyze_graphql(baseline, poc_disabled, "", 0.85)
    assert a.verdict == "rejected" and "introspection_disabled" in a.patterns

    poc_html = _profile(200, {"content-type": "text/html"}, "<html>login</html>")
    a = analyze_graphql(poc_html, poc_html, "", 0.85)
    assert a.verdict == "rejected" and "not_graphql" in a.patterns

    poc_schema_baseline_html = _profile(
        200, {"content-type": "application/json"},
        _graphql_body(data={"__schema": {"types": []}}),
    )
    a = analyze_graphql(poc_html, poc_schema_baseline_html, "", 0.85)
    assert a.verdict == "rejected" and "endpoint_not_graphql" in a.patterns


# ── analyze_crlf ──


def test_crlf_header_injected_verified():
    baseline = _profile(200, {}, "home")
    poc = _profile(302, {"location": "/", "x-vulhunt-injection": "1"}, "")
    analysis = analyze_crlf(baseline, poc, "X-Vulhunt-Injection: 1", 0.85)
    assert analysis.verdict == "verified" and analysis.score >= 0.85
    assert "header_injected" in analysis.signals


def test_crlf_âm_tính_escaped_waf_không_inject():
    baseline = _profile(200, {}, "home")
    poc_escaped = _profile(
        200, {},
        "value %0d%0aX-Vulhunt-Injection%3A%201 reflected trong body",
    )
    a = analyze_crlf(baseline, poc_escaped, "X-Vulhunt-Injection: 1", 0.85)
    assert a.verdict == "rejected" and "payload_escaped" in a.patterns

    poc_waf = _profile(403, {}, "request blocked by web application firewall")
    a = analyze_crlf(baseline, poc_waf, "X-Vulhunt-Injection: 1", 0.85)
    assert a.verdict == "rejected" and "waf_block" in a.patterns

    poc_clean = _profile(200, {}, "home patched")
    a = analyze_crlf(baseline, poc_clean, "X-Vulhunt-Injection: 1", 0.85)
    assert a.verdict == "rejected" and "header_not_injected" in a.patterns


# ── analyze_ssti ──


def test_ssti_math_evaluated_verified():
    baseline = _profile(200, {}, "hello world")
    poc = _profile(200, {}, "hello 49 world")
    analysis = analyze_ssti(baseline, poc, "{{7*7}}", 0.85)
    assert analysis.verdict == "verified" and analysis.score >= 0.85
    assert "math_evaluated" in analysis.signals


def test_ssti_âm_tính_escaped_và_math_có_sẵn_ở_baseline():
    baseline = _profile(200, {}, "hello world")
    poc_escaped = _profile(200, {}, "hello {{7*7}} world")
    a = analyze_ssti(baseline, poc_escaped, "{{7*7}}", 0.85)
    assert a.verdict == "rejected" and "payload_escaped" in a.patterns

    baseline_49 = _profile(200, {}, "phòng 49")
    poc_49 = _profile(200, {}, "phòng 49")
    a = analyze_ssti(baseline_49, poc_49, "{{7*7}}", 0.85)
    assert a.verdict == "rejected" and "ambiguous_baseline" in a.patterns

    poc_waf = _profile(406, {}, "Not Acceptable — Sucuri")
    a = analyze_ssti(baseline, poc_waf, "{{7*7}}", 0.85)
    assert a.verdict == "rejected" and "waf_block" in a.patterns


# ── analyze_headers ──


def test_headers_chỉ_informational_không_bao_giờ_verified():
    poc = _profile(200, {"content-type": "text/html"}, "<html>x</html>")
    analysis = analyze_headers(poc, 0.85)
    assert analysis.verdict == "informational"
    assert analysis.score == 0.0
    assert analysis.detail["missing"]  # đủ headers đang thiếu
    assert "content-security-policy" in analysis.detail["missing"]

    poc_full = _profile(200, {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=63072000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }, "x")
    analysis = analyze_headers(poc_full, 0.85)
    assert analysis.verdict == "informational"
    assert analysis.detail["missing"] == []


def test_cap_headers_severity_không_vượt_low():
    assert cap_headers_severity("high") == "low"
    assert cap_headers_severity("medium") == "low"
    assert cap_headers_severity("low") == "low"
    assert cap_headers_severity("info") == "info"
    assert cap_headers_severity("lạ") == "low"


# ── analyze_disclosure ──


def test_disclosure_secret_ở_poc_vắng_ở_baseline_verified():
    baseline = _profile(200, {}, "<html>trang chủ</html>")
    poc = _profile(200, {"content-type": "application/octet-stream"},
                   "DB_PASSWORD=hunter2\nAWS_SECRET=AKIAIOSFODNN7EXAMPLE\n")
    analysis = analyze_disclosure(baseline, poc, "", 0.85)
    assert analysis.verdict == "verified" and analysis.score >= 0.85
    assert "sensitive_content" in analysis.signals


def test_disclosure_âm_tính_endpoint_missing_waf_không_có_marker():
    baseline = _profile(200, {}, "<html>trang chủ</html>")

    poc_missing = _profile(404, {}, "not found")
    a = analyze_disclosure(baseline, poc_missing, "", 0.85)
    assert a.verdict == "rejected" and "endpoint_missing" in a.patterns

    poc_waf = _profile(403, {}, "Request blocked — Incapsula")
    a = analyze_disclosure(baseline, poc_waf, "", 0.85)
    assert a.verdict == "rejected" and "waf_block" in a.patterns

    poc_plain = _profile(200, {}, "<html>về chúng tôi</html>")
    a = analyze_disclosure(baseline, poc_plain, "", 0.85)
    assert a.verdict == "rejected" and "no_sensitive_content" in a.patterns

    poc_weak = _profile(200, {}, "Traceback (most recent call last): ...")
    a = analyze_disclosure(baseline, poc_weak, "", 0.85)
    assert a.verdict == "rejected" and "weak_disclosure_only" in a.patterns


# ── parsers tool chuyên dụng (detection batch A) ──


def test_parse_graphql_cop_json_introspection_hit():
    stdout = json.dumps([
        {"title": "Introspection", "danger": True, "result": True, "method": "POST"},
        {"title": "Field Suggestions", "danger": False, "result": False},
    ])
    hits = parse_graphql_cop(stdout)
    assert len(hits) == 1
    assert hits[0]["title"] == "Introspection"
    assert parse_graphql_cop("stdout rác") == []


def test_parse_graphw00f_lấy_fingerprint():
    stdout = "\033[92m[*] Discovered GraphQL Engine: (Appollo Graphql)\033[0m\n"
    assert parse_graphw00f(stdout) == "Appollo Graphql"
    # engine name chứa dấu ngoặc — greedy đến ')' cuối
    nested = "\033[92m[*] Discovered GraphQL Engine: (Envoy (Appollo))\033[0m\n"
    assert parse_graphw00f(nested) == "Envoy (Appollo)"
    assert parse_graphw00f("Could not determine the existence of GraphQL") is None


def test_parse_crlfuzz_url_vulnerable_mỗi_dòng():
    stdout = "https://t.example/x?q=1\nhttps://ok.example/y\n"
    assert parse_crlfuzz(stdout) == ["https://t.example/x?q=1", "https://ok.example/y"]
    assert parse_crlfuzz("") == []


def test_parse_sstimap_vulnerable_hit():
    stdout = (
        "\033[92m[+]\033[0m Jinja2 plugin has confirmed injection with tag '{{7*7}}'\n"
        "\033[92m[+]\033[0m Jinja2 plugin has confirmed error-based injection\n"
        "\033[91m[-]\033[0m Twig plugin is testing rendering with tag\n"
    )
    hits = parse_sstimap(stdout)
    assert len(hits) == 1  # dedupe theo engine
    assert hits[0]["engine"] == "Jinja2"
    assert parse_sstimap("[-] Twig plugin is testing rendering with tag") == []


def test_build_args_tool_chuyên_dụng():
    assert build_graphw00f_args("https://t.example/graphql") == [
        "-t", "https://t.example/graphql", "-f",
    ]
    assert build_graphql_cop_args("https://t.example/graphql") == [
        "-t", "https://t.example/graphql", "-o", "json",
    ]
