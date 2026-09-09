"""Catalog batch A (ticket #15) — verify + detection cho 7 lớp HTTP-only:
cors, dirlist, graphql, crlf, ssti, headers, disclosure.

Mỗi lớp 1 **verify skill riêng** (analyze_*): nhân rộng pattern verify của
ticket #12 — probe chạy TRONG sandbox (build_http_probe_script: method/
headers/body tuỳ ý, không follow redirect), **confirm tool output + baseline
diff** → confidence score 0.0–1.0; score ≥ ngưỡng → Finding (verified), dưới
ngưỡng → rejected kèm pattern log. Âm tính chuẩn từng lớp: WAF block page,
payload bị encode/escape, marker/số có sẵn ở baseline, introspection disabled,
origin không reflect… → KHÔNG bao giờ báo thật.

Ngoại lệ: class `headers` (missing security headers) chỉ **informational** —
verify chỉ thu thập evidence (danh sách headers thiếu) + ép severity trần
'low', KHÔNG bao giờ verdict verified/rejected → không tự tạo report, chỉ
hiển thị ở UI.

Detection batch A: 3 tool chuyên dụng bổ sung cho Detection Phase chính
(nuclei templates đã quét toàn bề mặt) — graphql-cop + graphw00f (GraphQL
introspection), crlfuzz (CRLF), SSTImap (SSTI); mỗi hit → Candidate kèm
evidence, đúng cơ chế Scope Validator/rate limit của mọi Tool Execution.
"""

import html
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable
from urllib.parse import quote, urlsplit

import asyncpg

from . import detect, sandbox
from .config import settings
from .detect import CANDIDATE_COLS, CandidateRow
from .tools import (
    ToolContext,
    add_log,
    build_context,
    execute_tool,
    filter_scope,
)
from .verify import (
    PROBE_MARKER,
    ProbeBlocked,
    ProbeProfile,
    _WAF_BLOCK_STATUSES,
    _WAF_MARKERS,
    default_threshold,
    decide_verdict,
    inject_param,
    parse_probe,
    write_verify_evidence,
)

log = logging.getLogger("httpverify")

# seam thực thi (như verify.ProbeCallable) — probe(script, target) → session
ProbeCallable = Callable[[str, str], Awaitable[dict]]

# 7 class HTTP-only của batch A — endpoint/MCP tool nhận đúng các class này
HTTP_VERIFY_CLASSES = ("cors", "dirlist", "graphql", "crlf", "ssti", "headers", "disclosure")

# class chỉ informational: KHÔNG tự tạo report (chỉ hiển thị) — verify chỉ
# thu evidence + ép severity; status/verdict của Candidate giữ nguyên (#15)
INFORMATIONAL_CLASSES = ("headers",)

# các class chèn PoC qua query param — thiếu param → không có PoC, rejected
_PARAM_CLASSES = ("crlf", "ssti")

# giá trị vô hại cho baseline param (khác payload, cùng hình dạng URL)
BENIGN_PARAM_VALUE = "vulhunt-baseline"

# điểm số theo tín hiệu khai thác được của từng lớp
SCORE_CORS_REFLECT_CREDS = 0.95   # ACAO echo origin canary + ACAC true
SCORE_CORS_REFLECT_ONLY = 0.60    # echo origin nhưng không credentials
SCORE_LISTING = 0.90              # chỉ mục thư mục, baseline không listing
SCORE_INTROSPECTION = 0.95        # __schema trả data, baseline là GraphQL
SCORE_HEADER_INJECTED = 0.95      # header CRLF xuất hiện trong response
SCORE_MATH_EVAL = 0.90            # 7*7 → 49, baseline không có
SCORE_DISCLOSURE_STRONG = 0.90    # secret/private key/phpinfo… mới so baseline

# security headers thường yêu cầu (verify class `headers`)
SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

# marker chỉ mục thư mục (lowercase) — trình server hay dùng
_LISTING_MARKERS = (
    "index of /",
    "directory listing for",
    "<title>index of",
    "[to parent directory]",
)

# marker nội dung nhạy cảm của info disclosure/debug endpoints — STRONG chỉ
# khi baseline (root host) không có; WEAK chỉ là stack trace → xem thêm tay
_STRONG_DISCLOSURE_MARKERS = (
    "begin rsa private key", "begin openssh private key", "begin private key",
    "aws_secret_access_key", "aws_access_key_id", "akia",
    "db_password", "database_url", "connectionstring",
    "api_key=", "apikey=", "secret_key=", "password=",
    "phpinfo()", '"_links"', "ref: refs/", "[core]",
)
_WEAK_DISCLOSURE_MARKERS = (
    "traceback (most recent call last)", "stack trace",
    "django debug", "debug mode", "whoops, looks like something went wrong",
)

# cap số target mỗi tool chuyên dụng trong detection batch A (giữ điều độ)
CATALOG_MAX_TARGETS_PER_TOOL = 8


# ───────────────────────────── probe script (sandbox) ─────────────────────────────


def build_http_probe_script(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
) -> str:
    """Probe script (sh) chạy TRONG sandbox — mở rộng của verify.build_probe_
    script: method/headers/body tuỳ ý (POST JSON cho GraphQL, Origin cho
    CORS…), KHÔNG follow redirect, header định danh từ env của bridge, emit
    profile JSON sau PROBE_MARKER (cùng schema ProbeProfile)."""
    req = {"url": url, "method": method or "GET",
           "headers": dict(headers or {}), "body": body}
    return (
        "python3 - <<'PY'\n"
        "import json, os, urllib.request, urllib.error\n"
        f"REQ = {json.dumps(req)}\n"
        f"MARKER = {json.dumps(PROBE_MARKER)}\n"
        "\n"
        "\n"
        "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
        "    def redirect_request(self, req, fp, code, msg, headers, newurl):\n"
        "        return None  # KHÔNG follow redirect — giữ 3xx nguyên bản\n"
        "\n"
        "\n"
        "def _emit(profile):\n"
        "    print(MARKER)\n"
        "    print(json.dumps(profile, ensure_ascii=False))\n"
        "\n"
        "\n"
        "ident_name = os.environ.get(\"IDENT_HEADER_NAME\")\n"
        "ident_value = os.environ.get(\"IDENT_HEADER_VALUE\")\n"
        "headers = dict(REQ.get(\"headers\") or {})\n"
        "if ident_name and ident_value and ident_name.lower() not in {\n"
        "    k.lower() for k in headers\n"
        "}:\n"
        "    headers[ident_name] = ident_value\n"
        "opener = urllib.request.build_opener(_NoRedirect)\n"
        "data = REQ.get(\"body\")\n"
        "request = urllib.request.Request(\n"
        "    REQ[\"url\"], headers=headers, method=REQ.get(\"method\") or \"GET\",\n"
        "    data=data.encode() if data else None,\n"
        ")\n"
        "try:\n"
        "    resp = opener.open(request, timeout=25)\n"
        "except urllib.error.HTTPError as exc:  # 3xx/4xx/5xx vẫn là response để diff\n"
        "    resp = exc\n"
        "except Exception as exc:\n"
        "    _emit({\"url\": REQ[\"url\"], \"status\": 0, \"error\": str(exc)[:300],\n"
        "           \"headers\": {}, \"content_type\": \"\", \"body_length\": 0,\n"
        "           \"body\": \"\"})\n"
        "    raise SystemExit(0)\n"
        "body = resp.read(65536)  # cap body — đủ diff, không ngập log\n"
        "_emit({\n"
        "    \"url\": REQ[\"url\"],\n"
        "    \"status\": resp.getcode() or 0,\n"
        "    \"headers\": {str(k).lower(): str(v) for k, v in resp.headers.items()},\n"
        "    \"content_type\": str(resp.headers.get(\"content-type\", \"\")),\n"
        "    \"body_length\": int(resp.headers.get(\"content-length\") or 0) or len(body),\n"
        "    \"body\": body.decode(\"utf-8\", \"replace\")[:50000],\n"
        "})\n"
        "PY"
    )


# ───────────────────────────── seam thuần (có test) ─────────────────────────────


@dataclass
class HTTPAnalysis:
    """Kết quả phân tích 1 lớp: pattern log (mọi pattern khớp), tín hiệu khai
    thác được, confidence 0.0–1.0, verdict theo ngưỡng + detail tuỳ lớp
    (headers thiếu, marker trúng…). Class informational → verdict
    'informational' (không phải verified/rejected)."""

    patterns: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    score: float = 0.0
    verdict: str = "rejected"
    reason: str = ""
    diff: dict = field(default_factory=dict)
    detail: dict = field(default_factory=dict)


def default_cors_origin() -> str:
    """Origin canary mặc định cho verify CORS (VERIFY_CORS_ORIGIN)."""
    return settings.verify_cors_origin


def default_ssti_payload() -> str:
    """Payload SSTI mặc định — phép tính vô hại, đích thân kết quả là canary."""
    return "{{7*7}}"


def _waf_hit(poc: ProbeProfile) -> bool:
    low = poc.body.lower()
    return poc.status in _WAF_BLOCK_STATUSES or any(m in low for m in _WAF_MARKERS)


def _same_response(a: ProbeProfile, b: ProbeProfile) -> bool:
    return (a.status, a.headers.get("location", ""), a.body_length, a.body) == (
        b.status, b.headers.get("location", ""), b.body_length, b.body
    )


def _probe_error(baseline: ProbeProfile, poc: ProbeProfile, diff: dict) -> HTTPAnalysis:
    err = poc.error or baseline.error
    return HTTPAnalysis(
        patterns=["probe_error"], score=0.0, verdict="rejected",
        reason=f"Không đọc được profile response từ sandbox: {err}", diff=diff,
    )


def _reject(patterns: list[str], score: float, reason: str, diff: dict,
            detail: dict | None = None) -> HTTPAnalysis:
    return HTTPAnalysis(patterns=patterns, score=score, verdict="rejected",
                        reason=reason, diff=diff, detail=detail or {})


# ── CORS misconfig ──


def analyze_cors(
    baseline: ProbeProfile, poc: ProbeProfile, payload: str,
    threshold: float | None = None,
) -> HTTPAnalysis:
    """CORS: probe PoC mang `Origin: <payload>` (origin canary). Dương tính khi
    server ECHO origin canary (Access-Control-Allow-Origin == payload) — chỉ đủ
    Finding khi kèm Access-Control-Allow-Credentials: true. Âm tính: wildcard
    `*`, origin không reflect, WAF, response giống baseline."""
    threshold = default_threshold() if threshold is None else float(threshold)
    acao_b = baseline.headers.get("access-control-allow-origin", "")
    acao = poc.headers.get("access-control-allow-origin", "").strip()
    acac = poc.headers.get("access-control-allow-credentials", "").strip().lower()
    diff = {
        "status": {"baseline": baseline.status, "poc": poc.status},
        "acao": {"baseline": acao_b, "poc": acao},
        "acac": {"poc": acac},
        "body_length": {"baseline": baseline.body_length, "poc": poc.body_length},
    }
    if baseline.error or poc.error:
        return _probe_error(baseline, poc, diff)

    reflected = bool(payload) and acao == payload
    if reflected and acac in ("true", "1"):
        score = SCORE_CORS_REFLECT_CREDS
        return HTTPAnalysis(
            patterns=["acao_reflects_origin", "acac_true"],
            signals=["acao_reflects_origin", "acac_true"], score=score,
            verdict=decide_verdict(score, threshold),
            reason=(f"Server echo origin canary '{payload}' VÀ cho phép credentials "
                    "— CORS khai thác được với cookie/session"), diff=diff,
        )
    if reflected:
        score = SCORE_CORS_REFLECT_ONLY
        analysis = HTTPAnalysis(
            patterns=["acao_reflects_origin"], signals=["acao_reflects_origin"],
            score=score, verdict=decide_verdict(score, threshold),
            reason=("Server echo origin canary nhưng KHÔNG cho credentials — "
                    "chỉ đọc được tài nguyên công khai, dưới ngưỡng"), diff=diff,
        )
        return analysis

    acac_b = baseline.headers.get("access-control-allow-credentials", "").strip().lower()
    if (poc.status, acao, acac, poc.body_length, poc.body) == (
        baseline.status, acao_b, acac_b, baseline.body_length, baseline.body
    ):
        return _reject(["no_diff"], 0.0,
                       "Response giống hệt baseline — server không phản ứng với Origin", diff)
    if _waf_hit(poc):
        return _reject(["waf_block"], 0.0,
                       "Response PoC trông giống trang chặn WAF — false positive", diff)
    if acao == "*":
        return _reject(["wildcard_only"], 0.3,
                       "Access-Control-Allow-Origin: * (wildcard) — trình duyệt chặn "
                       "credentials nên không khai thác được dữ liệu riêng tư", diff)
    return _reject(["origin_not_reflected"], 0.0,
                   f"Server không echo origin canary (ACAO: '{acao or '—'}')", diff)


# ── Directory listing ──


def analyze_dirlist(
    baseline: ProbeProfile, poc: ProbeProfile, payload: str,
    threshold: float | None = None,
) -> HTTPAnalysis:
    """Directory listing: PoC = GET URL candidate (nuclei báo listing); baseline
    = GET path con không tồn tại trong cùng thư mục — listing phải là hành vi
    RIÊNG của thư mục này, không phải server trả listing cho mọi path."""
    threshold = default_threshold() if threshold is None else float(threshold)
    low_p = poc.body.lower()
    low_b = baseline.body.lower()
    poc_markers = [m for m in _LISTING_MARKERS if m in low_p]
    baseline_markers = [m for m in _LISTING_MARKERS if m in low_b]
    diff = {
        "status": {"baseline": baseline.status, "poc": poc.status},
        "body_length": {"baseline": baseline.body_length, "poc": poc.body_length},
        "markers": {"baseline": baseline_markers, "poc": poc_markers},
    }
    if baseline.error or poc.error:
        return _probe_error(baseline, poc, diff)

    ok_status = 200 <= poc.status < 300
    if poc_markers and ok_status and not baseline_markers:
        score = SCORE_LISTING
        return HTTPAnalysis(
            patterns=["listing_markers"], signals=["listing_markers"], score=score,
            verdict=decide_verdict(score, threshold),
            reason=("URL trả chỉ mục thư mục (listing markers) trong khi baseline "
                    "path con không tồn tại — listing thật"), diff=diff,
            detail={"markers": poc_markers},
        )

    if baseline_markers:
        return _reject(["baseline_also_listing"], 0.3,
                       "Baseline path con CŨNG trả listing — server trả listing cho "
                       "mọi path, không phải listing riêng của thư mục", diff)
    if _waf_hit(poc):
        return _reject(["waf_block"], 0.0,
                       "Response PoC trông giống trang chặn WAF — false positive", diff)
    if poc.status in (403, 404):
        return _reject(["endpoint_missing"], 0.0,
                       f"PoC trả HTTP {poc.status} — thư mục không mở nữa (tool output "
                       "đã cũ hoặc matcher sai)", diff)
    return _reject(["not_a_listing"], 0.0,
                   "Response không có marker chỉ mục thư mục — không xác nhận listing", diff)


# ── GraphQL introspection ──


def _json_body(profile: ProbeProfile) -> dict | None:
    try:
        data = json.loads(profile.body)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def analyze_graphql(
    baseline: ProbeProfile, poc: ProbeProfile, payload: str,
    threshold: float | None = None,
) -> HTTPAnalysis:
    """GraphQL introspection: baseline = query vô hại `__typename` (confirm
    endpoint THẬT SỰ là GraphQL); PoC = query `__schema`. Dương tính khi
    baseline là GraphQL VÀ PoC trả data.__schema. Âm tính: introspection bị
    tắt (errors message), endpoint không phải GraphQL, WAF."""
    threshold = default_threshold() if threshold is None else float(threshold)
    base_json = _json_body(baseline)
    poc_json = _json_body(poc)
    baseline_graphql = base_json is not None and "data" in base_json
    schema = (poc_json or {}).get("data", {}).get("__schema") if poc_json else None
    introspection = isinstance(schema, dict)
    errors_text = json.dumps((poc_json or {}).get("errors") or []).lower()
    diff = {
        "status": {"baseline": baseline.status, "poc": poc.status},
        "content_type": {"baseline": baseline.content_type, "poc": poc.content_type},
        "baseline_graphql": baseline_graphql,
        "introspection": introspection,
    }
    if baseline.error or poc.error:
        return _probe_error(baseline, poc, diff)

    if baseline_graphql and introspection:
        score = SCORE_INTROSPECTION
        types = schema.get("types") or []
        return HTTPAnalysis(
            patterns=["introspection_enabled"], signals=["introspection_enabled"],
            score=score, verdict=decide_verdict(score, threshold),
            reason=("Baseline query vô hại xác nhận endpoint là GraphQL; __schema "
                    f"trả về schema đầy đủ ({len(types)} types) — introspection mở"),
            diff=diff, detail={"types": len(types)},
        )

    if poc_json is None:
        return _reject(["not_graphql"], 0.0,
                       "PoC response không phải JSON — endpoint không phản ứng như "
                       "một GraphQL server", diff)
    if not baseline_graphql:
        return _reject(["endpoint_not_graphql"], 0.0,
                       "Baseline query __typename không trả data — endpoint không xác "
                       "nhận được là GraphQL (tool output chưa được confirm)", diff)
    if "introspection" in errors_text:
        return _reject(["introspection_disabled"], 0.0,
                       "GraphQL server trả errors nói rõ introspection bị tắt — "
                       "false positive", diff)
    return _reject(["no_schema"], 0.0,
                   "Baseline là GraphQL nhưng __schema không trả data — introspection "
                   "không xác nhận được", diff)


# ── CRLF injection ──


def analyze_crlf(
    baseline: ProbeProfile, poc: ProbeProfile, payload: str,
    threshold: float | None = None,
) -> HTTPAnalysis:
    """CRLF: PoC chèn `%0d%0a` + header canary vào param. Dương tính khi header
    canary XUẤT HIỆN trong response headers (server parse CRLF). Âm tính: payload
    chỉ bị echo ở dạng encode/escape trong body, WAF, giống baseline."""
    threshold = default_threshold() if threshold is None else float(threshold)
    header_name, _, header_value = str(payload).partition(":")
    header_name = header_name.strip()
    header_value = header_value.strip()
    injected = poc.headers.get(header_name.lower())
    diff = {
        "status": {"baseline": baseline.status, "poc": poc.status},
        "header": {"expect": header_name, "poc": injected},
        "body_length": {"baseline": baseline.body_length, "poc": poc.body_length},
    }
    if baseline.error or poc.error:
        return _probe_error(baseline, poc, diff)

    if header_name and injected is not None and (
        not header_value or injected.strip() == header_value
    ):
        score = SCORE_HEADER_INJECTED
        return HTTPAnalysis(
            patterns=["header_injected"], signals=["header_injected"], score=score,
            verdict=decide_verdict(score, threshold),
            reason=(f"Header canary '{header_name}' xuất hiện trong response — "
                    "server parse CRLF do người dùng kiểm soát"), diff=diff,
        )

    if _same_response(baseline, poc):
        return _reject(["no_diff"], 0.0,
                       "Response giống hệt baseline — param không phản ứng với CRLF", diff)
    if _waf_hit(poc):
        return _reject(["waf_block"], 0.0,
                       "Response PoC trông giống trang chặn WAF — false positive", diff)
    full_payload = "\r\n" + str(payload)
    low_body = poc.body.lower()
    escaped = [quote(full_payload, safe="").lower(), quote(payload, safe="").lower(),
               html.escape(payload).lower()]
    if any(v in low_body for v in escaped):
        return _reject(["payload_escaped"], 0.0,
                       "CRLF payload chỉ xuất hiện ở dạng đã encode/escape trong body "
                       "— server đã vô hiệu hoá", diff)
    return _reject(["header_not_injected"], 0.0,
                   "Header canary không xuất hiện trong response — không xác nhận CRLF", diff)


# ── SSTI ──


def analyze_ssti(
    baseline: ProbeProfile, poc: ProbeProfile, payload: str,
    threshold: float | None = None,
) -> HTTPAnalysis:
    """SSTI: payload `{{7*7}}` — dương tính khi kết quả phép tính (`49`) xuất
    hiện trong PoC VÀ không có sẵn ở baseline (baseline diff). Âm tính: payload
    chỉ bị reflect nguyên văn (đã escape), số 49 có sẵn ở baseline, WAF."""
    threshold = default_threshold() if threshold is None else float(threshold)
    expect = "49" if "7*7" in str(payload) else ""
    diff = {
        "status": {"baseline": baseline.status, "poc": poc.status},
        "body_length": {"baseline": baseline.body_length, "poc": poc.body_length},
        "expect": expect,
    }
    if baseline.error or poc.error:
        return _probe_error(baseline, poc, diff)

    if expect and expect in poc.body and expect not in baseline.body:
        score = SCORE_MATH_EVAL
        return HTTPAnalysis(
            patterns=["math_evaluated"], signals=["math_evaluated"], score=score,
            verdict=decide_verdict(score, threshold),
            reason=(f"Kết quả phép tính của payload ('{expect}') xuất hiện trong PoC "
                    "và vắng ở baseline — template engine đã evaluate"), diff=diff,
        )

    if _waf_hit(poc):
        return _reject(["waf_block"], 0.0,
                       "Response PoC trông giống trang chặn WAF — false positive", diff)
    if expect and expect in baseline.body:
        return _reject(["ambiguous_baseline"], 0.0,
                       f"'{expect}' có sẵn ở baseline — không phải kết quả payload "
                       "(false positive kiểu 'số ở đâu đó')", diff)
    if _same_response(baseline, poc):
        return _reject(["no_diff"], 0.0,
                       "Response giống hệt baseline — param không phản ứng", diff)
    if str(payload) in poc.body:
        return _reject(["payload_escaped"], 0.0,
                       "Payload chỉ bị reflect nguyên văn — template engine không "
                       "evaluate (đã escape/tắt)", diff)
    return _reject(["math_not_evaluated"], 0.0,
                   "Không thấy kết quả phép tính trong response — không xác nhận SSTI", diff)


# ── Missing security headers (informational) ──


def analyze_headers(poc: ProbeProfile, threshold: float | None = None) -> HTTPAnalysis:
    """Missing security headers: CHỈ THÔNG TIN — luôn verdict 'informational',
    score 0.0: KHÔNG bao giờ thành Finding/report (đề bài #15: chỉ hiển thị).
    Evidence ghi danh sách headers thiếu để người dùng tự cân nhắc."""
    present_map = {k.lower(): v for k, v in (poc.headers or {}).items()}
    missing = [h for h in SECURITY_HEADERS if h not in present_map]
    present = [h for h in SECURITY_HEADERS if h in present_map]
    patterns = [f"missing:{h}" for h in missing]
    if poc.error:
        patterns = ["probe_error"] + patterns
    detail = {"missing": missing, "present": present, "status": poc.status}
    return HTTPAnalysis(
        patterns=patterns, signals=[], score=0.0, verdict="informational",
        reason=(f"Thiếu {len(missing)}/{len(SECURITY_HEADERS)} security headers — chỉ "
                "hiển thị (informational), KHÔNG tự tạo report cho class này"),
        diff={"status": poc.status, "headers": present_map},
        detail=detail,
    )


def cap_headers_severity(severity: str) -> str:
    """Severity trần 'low' cho class headers (informational — mặc định thấp)."""
    return detect.cap_severity(severity, "low")


# ── Info disclosure / debug endpoints ──


def analyze_disclosure(
    baseline: ProbeProfile, poc: ProbeProfile, payload: str,
    threshold: float | None = None,
) -> HTTPAnalysis:
    """Info disclosure/debug: PoC = GET endpoint; baseline = GET root host —
    marker nhạy cảm phải MỚI xuất hiện ở endpoint so với root. Dương tính khi
    marker STRONG (secret/private key/phpinfo/actuator…). Stack trace đơn thuần
    → dưới ngưỡng (xem tay). Âm tính: 403/404, WAF, giống baseline."""
    threshold = default_threshold() if threshold is None else float(threshold)
    low_p = poc.body.lower()
    low_b = baseline.body.lower()
    strong = [m for m in _STRONG_DISCLOSURE_MARKERS if m in low_p and m not in low_b]
    weak = [m for m in _WEAK_DISCLOSURE_MARKERS if m in low_p and m not in low_b]
    diff = {
        "status": {"baseline": baseline.status, "poc": poc.status},
        "body_length": {"baseline": baseline.body_length, "poc": poc.body_length},
        "markers": {"strong": strong, "weak": weak},
    }
    if baseline.error or poc.error:
        return _probe_error(baseline, poc, diff)

    if strong:
        score = SCORE_DISCLOSURE_STRONG
        return HTTPAnalysis(
            patterns=["sensitive_content"], signals=["sensitive_content"], score=score,
            verdict=decide_verdict(score, threshold),
            reason=(f"Endpoint lộ nội dung nhạy cảm ({', '.join(strong[:3])}) mà root "
                    "host không có — info disclosure xác nhận"), diff=diff,
            detail={"markers": strong},
        )

    if _same_response(baseline, poc):
        return _reject(["no_diff"], 0.0,
                       "Response giống hệt baseline (root host) — endpoint không có gì "
                       "khác", diff)
    if _waf_hit(poc):
        return _reject(["waf_block"], 0.0,
                       "Response PoC trông giống trang chặn WAF — false positive", diff)
    if poc.status in (403, 404):
        return _reject(["endpoint_missing"], 0.0,
                       f"PoC trả HTTP {poc.status} — debug endpoint không tồn tại/nghiêm "
                       "cấm (tool output đã cũ)", diff)
    if weak:
        return _reject(["weak_disclosure_only"], SCORE_CORS_REFLECT_ONLY,
                       "Chỉ thấy stack trace/debug message — chưa đủ làm Finding, cần "
                       "xem tay", diff, detail={"markers": weak})
    return _reject(["no_sensitive_content"], 0.0,
                   "Endpoint phản hồi nhưng không có marker nội dung nhạy cảm", diff)


# ───────────────────────────── pipeline (async) ─────────────────────────────


@dataclass(frozen=True)
class VerifySpec:
    """Khai báo verify của 1 lớp: dựng (baseline, PoC) request + hàm analyze."""
    make_requests: Callable[[dict, str], tuple[dict, dict]]
    analyze: Callable[..., HTTPAnalysis]


def _cors_requests(candidate: dict, payload: str) -> tuple[dict, dict]:
    url = candidate["target"]
    return (
        {"url": url, "method": "GET", "headers": {}, "body": None},
        {"url": url, "method": "GET", "headers": {"origin": payload}, "body": None},
    )


def _dirlist_requests(candidate: dict, payload: str) -> tuple[dict, dict]:
    url = candidate["target"]
    baseline_url = url + ("" if url.endswith("/") else "/") + ".vulhunt-baseline"
    return (
        {"url": baseline_url, "method": "GET", "headers": {}, "body": None},
        {"url": url, "method": "GET", "headers": {}, "body": None},
    )


def _graphql_requests(candidate: dict, payload: str) -> tuple[dict, dict]:
    url = candidate["target"]
    headers = {"content-type": "application/json"}
    return (
        {"url": url, "method": "POST", "headers": headers,
         "body": json.dumps({"query": "{ __typename }"})},
        {"url": url, "method": "POST", "headers": headers,
         "body": json.dumps({"query": "{ __schema { types { name } } }"})},
    )


def _param_requests(candidate: dict, payload: str) -> tuple[dict, dict]:
    param = (candidate.get("param") or "").split(",")[0].strip()
    target = candidate["target"]
    return (
        {"url": inject_param(target, param, BENIGN_PARAM_VALUE),
         "method": "GET", "headers": {}, "body": None},
        {"url": inject_param(target, param, payload),
         "method": "GET", "headers": {}, "body": None},
    )


def _crlf_requests(candidate: dict, payload: str) -> tuple[dict, dict]:
    payload = payload or "X-Vulhunt-Injection: 1"
    return _param_requests(candidate, "\r\n" + payload)


def _ssti_requests(candidate: dict, payload: str) -> tuple[dict, dict]:
    return _param_requests(candidate, payload or default_ssti_payload())


def _headers_requests(candidate: dict, payload: str) -> tuple[dict, dict]:
    req = {"url": candidate["target"], "method": "GET", "headers": {}, "body": None}
    return (dict(req), dict(req))


def _disclosure_requests(candidate: dict, payload: str) -> tuple[dict, dict]:
    target = candidate["target"]
    parts = urlsplit(target)
    root = f"{parts.scheme}://{parts.netloc}/"
    return (
        {"url": root, "method": "GET", "headers": {}, "body": None},
        {"url": target, "method": "GET", "headers": {}, "body": None},
    )


_SPECS: dict[str, VerifySpec] = {
    "cors": VerifySpec(_cors_requests, analyze_cors),
    "dirlist": VerifySpec(_dirlist_requests, analyze_dirlist),
    "graphql": VerifySpec(_graphql_requests, analyze_graphql),
    "crlf": VerifySpec(_crlf_requests, analyze_crlf),
    "ssti": VerifySpec(_ssti_requests, analyze_ssti),
    "headers": VerifySpec(_headers_requests, analyze_headers),
    "disclosure": VerifySpec(_disclosure_requests, analyze_disclosure),
}


def _default_payload(cls: str) -> str:
    if cls == "cors":
        return default_cors_origin()
    if cls == "ssti":
        return default_ssti_payload()
    if cls == "crlf":
        return "X-Vulhunt-Injection: 1"
    return ""


_VERDICT_SQL = f"""
UPDATE candidates SET status = $2, confidence = $3, confidence_threshold = $4,
    reject_reason = $5, verify_evidence_path = $6, verify_session_id = $7,
    baseline_session_id = $8
WHERE id = $1 RETURNING {CANDIDATE_COLS}
"""

# class informational: KHÔNG đổi status/verdict — chỉ ép severity + evidence
_INFO_SQL = f"""
UPDATE candidates SET severity = $2, verify_evidence_path = $3,
    verify_session_id = $4, baseline_session_id = $5
WHERE id = $1 RETURNING {CANDIDATE_COLS}
"""


def _evidence_record(
    candidate: dict,
    cls: str,
    payload: str,
    threshold: float,
    analysis: HTTPAnalysis,
    baseline: ProbeProfile | None,
    baseline_session_id: int | None,
    poc: ProbeProfile | None,
    poc_session_id: int | None,
    unparsed: ProbeProfile | None = None,
) -> dict:
    """Nội dung file evidence của vòng verify batch A — baseline + PoC + phân
    tích + detail tuỳ lớp (headers thiếu, marker trúng…)."""

    def _profile_or_parse_error(p: ProbeProfile | None) -> dict:
        if p is not None:
            return p.to_dict()
        if unparsed is not None:
            return {"parse_error": True, "stdout_head": (unparsed.body or "")[:2000]}
        return {"skipped": True}

    return {
        "schema": "vulhunt.httpverify-evidence/1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate["id"],
        "run_id": candidate["run_id"],
        "class": cls,
        "target": candidate.get("target"),
        "param": candidate.get("param"),
        "payload": payload,
        "threshold": threshold,
        "baseline": _profile_or_parse_error(baseline),
        "poc": _profile_or_parse_error(poc),
        "baseline_session_id": baseline_session_id,
        "verify_session_id": poc_session_id,
        "analysis": {
            "signals": analysis.signals,
            "patterns": analysis.patterns,
            "score": analysis.score,
            "verdict": analysis.verdict,
            "reason": analysis.reason,
            "diff": analysis.diff,
            "detail": analysis.detail,
        },
    }


async def run_http_verification(
    pool: asyncpg.Pool,
    candidate: dict,
    payload: str | None = None,
    probe: "ProbeCallable | None" = None,
    threshold: float | None = None,
) -> dict:
    """Dispatch trọn vòng verify 1 Candidate thuộc 7 lớp HTTP-only (#15).

    `probe(script, target)` là seam thực thi (mặc định sandbox.run_verify_
    session — container ephemeral, scope + egress + rate limit). Target bị
    chặn scope → ProbeBlocked (candidate trả về trạng thái cũ); lỗi môi
    trường → RuntimeError cho tầng trên retry — KHÔNG verdict oan.
    """
    cls = str(candidate.get("class") or "").strip()
    if cls not in HTTP_VERIFY_CLASSES:
        raise ValueError(
            f"class '{cls}' không thuộc batch A HTTP-only: {', '.join(HTTP_VERIFY_CLASSES)}"
        )
    spec = _SPECS[cls]
    candidate_id = candidate["id"]
    run_id = candidate["run_id"]
    threshold = default_threshold() if threshold is None else float(threshold)
    payload = (payload or _default_payload(cls)).strip()
    param = (candidate.get("param") or "").split(",")[0].strip()
    prev_status = candidate.get("status") or "new"
    informational = cls in INFORMATIONAL_CLASSES

    async def _update_verdict(status: str, score: float | None = None,
                              reject_reason: str | None = None,
                              evidence: str | None = None,
                              poc_sid: int | None = None,
                              base_sid: int | None = None) -> dict | None:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                _VERDICT_SQL, candidate_id, status, score, threshold,
                reject_reason, evidence, poc_sid, base_sid,
            )
        return dict(row) if row else None

    async def _update_info(evidence: str | None,
                           poc_sid: int | None,
                           base_sid: int | None) -> dict | None:
        severity = cap_headers_severity(candidate.get("severity") or "info")
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                _INFO_SQL, candidate_id, severity, evidence, poc_sid, base_sid,
            )
        return dict(row) if row else None

    def _summary(verdict: str, score: float, reason: str,
                 analysis: HTTPAnalysis, evidence: str | None,
                 base_sid: int | None, poc_sid: int | None) -> dict:
        return {
            "candidate_id": candidate_id,
            "run_id": run_id,
            "class": cls,
            "payload": payload,
            "verdict": verdict,
            "score": round(float(score), 4),
            "threshold": threshold,
            "reason": reason,
            "signals": analysis.signals,
            "patterns": analysis.patterns,
            "detail": analysis.detail,
            "reportable": cls not in INFORMATIONAL_CLASSES,
            "evidence_path": evidence,
            "baseline_session_id": base_sid,
            "verify_session_id": poc_sid,
        }

    # class chèn PoC qua param — thiếu param thì không có PoC: rejected ngay
    if cls in _PARAM_CLASSES and not param:
        analysis = HTTPAnalysis(
            patterns=["no_param"], score=0.0, verdict="rejected",
            reason="Candidate không có param để chèn PoC",
        )
        evidence = write_verify_evidence(run_id, candidate_id, _evidence_record(
            candidate, cls, payload, threshold, analysis, None, None, None, None,
        ))
        await _update_verdict("rejected", 0.0, analysis.reason, evidence)
        return _summary("rejected", 0.0, analysis.reason, analysis, evidence, None, None)

    baseline_req, poc_req = spec.make_requests(candidate, payload)

    if probe is None:
        run = await sandbox.resolve_run(pool, run_id)
        if run is None:
            raise ValueError("không có Run nào — không thể xác minh qua sandbox")

        async def probe(script: str, target: str, _run: asyncpg.Record = run) -> dict:
            return await sandbox.run_verify_session(pool, _run, script, target)

    if not informational:
        await _update_verdict("verifying")

    async def _run_probe(req: dict) -> dict:
        res = await probe(build_http_probe_script(**req), candidate["target"])
        if res.get("status") == "blocked":
            if not informational:
                await _update_verdict(prev_status)  # không verdict oan
            raise ProbeBlocked(res.get("reason") or "target bị chặn tại bridge")
        if res.get("status") == "error":
            if not informational:
                await _update_verdict(prev_status)
            raise RuntimeError(
                f"lỗi môi trường sandbox: {res.get('reason') or res.get('stderr', '')}"
            )
        return res

    base_res = await _run_probe(baseline_req)
    poc_res = await _run_probe(poc_req)

    baseline = parse_probe(base_res.get("stdout") or "")
    poc = parse_probe(poc_res.get("stdout") or "")
    if cls == "headers":
        analysis = analyze_headers(poc, threshold)
        diff_src = poc if poc is None else None
    elif baseline is None or poc is None:
        analysis = HTTPAnalysis(
            patterns=["probe_error"], score=0.0, verdict="rejected",
            reason="Không đọc được profile response từ stdout sandbox (thiếu marker/JSON đứt)",
        )
        diff_src = (baseline or poc)
    else:
        analysis = spec.analyze(baseline, poc, payload, threshold)
        diff_src = None

    evidence = write_verify_evidence(run_id, candidate_id, _evidence_record(
        candidate, cls, payload, threshold, analysis,
        baseline, base_res.get("session_id"),
        poc, poc_res.get("session_id"),
        unparsed=diff_src,
    ))
    base_sid = base_res.get("session_id")
    poc_sid = poc_res.get("session_id")

    if informational:
        # chỉ hiển thị: severity ép trần 'low' + evidence — KHÔNG verdict,
        # KHÔNG đổi status → không bao giờ tự thành Finding/report (#15)
        await _update_info(evidence, poc_sid, base_sid)
    else:
        await _update_verdict(
            analysis.verdict, analysis.score,
            analysis.reason if analysis.verdict == "rejected" else None,
            evidence, poc_sid, base_sid,
        )
    await add_log(
        pool, run_id,
        f"Verify HTTP ({cls}) Candidate #{candidate_id}: {analysis.verdict} "
        f"(score {analysis.score:.2f} / ngưỡng {threshold:.2f}) · patterns: "
        f"{', '.join(analysis.patterns) or '—'}"
        + (f" · evidence: {evidence}" if evidence else ""),
    )
    return _summary(analysis.verdict, analysis.score, analysis.reason,
                    analysis, evidence, base_sid, poc_sid)


# ───────────────────────────── detection batch A ─────────────────────────────
# 3 tool chuyên dụng bổ sung cho Detection Phase chính (nuclei templates đã quét
# toàn bề mặt): graphql-cop + graphw00f (GraphQL), crlfuzz (CRLF), SSTImap (SSTI)


_GRAPHQL_URL_RE = re.compile(r"graphql|gql", re.IGNORECASE)


def build_graphw00f_args(url: str) -> list[str]:
    """graphw00f: fingerprint mode (-f) — engine GraphQL vào evidence."""
    return ["-t", url, "-f"]


def build_graphql_cop_args(url: str) -> list[str]:
    """graphql-cop: chạy mọi security check — stdout JSON (-o json)."""
    return ["-t", url, "-o", "json"]


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def parse_graphql_cop(stdout: str) -> list[dict]:
    """graphql-cop -o json → list check {title, result, danger…}; giữ lại check
    kết luận vulnerable (result/danger true, hay chữ Yes/Active trong stdout
    text). stdout rác → []."""
    try:
        data = json.loads(stdout)
    except ValueError:
        hits = []
        for line in (stdout or "").splitlines():
            low = _ANSI_RE.sub("", line).lower()
            if "introspection" in low and any(
                t in low for t in ("yes", "true", "vulnerable", "active")
            ):
                hits.append({"title": "Introspection", "vulnerable": True})
        return hits
    items = data if isinstance(data, list) else [data]
    hits = []
    for it in items:
        if not isinstance(it, dict):
            continue
        result = it.get("result")
        vulnerable = result is True or it.get("danger") is True or (
            isinstance(result, str) and result.strip().lower() in ("yes", "true", "vulnerable")
        )
        if vulnerable:
            hits.append(it)
    return hits


def parse_graphw00f(stdout: str) -> str | None:
    """graphw00f: '[*] Discovered GraphQL Engine: (<engine>)' → engine (đã bỏ
    ANSI colour); không xác định được → None."""
    clean = _ANSI_RE.sub("", stdout or "")
    m = re.search(r"Discovered GraphQL Engine:\s*\((.*)\)", clean)
    return m.group(1).strip() if m else None


def parse_crlfuzz(stdout: str) -> list[str]:
    """crlfuzz in mỗi URL vulnerable trên 1 dòng → list URL."""
    return [
        line.strip() for line in (stdout or "").splitlines()
        if line.strip().startswith("http")
    ]


def parse_sstimap(stdout: str) -> list[dict]:
    """SSTImap: '<Engine> plugin has confirmed injection…' (prefix [+] màu,
    ANSI) → 1 hit kèm tên engine. Không hit → []."""
    hits = []
    seen_engines: set[str] = set()
    for line in (stdout or "").splitlines():
        clean = _ANSI_RE.sub("", line)
        m = re.search(r"(\S+)\s+plugin has confirmed", clean)
        if m and "[+]" in clean and m.group(1) not in seen_engines:
            seen_engines.add(m.group(1))
            hits.append({
                "title": f"SSTI ({m.group(1)})",
                "engine": m.group(1),
                "vulnerable": True,
            })
    return hits


def _severity(value: str) -> str:
    """Chuẩn hoá severity từ output tool — lạ/không có thì 'medium' (hit tool
    chuyên dụng đã có thông tin trước, còn qua vòng verify nữa)."""
    try:
        return detect.validate_severity(value)
    except ValueError:
        return "medium"


async def run_catalog_detection(
    pool: asyncpg.Pool,
    run: asyncpg.Record | dict,
    tool_runner=None,
    live_urls: list[str] | None = None,
    classed_urls: list[str] | None = None,
) -> dict:
    """Detection batch A của 1 Run (chạy sau Detection Phase chính): 3 tool
    chuyên dụng cho GraphQL/CRLF/SSTI trên bề mặt đã thu (4 lớp còn lại — cors,
    dirlist, headers, disclosure — nuclei templates trong Detection Phase chính
    đã cover, map_class trả đúng class). Mỗi hit → Candidate kèm evidence;
    tool lỗi coi như không phát hiện gì; target ngoài Scope bị chặn như mọi
    Tool Execution."""
    run_id = run["id"]
    snapshot = run["scope_snapshot"]
    if isinstance(snapshot, str):
        snapshot = json.loads(snapshot)
    ctx: ToolContext = build_context(
        run_id,
        run["rate_limit_rps"],
        run["ident_header_name"],
        run["ident_header_value"],
        snapshot,
        bool(run["allow_non_prod"]),
    )

    if live_urls is None or classed_urls is None:
        db_live, db_classed = await detect._load_targets(pool, run_id)
        live_urls = db_live if live_urls is None else live_urls
        classed_urls = db_classed if classed_urls is None else classed_urls

    targets = detect.build_targets(live_urls, classed_urls)
    allowed, blocked = await filter_scope(pool, ctx, targets, "catalog-a")
    if not targets:
        return {"candidates": 0, "blocked": 0}
    await add_log(
        pool, run_id,
        f"Batch A: {len(allowed)}/{len(targets)} target trong Scope "
        f"(validator chặn {blocked}) — graphql-cop · crlfuzz · sstimap",
    )

    rows: list[CandidateRow] = []
    seen: set[tuple] = set()
    allowed_hosts = {urlsplit(u).netloc for u in allowed}

    async def add_candidate(
        raw_target: str, cls: str, template_id: str, title: str,
        severity: str, matcher: str, raw_finding: dict,
    ) -> None:
        target = str(raw_target).strip()
        if not target.startswith("http"):
            return
        # stdout trôi — hit của tool không thuộc host nào đã qua validator thì bỏ
        if urlsplit(target).netloc not in allowed_hosts:
            return
        key = (target, cls, detect.param_key(target))
        if key in seen:
            return
        seen.add(key)
        rows.append(CandidateRow(
            run_id=run_id,
            target=target,
            cls=cls,
            param=key[2],
            template_id=template_id,
            title=title,
            severity=_severity(severity),
            matcher_name=matcher,
            status="new",
            evidence_path=write_verify_evidence(run_id, len(rows) + 1, {
                "schema": "vulhunt.catalog-detection-evidence/1",
                "template-id": template_id,
                "matched-at": target,
                **raw_finding,
            }),
        ))

    # ── GraphQL: graphw00f (fingerprint) + graphql-cop (introspection) ──
    gh_targets = [u for u in allowed if _GRAPHQL_URL_RE.search(u)]
    gh_targets = gh_targets[:CATALOG_MAX_TARGETS_PER_TOOL]
    for url in gh_targets:
        fp_res = await execute_tool(
            pool, ctx, "graphw00f", build_graphw00f_args(url), runner=tool_runner
        )
        service = parse_graphw00f(fp_res.stdout) if fp_res.exit_code == 0 else None
        cop_res = await execute_tool(
            pool, ctx, "graphql-cop", build_graphql_cop_args(url), runner=tool_runner
        )
        if cop_res.exit_code != 0:
            await add_log(
                pool, run_id,
                f"graphql-cop exit {cop_res.exit_code} cho {url} — bỏ qua",
                level="error",
            )
            continue
        title = f"GraphQL Introspection ({service})" if service else "GraphQL Introspection"
        for hit in parse_graphql_cop(cop_res.stdout):
            if str(hit.get("title") or "").lower() != "introspection":
                continue  # batch A chỉ Candidate cho lớp GraphQL introspection
            await add_candidate(
                url, "graphql", "graphql-cop/introspection", title, "medium",
                str(hit.get("method") or "query"), {"hit": hit, "service": service},
            )

    # ── CRLF: crlfuzz (stdin = danh sách URL) ──
    if allowed:
        res = await execute_tool(pool, ctx, "crlfuzz", [], stdin="\n".join(allowed),
                                 runner=tool_runner)
        if res.exit_code == 0:
            for url in parse_crlfuzz(res.stdout):
                await add_candidate(
                    url, "crlf", "crlfuzz/crlf", "CRLF Injection", "high",
                    "crlfuzz", {"matched-at": url},
                )
        else:
            await add_log(
                pool, run_id, f"crlfuzz exit {res.exit_code} — không có match",
                level="error",
            )

    # ── SSTI: SSTImap trên URL có param (chạy per-URL) ──
    param_urls = [u for u in allowed if urlsplit(u).query]
    param_urls = param_urls[:CATALOG_MAX_TARGETS_PER_TOOL]
    for url in param_urls:
        res = await execute_tool(pool, ctx, "sstimap", ["-u", url], runner=tool_runner)
        if res.exit_code != 0:
            continue
        for hit in parse_sstimap(res.stdout):
            await add_candidate(
                url, "ssti", "sstimap/ssti", f"SSTI ({hit.get('engine')})", "high",
                "sstimap", {"matched-at": url, "hit": hit},
            )

    await detect._insert_candidates(pool, rows)
    await add_log(
        pool, run_id,
        f"Batch A: {len(rows)} Candidate từ tool chuyên dụng "
        f"(graphql {len(gh_targets)} · crlfuzz toàn bề mặt · sstimap "
        f"{len(param_urls)} URL có param) — chờ vòng xác minh tương ứng",
    )
    return {"candidates": len(rows), "blocked": blocked}
