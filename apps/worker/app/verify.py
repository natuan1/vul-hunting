"""Vòng xác minh open redirect (ticket #12) — viên đạn-thữa của Detection Phase.

Candidate class `redirect` → **baseline capture** (request vô hại, ghi lại
status/headers/body-length/content-type) → soạn PoC → **run_in_sandbox**
(MỌI payload chạy trong container ephemeral — agent/tool không bao giờ thực
thi trực tiếp) → **response diff analysis SO VỚI BASELINE**: câu hỏi là
"response khác baseline theo hướng khai thác được?" — KHÔNG phải "payload có
xuất hiện trong response?". WAF block page / payload bị encode-escape /
payload nằm trong error log đều kết luận false positive → **confidence score**
0.0–1.0; score ≥ ngưỡng (mặc định 0.85, cấu hình qua VERIFY_CONFIDENCE_
THRESHOLD) → Candidate thành **Finding** (status `verified`) kèm evidence
diff; dưới ngưỡng → `rejected` kèm lý do + pattern log.

Phần thuần (probe script, parser, diff analysis, scoring, evidence writer)
tách riêng để test; pipeline nhận `probe` là seam thay `sandbox.
run_verify_session` (production quay container thật, test giả lập).
"""

import html
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import asyncpg

from . import sandbox
from .config import settings
from .detect import CANDIDATE_COLS
from .tools import add_log

log = logging.getLogger("verify")

# seam thực thi của pipeline: probe(script, target) → dict verify session
ProbeCallable = Callable[[str, str], Awaitable[dict]]

# marker dòng trong stdout sandbox — parse_probe đọc JSON ở dòng kế tiếp
PROBE_MARKER = "###VULHUNT_PROBE_JSON###"

# giá trị vô hại cho baseline: cùng URL/param nhưng KHÔNG phải payload
BENIGN_PARAM_VALUE = "https://example.com/"

# điểm số theo tín hiệu khai thác được (đơn signals, lấy max nếu nhiều)
SCORE_LOCATION_REDIRECT = 0.95  # 3xx + Location trỏ thẳng tới payload
SCORE_META_REFRESH = 0.90       # <meta http-equiv="refresh" url=payload>
SCORE_JS_REDIRECT = 0.85        # location.href / window.location = payload
SCORE_BODY_REFLECTION = 0.50    # payload raw trong body nhưng không có redirect

# trang chặn WAF hay gặp — chỉ xét khi KHÔNG có tín hiệu khai thác được
_WAF_BLOCK_STATUSES = (403, 406, 418, 429, 501)
_WAF_MARKERS = (
    "request blocked", "access denied", "permission denied", "blocked by",
    "captcha", "cloudflare", "incapsula", "sucuri", "imperva", "fortiweb",
    "barracuda", "radware", "web application firewall",
)
# payload chỉ xuất hiện trong error log / stack trace → false positive
_ERROR_MARKERS = (
    "traceback", "stack trace", "exception", "fatal error", "syntax error",
    "parse error", "warning:", "error:", "notice:", "sqlstate", "undefined ",
)

# token cơ chế JS redirect — chỉ tính khi NẰM GẦN payload (xem _near_tokens)
_JS_REDIRECT_TOKENS = (
    "location.href", "location.replace", "window.location",
    "document.location", "location=",
)
# bán kính (ký tự) coi token là "cơ chế trỏ tới payload" — meta tag/statement
# JS redirect ngắn; token xa hơn chỉ là trùng hợp trong trang
_NEIGHBOUR_WINDOW = 200


def _near_tokens(body_low: str, payload: str, tokens: tuple[str, ...]) -> bool:
    """True nếu quanh MỘT lần xuất hiện payload (± _NEIGHBOUR_WINDOW ký tự) có
    ít nhất 1 token — cơ chế redirect phải trỏ tới payload, không phải đứng
    đâu đó trong trang."""
    pl = payload.lower()
    start = body_low.find(pl)
    while start != -1:
        window = body_low[max(0, start - _NEIGHBOUR_WINDOW):start + len(pl) + _NEIGHBOUR_WINDOW]
        if any(t in window for t in tokens):
            return True
        start = body_low.find(pl, start + 1)
    return False


# ───────────────────────────── seam thuần (có test) ─────────────────────────────


@dataclass
class ProbeProfile:
    """Profile response của 1 lần probe (baseline hoặc PoC) — ghi lại đúng thứ
    ticket yêu cầu: status, headers, content-type, body-length (cộng body để
    diff). `error` ≠ None nghĩa là probe không lấy được response nào."""

    status: int
    headers: dict[str, str]
    content_type: str
    body_length: int
    body: str
    error: str | None = None
    url: str | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "headers": self.headers,
            "content_type": self.content_type,
            "body_length": self.body_length,
            "body": self.body,
            "error": self.error,
        }


@dataclass
class RedirectAnalysis:
    """Kết quả diff PoC so với baseline: pattern log (mọi pattern khớp), tín
    hiệu khai thác được, confidence score 0.0–1.0 và verdict theo ngưỡng."""

    patterns: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    score: float = 0.0
    verdict: str = "rejected"
    reason: str = ""
    diff: dict = field(default_factory=dict)


def default_threshold() -> float:
    """Ngưỡng confidence hiện hành (VERIFY_CONFIDENCE_THRESHOLD, mặc định 0.85)."""
    return float(settings.verify_confidence_threshold)


def build_probe_script(url: str) -> str:
    """Probe script (sh) chạy TRONG sandbox: python3 fetch `url`, KHÔNG follow
    redirect (302 phải được nhìn nguyên bản để diff), header định danh đọc từ
    env do bridge truyền vào, in ra profile JSON sau PROBE_MARKER."""
    return (
        "python3 - <<'PY'\n"
        "import json, os, urllib.request, urllib.error\n"
        f"URL = {json.dumps(url)}\n"
        f"MARKER = {json.dumps(PROBE_MARKER)}\n"
        "\n"
        "\n"
        "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
        "    def redirect_request(self, req, fp, code, msg, headers, newurl):\n"
        "        return None  # KHÔNG follow redirect — giữ 302 nguyên bản\n"
        "\n"
        "\n"
        "def _emit(profile):\n"
        "    print(MARKER)\n"
        "    print(json.dumps(profile, ensure_ascii=False))\n"
        "\n"
        "\n"
        "ident_name = os.environ.get(\"IDENT_HEADER_NAME\")\n"
        "ident_value = os.environ.get(\"IDENT_HEADER_VALUE\")\n"
        "headers = {ident_name: ident_value} if ident_name and ident_value else {}\n"
        "opener = urllib.request.build_opener(_NoRedirect)\n"
        "request = urllib.request.Request(URL, headers=headers, method=\"GET\")\n"
        "try:\n"
        "    resp = opener.open(request, timeout=25)\n"
        "except urllib.error.HTTPError as exc:  # 3xx/4xx/5xx vẫn là response để diff\n"
        "    resp = exc\n"
        "except Exception as exc:\n"
        "    _emit({\"url\": URL, \"status\": 0, \"error\": str(exc)[:300],\n"
        "           \"headers\": {}, \"content_type\": \"\", \"body_length\": 0,\n"
        "           \"body\": \"\"})\n"
        "    raise SystemExit(0)\n"
        "body = resp.read(65536)  # cap body — đủ diff, không ngập log\n"
        "_emit({\n"
        "    \"url\": URL,\n"
        "    \"status\": resp.getcode() or 0,\n"
        "    \"headers\": {str(k).lower(): str(v) for k, v in resp.headers.items()},\n"
        "    \"content_type\": str(resp.headers.get(\"content-type\", \"\")),\n"
        "    # body-length THẬT theo content-length header (fallback: số byte đọc được)\n"
        "    \"body_length\": int(resp.headers.get(\"content-length\") or 0) or len(body),\n"
        "    \"body\": body.decode(\"utf-8\", \"replace\")[:50000],\n"
        "})\n"
        "PY"
    )


def parse_probe(stdout: str) -> ProbeProfile | None:
    """Đọc profile từ stdout sandbox: JSON ở dòng đầu tiên không trống SAU
    marker; thiếu marker hoặc JSON đứt → None (coi như probe không đọc được)."""
    lines = (stdout or "").splitlines()
    for i, line in enumerate(lines):
        if PROBE_MARKER not in line:
            continue
        for nxt in lines[i + 1:]:
            nxt = nxt.strip()
            if not nxt:
                continue
            try:
                raw = json.loads(nxt)
            except ValueError:
                return None
            return ProbeProfile(
                status=int(raw.get("status") or 0),
                headers={str(k): str(v) for k, v in (raw.get("headers") or {}).items()},
                content_type=str(raw.get("content_type") or ""),
                body_length=int(raw.get("body_length") or 0),
                body=str(raw.get("body") or ""),
                error=raw.get("error"),
                url=raw.get("url"),
            )
    return None


def inject_param(url: str, param: str, value: str) -> str:
    """Đặt/ thay 1 query param trong URL (giữ các param khác) — URL cho baseline
    và PoC cùng hình dạng, chỉ khác giá trị param."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    out: list[tuple[str, str]] = []
    for k, v in pairs:
        if k == param:
            replaced = True
            out.append((k, value))
        else:
            out.append((k, v))
    if not replaced:
        out.append((param, value))
    query = urlencode(out, quote_via=quote, safe="/")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _waf_marker(body: str) -> str | None:
    low = body.lower()
    return next((m for m in _WAF_MARKERS if m in low), None)


def _escaped_variants(payload: str) -> list[str]:
    """Các dạng payload đã bị encode/escape hay gặp trong response."""
    return [
        quote(payload, safe=""),        # percent-encode toàn bộ
        quote(payload, safe="/"),       # percent-encode giữ '/'
        html.escape(payload),           # HTML entity
    ]


def analyze_redirect(
    baseline: ProbeProfile,
    poc: ProbeProfile,
    payload: str,
    threshold: float | None = None,
) -> RedirectAnalysis:
    """Diff PoC SO VỚI BASELINE theo hướng khai thác được + chấm confidence.

    Âm tính (đề bài): WAF block page, payload bị encode/escape, payload nằm
    trong error log, response giống hệt baseline → rejected, KHÔNG báo thật.
    Dương tính: 3xx Location trỏ tới payload / meta refresh / JS redirect.
    """
    threshold = default_threshold() if threshold is None else float(threshold)
    loc_b = baseline.headers.get("location", "")
    loc_p = poc.headers.get("location", "")
    diff = {
        "status": {"baseline": baseline.status, "poc": poc.status},
        "location": {"baseline": loc_b, "poc": loc_p},
        "content_type": {"baseline": baseline.content_type, "poc": poc.content_type},
        "body_length": {
            "baseline": baseline.body_length,
            "poc": poc.body_length,
            "delta": poc.body_length - baseline.body_length,
        },
    }

    def _rejected(patterns: list[str], score: float, reason: str) -> RedirectAnalysis:
        return RedirectAnalysis(
            patterns=patterns, signals=[], score=score,
            verdict="rejected", reason=reason, diff=diff,
        )

    # probe không lấy được response nào (mạng/DNS chết trong sandbox)
    if baseline.error or poc.error:
        err = poc.error or baseline.error
        return _rejected(["probe_error"], 0.0,
                         f"Không đọc được profile response từ sandbox: {err}")

    raw_in_loc = bool(payload) and payload in loc_p
    raw_in_body = bool(payload) and payload in poc.body
    body_low = poc.body.lower()

    # ── tín hiệu khai thác được (đúng 1 nhánh, ưu tiên mạnh nhất) ──
    # meta/js phải CÓ cơ chế redirect GẦN payload (cửa sổ ±_NEIGHBOUR_WINDOW
    # ký tự) — không phải "payload + token redirect đâu đó trong trang", đó
    # chính là false positive "chỉ vì payload xuất hiện" mà đề bài cấm
    signal: str | None = None
    if poc.status in (301, 302, 303, 307, 308) and raw_in_loc:
        signal = "location_redirect"
    elif raw_in_body and _near_tokens(
        body_low, payload,
        ("<meta", "http-equiv", "refresh"),
    ):
        signal = "meta_refresh"
    elif raw_in_body and _near_tokens(body_low, payload, _JS_REDIRECT_TOKENS):
        signal = "js_redirect"

    if signal is not None:
        score = {
            "location_redirect": SCORE_LOCATION_REDIRECT,
            "meta_refresh": SCORE_META_REFRESH,
            "js_redirect": SCORE_JS_REDIRECT,
        }[signal]
        reason = {
            "location_redirect": (
                f"PoC được redirect thẳng tới payload (HTTP {poc.status} Location) — "
                "response khác baseline theo hướng khai thác được"
            ),
            "meta_refresh": "PoC chèn meta refresh trỏ tới payload trong body",
            "js_redirect": "PoC chèn JS redirect tới payload trong body",
        }[signal]
        return RedirectAnalysis(
            patterns=[signal], signals=[signal], score=score,
            verdict=decide_verdict(score, threshold),
            reason=reason, diff=diff,
        )

    # ── không có tín hiệu mạnh → xét các pattern âm tính ──
    if (poc.status, loc_p, poc.content_type, poc.body_length, poc.body) == (
        baseline.status, loc_b, baseline.content_type, baseline.body_length,
        baseline.body,
    ):
        return _rejected(["no_diff"], 0.0,
                         "Response PoC giống hệt baseline — target không phản ứng với param")

    marker = _waf_marker(body_low)
    if poc.status in _WAF_BLOCK_STATUSES or marker is not None:
        detail = f"marker '{marker}'" if marker else f"HTTP {poc.status}"
        return _rejected(["waf_block"], 0.0,
                         f"Response PoC trông giống trang chặn WAF ({detail}) — false positive")

    if not raw_in_loc and not raw_in_body:
        blob = f"{loc_p} {poc.body}"
        if any(v and v in blob for v in _escaped_variants(payload)):
            return _rejected(["payload_escaped"], 0.0,
                             "Payload chỉ xuất hiện ở dạng đã encode/escape trong response — false positive")

    if raw_in_body and any(m in body_low for m in _ERROR_MARKERS):
        return _rejected(["payload_in_error"], 0.0,
                         "Payload chỉ xuất hiện trong thông điệp lỗi/stack trace — false positive")

    if raw_in_body or raw_in_loc:
        analysis = RedirectAnalysis(
            patterns=["body_reflection"], signals=[], score=SCORE_BODY_REFLECTION,
            verdict=decide_verdict(SCORE_BODY_REFLECTION, threshold),
            reason=("Payload xuất hiện raw trong response nhưng không có cơ chế "
                    "redirect — dưới ngưỡng"),
            diff=diff,
        )
        return analysis

    return _rejected(["no_exploitable_diff"], 0.1,
                     "Response khác baseline nhưng không theo hướng khai thác được")


def decide_verdict(score: float, threshold: float) -> str:
    """Score ≥ ngưỡng → Finding (verified); dưới → rejected."""
    return "verified" if score >= threshold else "rejected"


def write_verify_evidence(run_id: int, candidate_id: int, record: dict) -> str | None:
    """Ghi evidence diff (baseline + PoC + analysis + pattern log) ra volume;
    path ghi vào candidates.verify_evidence_path. IO lỗi → None (không chết)."""
    try:
        base = Path(settings.evidence_dir) / str(run_id) / "verify"
        base.mkdir(parents=True, exist_ok=True)
        path = base / f"{candidate_id:03d}.json"
        path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        return str(path)
    except OSError as exc:
        log.warning("run %d: không ghi được verify evidence (%s)", run_id, exc)
        return None


# ───────────────────────────── pipeline (async) ─────────────────────────────


class ProbeBlocked(Exception):
    """Target PoC/baseline bị Scope Validator chặn TẠI BRIDGE — không có
    request nào đi ra; Candidate giữ nguyên lifecycle (không verdict)."""


# RETURNING dùng đúng CANDIDATE_COLS của detect (đã gồm các cột verify từ
# migration 0010) — không lặp danh sách cột ở đây

# 1 statement duy nhất cho cả 'verifying' lẫn verdict cuối — lifecycle luôn
# nhìn thấy được ở UI trong lúc sandbox chạy
_UPDATE_VERDICT_SQL = f"""
UPDATE candidates SET status = $2, confidence = $3, confidence_threshold = $4,
    reject_reason = $5, verify_evidence_path = $6, verify_session_id = $7,
    baseline_session_id = $8
WHERE id = $1 RETURNING {CANDIDATE_COLS}
"""


async def run_redirect_verification(
    pool: asyncpg.Pool,
    candidate: dict,
    payload: str | None = None,
    probe: "ProbeCallable | None" = None,
    threshold: float | None = None,
) -> dict:
    """Trọn vòng verify 1 Candidate class redirect. `probe(script, target)`
    là seam thực thi (mặc định: sandbox.run_verify_session — container
    ephemeral, scope + egress + rate limit như mọi Tool Execution).

    Trả summary (verdict/score/patterns/evidence path/session ids). Target bị
    chặn scope → ProbeBlocked (candidate trả về trạng thái cũ); lỗi môi trường
    → RuntimeError cho tầng trên retry — KHÔNG verdict oan.
    """
    candidate_id = candidate["id"]
    run_id = candidate["run_id"]
    threshold = default_threshold() if threshold is None else float(threshold)
    payload = (payload or settings.verify_canary_url or "").strip()
    param = (candidate.get("param") or "").split(",")[0].strip()
    prev_status = candidate.get("status") or "new"

    async def _update(status: str, score: float | None = None,
                      reject_reason: str | None = None,
                      evidence: str | None = None,
                      poc_sid: int | None = None,
                      base_sid: int | None = None) -> dict | None:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                _UPDATE_VERDICT_SQL, candidate_id, status, score, threshold,
                reject_reason, evidence, poc_sid, base_sid,
            )
        return dict(row) if row else None

    def _summary(verdict: str, score: float, reason: str,
                 analysis: RedirectAnalysis, evidence: str | None,
                 base_sid: int | None, poc_sid: int | None) -> dict:
        return {
            "candidate_id": candidate_id,
            "run_id": run_id,
            "payload": payload,
            "verdict": verdict,
            "score": round(float(score), 4),
            "threshold": threshold,
            "reason": reason,
            "signals": analysis.signals,
            "patterns": analysis.patterns,
            "evidence_path": evidence,
            "baseline_session_id": base_sid,
            "verify_session_id": poc_sid,
        }

    # không có param thì không có PoC — rejected ngay, không tốn sandbox
    if not param:
        analysis = RedirectAnalysis(
            patterns=["no_param"], score=0.0, verdict="rejected",
            reason="Candidate không có param để chèn PoC",
        )
        evidence = write_verify_evidence(run_id, candidate_id, _evidence_record(
            candidate, payload, threshold, analysis, None, None, None, None,
        ))
        await _update("rejected", 0.0, analysis.reason, evidence)
        return _summary("rejected", 0.0, analysis.reason, analysis, evidence, None, None)

    baseline_url = inject_param(candidate["target"], param, BENIGN_PARAM_VALUE)
    poc_url = inject_param(candidate["target"], param, payload)

    if probe is None:
        run = await sandbox.resolve_run(pool, run_id)
        if run is None:
            raise ValueError("không có Run nào — không thể xác minh qua sandbox")

        async def probe(script: str, target: str, _run: asyncpg.Record = run) -> dict:
            return await sandbox.run_verify_session(pool, _run, script, target)

    await _update("verifying")

    async def _run_probe(script: str) -> dict:
        res = await probe(script, candidate["target"])
        if res.get("status") == "blocked":
            await _update(prev_status)  # không verdict oan — trả lifecycle về cũ
            raise ProbeBlocked(res.get("reason") or "target bị chặn tại bridge")
        if res.get("status") == "error":
            await _update(prev_status)
            raise RuntimeError(f"lỗi môi trường sandbox: {res.get('reason') or res.get('stderr', '')}")
        return res

    base_res = await _run_probe(build_probe_script(baseline_url))
    poc_res = await _run_probe(build_probe_script(poc_url))

    base_raw = base_res.get("stdout") or ""
    poc_raw = poc_res.get("stdout") or ""
    baseline = parse_probe(base_raw)
    poc = parse_probe(poc_raw)
    if baseline is None or poc is None:
        analysis = RedirectAnalysis(
            patterns=["probe_error"], score=0.0, verdict="rejected",
            reason="Không đọc được profile response từ stdout sandbox (thiếu marker/JSON đứt)",
        )
    else:
        analysis = analyze_redirect(baseline, poc, payload, threshold)

    evidence = write_verify_evidence(run_id, candidate_id, _evidence_record(
        candidate, payload, threshold, analysis,
        baseline, base_res.get("session_id"),
        poc, poc_res.get("session_id"),
        baseline_raw=base_raw, poc_raw=poc_raw,
    ))
    base_sid = base_res.get("session_id")
    poc_sid = poc_res.get("session_id")
    await _update(analysis.verdict, analysis.score,
                  analysis.reason if analysis.verdict == "rejected" else None,
                  evidence, poc_sid, base_sid)
    await add_log(
        pool, run_id,
        f"Verify open redirect Candidate #{candidate_id}: {analysis.verdict} "
        f"(score {analysis.score:.2f} / ngưỡng {threshold:.2f}) · patterns: "
        f"{', '.join(analysis.patterns) or '—'}"
        + (f" · evidence: {evidence}" if evidence else ""),
    )
    return _summary(analysis.verdict, analysis.score, analysis.reason,
                    analysis, evidence, base_sid, poc_sid)


def _evidence_record(
    candidate: dict,
    payload: str,
    threshold: float,
    analysis: RedirectAnalysis,
    baseline: ProbeProfile | None,
    baseline_session_id: int | None,
    poc: ProbeProfile | None,
    poc_session_id: int | None,
    baseline_raw: str = "",
    poc_raw: str = "",
) -> dict:
    """Nội dung file evidence diff — bằng chứng đầy đủ cho Finding/rejected."""

    def _profile_or_parse_error(p: ProbeProfile | None, raw: str) -> dict:
        if p is not None:
            return p.to_dict()
        if raw:
            # probe chạy thật nhưng stdout không parse được — giữ NGUYÊN stdout
            # thô của CHÍNH probe đó để debug (không phải dữ liệu probe còn lại)
            return {"parse_error": True, "stdout_head": raw[:2000]}
        return {"skipped": True}  # probe không hề chạy (vd: candidate thiếu param)

    return {
        "schema": "vulhunt.verify-evidence/1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate["id"],
        "run_id": candidate["run_id"],
        "class": candidate.get("class"),
        "target": candidate.get("target"),
        "param": candidate.get("param"),
        "payload": payload,
        "threshold": threshold,
        "baseline": _profile_or_parse_error(baseline, baseline_raw),
        "poc": _profile_or_parse_error(poc, poc_raw),
        "baseline_session_id": baseline_session_id,
        "verify_session_id": poc_session_id,
        "analysis": {
            "signals": analysis.signals,
            "patterns": analysis.patterns,  # pattern log (kể cả khi rejected)
            "score": analysis.score,
            "verdict": analysis.verdict,
            "reason": analysis.reason,
            "diff": analysis.diff,
        },
    }
