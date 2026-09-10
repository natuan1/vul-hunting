"""Catalog batch B (ticket #16) — lớp **SQLi** với sqlmap, CHỈ chạy trong
sandbox bridge (ADR-0003), profile an toàn MỨC THẤP:

- kỹ thuật duy nhất: error-based + boolean blind (`--technique=BE`) — KHÔNG
  time-based nặng, KHÔNG UNION/stacked;
- `--level=1 --risk=1 --threads=1` — độ chuya khuếch tán tối thiểu;
- rate limit nghiêm ngặt của Run: `--delay` ≥ 1 req/s (Run chậm hơn thì delay
  đúng nghịch đảo rps), cộng thêm limiter của egress proxy chặn từng request;
- TUYỆT ĐỐI KHÔNG: `--dump*` (dump dữ liệu), `--file-read/--file-write` (đọc
  file hệ thống), `--os-shell/--os-pwn` — vi phạm nguyên tắc "minimum testing
  necessary" + rules chống pivot/PII của các Program. PoC = chứng minh
  injection được, KHÔNG phải chiếm dữ liệu.

Stop-condition (guardrails): output của sqlmap có dấu hiệu dump/đọc file/kỹ
thuật ngoài profile → guardrails HALT Run + cảnh báo, KHÔNG tiếp tục (không
verdict, Candidate trả lifecycle về cũ). Detection cho class `sqli` đã có
sẵn (nuclei tags ∩ vocab + gf); batch B chỉ bổ sung vòng xác minh.
"""

import json
import logging
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

import asyncpg

from . import guardrails, sandbox
from .config import settings
from .detect import CANDIDATE_COLS
from .httpverify import build_http_probe_script
from .tools import add_log
from .verify import (
    PROBE_MARKER,
    _WAF_BLOCK_STATUSES,
    _WAF_MARKERS,
    ProbeBlocked,
    ProbeCallable,
    ProbeProfile,
    default_threshold,
    parse_probe,
)

log = logging.getLogger("sqli")

# class Candidate mà vòng này hỗ trợ
SQLI_VERIFY_CLASSES = ("sqli",)

# ── profile an toàn (được ghi rõ trong skill sqli-verify + evidence) ──
SQLMAP_TECHNIQUE = "BE"      # boolean + error-based duy nhất — KHÔNG time-based
SQLMAP_LEVEL = 1             # mức khuếch tán thấp nhất
SQLMAP_RISK = 1              # risk thấp nhất (không OR/heavy payload)
SQLMAP_THREADS = 1           # tuần tự — không dồn dập target
SQLMAP_MIN_DELAY_S = 1.0     # sàn rate limit: không bao giờ nhanh hơn 1 req/s
SQLMAP_TIMEOUT_S = 15        # timeout từng request
SQLMAP_LOG_CAP = 60_000      # cap log nhúng vào marker JSON

# bảng stop-condition: dấu hiệu vi phạm trong output sqlmap (theo thứ tự bảng)
# — dump dữ liệu, đọc/ghi file hệ thống, shell, kỹ thuật ngoài profile BE.
# Match chính xác (sqlmap in đúng những cụm này); fail-safe: báo nhầm chỉ là
# halt phiền, lọt là pivot/PII thật.
DUMP_VIOLATION_PATTERNS = (
    "--dump",                    # dump table/database
    "--dump-all",
    "--common-tables",           # enumeration schema
    "--common-columns",
    "--file-read",               # đọc file hệ thống
    "--file-write",
    "--file-dest",
    "--os-shell",                # shell/executing
    "--os-pwn",
    "--os-cmd",
    "--os-smbrelay",
    "--sql-shell",
    "--reg-read",                # registry
    "--reg-add",
    "--reg-del",
    "Type: time-based blind",    # kỹ thuật NGOÀI profile BE — fail-safe
    "Type: stacked queries",
    "Type: UNION query",
    "fetching entries",          # log dump dữ liệu
    "fetching number of entries",
    "reading file",              # log đọc file
)

# sqlmap in usage/help khi bị truyền option sai — help CHỨA "--dump"… (văn
# bản trợ giúp) nên phải tách khỏi dấu hiệu dump THẬT để không HALT oan Run
_SQLMAP_USAGE_MARKERS = ("Usage: ", "sqlmap: error:", "sqlmap.py: error:")

# sqlmap xác nhận injection → bằng chứng quyết định của vòng này
SCORE_SQLMAP_INJECTABLE = 0.95


# ───────────────────────────── seam thuần (có test) ─────────────────────────────


def format_delay(delay_s: float) -> str:
    """Delay gọn cho CLI: 2.0 → '2', 0.5 → '0.5'."""
    return f"{float(delay_s):g}"


def delay_for_run(rate_limit_rps: float | None) -> float:
    """Delay sqlmap theo rate limit của Run: sàn SQLMAP_MIN_DELAY_S (1 req/s),
    Run chậm hơn thì delay = 1/rps (đúng nhịp nghiêm ngặt của Run)."""
    rps = float(rate_limit_rps or 0)
    if rps <= 0:
        return SQLMAP_MIN_DELAY_S
    return max(SQLMAP_MIN_DELAY_S, 1.0 / rps)


def build_sqlmap_args(url: str, param: str, delay_s: float) -> list[str]:
    """Args sqlmap với profile an toàn — NGUỒN DUY NHẤT của command line
    (script sandbox ghép từ đây). Cấm kênh dump/đọc file/os: chúng KHÔNG BAO
    GIỜ xuất hiện trong args; scan_violations là lớp 2, profile là lớp 1."""
    return [
        "-u", url,
        "-p", param,
        "--batch",                       # không tương tác (automation)
        f"--technique={SQLMAP_TECHNIQUE}",
        f"--level={SQLMAP_LEVEL}",
        f"--risk={SQLMAP_RISK}",
        f"--threads={SQLMAP_THREADS}",
        f"--delay={format_delay(delay_s)}",
        f"--timeout={SQLMAP_TIMEOUT_S}",
        "--retries=1",                   # không dày request retry
        "--flush-session",               # session sạch mỗi lần chạy
    ]


def scan_violations(text: str) -> list[str]:
    """Stop-condition: các dấu hiệu vi phạm xuất hiện trong output sqlmap —
    trả theo thứ tự bảng; sạch → []. Đây là bằng chứng cho guardrails HALT."""
    return [p for p in DUMP_VIOLATION_PATTERNS if p in (text or "")]


def is_usage_error(text: str) -> bool:
    """sqlmap lỗi option → in usage/help (văn bản trợ giúp có chứa '--dump'…)
    — đây KHÔNG phải dấu hiệu dump thật: reject, không HALT oan Run."""
    return any(m in (text or "") for m in _SQLMAP_USAGE_MARKERS)


_PARAM_RE = re.compile(r"^Parameter:\s+(\S+)\s+\((\w+)\)", re.MULTILINE)
_TYPE_RE = re.compile(r"^\s+Type:\s+(.+)$", re.MULTILINE)
_PAYLOAD_RE = re.compile(r"^\s+Payload:\s+(.+)$", re.MULTILINE)
_DBMS_RES = (
    re.compile(r"back-end DBMS is ([^\n]+)"),
    re.compile(r"back-end DBMS:\s*([^\n]+)"),
)


def parse_sqlmap_result(log_text: str) -> dict:
    """Parse log console sqlmap → kết quả xác minh (KHÔNG có dữ liệu dump —
    profile cấm dump nên log chỉ chứa injection point + DBMS banner)."""
    text = log_text or ""
    dbms = None
    for rx in _DBMS_RES:
        m = rx.search(text)
        if m:
            dbms = m.group(1).strip()
            break
    return {
        "vulnerable": "identified the following injection point" in text,
        "not_injectable": "do not appear to be injectable" in text,
        # sqlmap in 1 block "Parameter:" per technique — dedupe giữ thứ tự
        "parameters": list(dict.fromkeys(m.group(1) for m in _PARAM_RE.finditer(text))),
        "types": [m.group(1).strip() for m in _TYPE_RE.finditer(text)],
        "payloads": [m.group(1).strip() for m in _PAYLOAD_RE.finditer(text)],
        "dbms": dbms,
    }


def build_sqlmap_script(url: str, param: str, delay_s: float) -> str:
    """Script (sh) chạy TRONG sandbox: sqlmap với profile an toàn (args dựng
    từ build_sqlmap_args — không cờ phá hoại nào), log console đổ vào file rồi
    được nhúng (cap) vào JSON emit sau PROBE_MARKER — worker parse + scan
    violations trên đó. Stdout session không chứa gì ngoài JSON tóm tắt."""
    cmd = " ".join(shlex.quote(a) for a in ["sqlmap", *build_sqlmap_args(url, param, delay_s)])
    return (
        "set -u\n"
        "OUT=$(mktemp -d)\n"
        f"{cmd} >\"$OUT/sqlmap.log\" 2>\"$OUT/sqlmap.err\"\n"
        "code=$?\n"
        "export SQL_LOG=\"$OUT/sqlmap.log\" SQL_CODE=\"$code\"\n"
        "python3 - <<'PY'\n"
        "import json, os\n"
        f"MARKER = {json.dumps(PROBE_MARKER)}\n"
        f"URL = {json.dumps(url)}\n"
        f"PARAM = {json.dumps(param)}\n"
        f"DELAY = {json.dumps(format_delay(delay_s))}\n"
        f"LOG_CAP = {SQLMAP_LOG_CAP}\n"
        "try:\n"
        "    log_text = open(os.environ.get(\"SQL_LOG\", \"\"), encoding=\"utf-8\",\n"
        "                   errors=\"replace\").read()\n"
        "except OSError:\n"
        "    log_text = \"\"\n"
        "try:\n"
        "    exit_code = int(os.environ.get(\"SQL_CODE\", \"0\") or 0)\n"
        "except ValueError:\n"
        "    exit_code = 0\n"
        "print(MARKER)\n"
        "print(json.dumps({\n"
        "    \"url\": URL,\n"
        "    \"param\": PARAM,\n"
        "    \"delay_s\": DELAY,\n"
        "    \"exit_code\": exit_code,\n"
        "    \"sqlmap_log\": log_text[:LOG_CAP],\n"
        "}, ensure_ascii=False))\n"
        "PY"
    )


def parse_sqlmap_emission(stdout: str) -> dict | None:
    """Đọc JSON tóm tắt từ stdout sandbox: dict ở dòng đầu tiên không trống
    SAU marker; thiếu marker/JSON đứt → None."""
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
            if not isinstance(raw, dict):
                return None
            return {
                "url": str(raw.get("url") or ""),
                "param": str(raw.get("param") or ""),
                "delay_s": str(raw.get("delay_s") or ""),
                "exit_code": int(raw.get("exit_code") or 0),
                "sqlmap_log": str(raw.get("sqlmap_log") or ""),
            }
    return None


# ───────────────────────────── pipeline (async) ─────────────────────────────


@dataclass
class SqlmapAnalysis:
    """Kết quả phân tích: pattern log, tín hiệu, confidence, verdict + kết quả
    parse sqlmap (parameters/types/payloads/dbms) để ghi evidence."""

    patterns: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    score: float = 0.0
    verdict: str = "rejected"
    reason: str = ""


def _waf_hit(baseline: ProbeProfile) -> bool:
    low = baseline.body.lower()
    return baseline.status in _WAF_BLOCK_STATUSES or any(m in low for m in _WAF_MARKERS)


# RETURNING dùng đúng CANDIDATE_COLS của detect (giống verify/httpverify)
_VERDICT_SQL = f"""
UPDATE candidates SET status = $2, confidence = $3, confidence_threshold = $4,
    reject_reason = $5, verify_evidence_path = $6, verify_session_id = $7,
    baseline_session_id = $8
WHERE id = $1 RETURNING {CANDIDATE_COLS}
"""


def _evidence_record(
    candidate: dict,
    threshold: float,
    analysis: SqlmapAnalysis,
    delay_s: float,
    baseline: ProbeProfile | None,
    baseline_session_id: int | None,
    emission: dict | None,
    poc_session_id: int | None,
    violations: list[str],
    result: dict,
) -> dict:
    """Nội dung file evidence SQLi: baseline + kết quả sqlmap (injection point,
    KHÔNG dữ liệu) + profile an toàn + violations (luôn rỗng khi tới đây) —
    PoC chỉ chứng minh injection."""
    return {
        "schema": "vulhunt.sqli-evidence/1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate["id"],
        "run_id": candidate["run_id"],
        "class": candidate.get("class"),
        "target": candidate.get("target"),
        "param": candidate.get("param"),
        "threshold": threshold,
        "safety": {
            "technique": SQLMAP_TECHNIQUE,
            "level": SQLMAP_LEVEL,
            "risk": SQLMAP_RISK,
            "threads": SQLMAP_THREADS,
            "delay_s": delay_s,
            "forbidden": (
                "KHÔNG time-based, KHÔNG dump dữ liệu, KHÔNG đọc/ghi file hệ "
                "thống — minimum testing necessary (ticket #16)"
            ),
        },
        "baseline": baseline.to_dict() if baseline else {"skipped": True},
        "sqlmap": result,
        "sqlmap_exit_code": (emission or {}).get("exit_code"),
        "violations": violations,
        "baseline_session_id": baseline_session_id,
        "verify_session_id": poc_session_id,
        "analysis": {
            "signals": analysis.signals,
            "patterns": analysis.patterns,  # pattern log (kể cả khi rejected)
            "score": analysis.score,
            "verdict": analysis.verdict,
            "reason": analysis.reason,
        },
        "note": "PoC chỉ chứng minh injection — KHÔNG dump dữ liệu, KHÔNG đọc file.",
    }


async def run_sqli_verification(
    pool: asyncpg.Pool,
    candidate: dict,
    probe: "ProbeCallable | None" = None,
    threshold: float | None = None,
    delay_s: float | None = None,
) -> dict:
    """Trọn vòng verify 1 Candidate class `sqli`: baseline GET (WAF chặn →
    rejected TRƯỚC khi sqlmap chạy — minimum testing) → sqlmap trong sandbox
    với profile an toàn → STOP-CONDITION scan output: dấu hiệu dump/đọc file →
    guardrails HALT + cảnh báo, KHÔNG tiếp tục → sqlmap xác nhận injectable →
    Finding (PoC = payload injection, không dữ liệu); không xác nhận → rejected.

    `probe(script, target)` là seam thực thi (mặc định sandbox.run_verify_
    session); `delay_s` override delay (mặc định: theo rate limit của Run khi
    probe mặc định, sàn 1 req/s). Contract lỗi như verify khác: class lạ →
    ValueError; target bị chặn scope → ProbeBlocked (trả lifecycle về cũ);
    lỗi môi trường → RuntimeError.
    """
    candidate_id = candidate["id"]
    run_id = candidate["run_id"]
    cls = str(candidate.get("class") or "").strip()
    if cls not in SQLI_VERIFY_CLASSES:
        raise ValueError(
            f"class '{cls}' không thuộc lớp SQLi: {', '.join(SQLI_VERIFY_CLASSES)}"
        )
    threshold = default_threshold() if threshold is None else float(threshold)
    param = (candidate.get("param") or "").split(",")[0].strip()
    prev_status = candidate.get("status") or "new"

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

    def _summary(verdict: str, score: float, reason: str,
                 analysis: SqlmapAnalysis, evidence: str | None,
                 base_sid: int | None, poc_sid: int | None,
                 result: dict | None, violations: list[str] | None,
                 delay: float | None) -> dict:
        return {
            "candidate_id": candidate_id,
            "run_id": run_id,
            "class": cls,
            "verdict": verdict,
            "score": round(float(score), 4),
            "threshold": threshold,
            "reason": reason,
            "signals": analysis.signals,
            "patterns": analysis.patterns,
            "sqlmap": result or {},
            "violations": violations or [],
            "delay_s": delay,
            "evidence_path": evidence,
            "baseline_session_id": base_sid,
            "verify_session_id": poc_sid,
        }

    # không có param thì sqlmap không có gì test — rejected ngay, không tốn sandbox
    if not param:
        analysis = SqlmapAnalysis(
            patterns=["no_param"], score=0.0, verdict="rejected",
            reason="Candidate không có param để sqlmap test",
        )
        evidence = _write_evidence(candidate, threshold, analysis, None, None, None,
                                   None, None, [], {})
        await _update_verdict("rejected", 0.0, analysis.reason, evidence)
        return _summary("rejected", 0.0, analysis.reason, analysis, evidence,
                        None, None, None, [], None)

    if probe is None:
        run = await sandbox.resolve_run(pool, run_id)
        if run is None:
            raise ValueError("không có Run nào — không thể xác minh qua sandbox")
        if delay_s is None:
            delay_s = delay_for_run(run["rate_limit_rps"])

        async def probe(script: str, target: str, _run: asyncpg.Record = run) -> dict:
            return await sandbox.run_verify_session(pool, _run, script, target)

    delay_s = float(settings.sqlmap_min_delay_s if delay_s is None else delay_s)

    await _update_verdict("verifying")

    async def _run_probe(script: str) -> dict:
        res = await probe(script, candidate["target"])
        if res.get("status") == "blocked":
            await _update_verdict(prev_status)  # không verdict oan
            raise ProbeBlocked(res.get("reason") or "target bị chặn tại bridge")
        if res.get("status") == "error":
            await _update_verdict(prev_status)
            raise RuntimeError(
                f"lỗi môi trường sandbox: {res.get('reason') or res.get('stderr', '')}"
            )
        return res

    base_res = await _run_probe(build_http_probe_script(candidate["target"]))
    baseline = parse_probe(base_res.get("stdout") or "")

    # WAF chặn baseline → dừng TRƯỚC sqlmap (minimum testing necessary)
    if baseline is None:
        analysis = SqlmapAnalysis(
            patterns=["probe_error"], score=0.0, verdict="rejected",
            reason="Không đọc được profile baseline từ stdout sandbox "
                   "(thiếu marker/JSON đứt)",
        )
    elif _waf_hit(baseline):
        analysis = SqlmapAnalysis(
            patterns=["waf_block"], score=0.0, verdict="rejected",
            reason=f"Baseline bị chặn (HTTP {baseline.status}) — sqlmap KHÔNG "
                   "chạy để tránh request thừa, không báo thật",
        )
    else:
        analysis = None
    if analysis is not None:
        evidence = _write_evidence(
            candidate, threshold, analysis, delay_s, baseline,
            base_res.get("session_id"), None, None, [], {},
        )
        await _update_verdict(analysis.verdict, analysis.score, analysis.reason,
                              evidence, None, base_res.get("session_id"))
        await add_log(
            pool, run_id,
            f"Verify SQLi Candidate #{candidate_id}: {analysis.verdict} · "
            f"patterns: {', '.join(analysis.patterns)}"
            + (f" · evidence: {evidence}" if evidence else ""),
        )
        return _summary(analysis.verdict, analysis.score, analysis.reason,
                        analysis, evidence, base_res.get("session_id"), None,
                        None, [], delay_s)

    poc_res = await _run_probe(
        build_sqlmap_script(candidate["target"], param, delay_s)
    )
    raw_stdout = poc_res.get("stdout") or ""

    # ── STOP-CONDITION (AC #16): dấu hiệu dump/đọc file/kỹ thuật ngoài profile
    # → guardrails HALT + cảnh báo, KHÔNG tiếp tục (không verdict, lifecycle
    # trả về cũ, Run dừng chờ người dùng xem xét). RIÊNG usage/help của sqlmap
    # (lỗi option) chứa '--dump'… trong văn bản trợ giúp — không HALT oan. ──
    violations = scan_violations(raw_stdout)
    usage_error = is_usage_error(raw_stdout)
    if violations and not usage_error:
        halt_reason = (
            f"sqlmap (Candidate #{candidate_id}) có dấu hiệu vi phạm profile an "
            f"toàn: {', '.join(violations)} — dump/đọc file là điều cấm theo "
            "minimum testing necessary. Run bị HALT, không tiếp tục."
        )
        await _update_verdict(prev_status)
        await guardrails.halt_run(pool, run_id, halt_reason)
        raise guardrails.RunHalted(halt_reason)

    emission = parse_sqlmap_emission(raw_stdout)
    if emission is None:
        analysis = SqlmapAnalysis(
            patterns=["probe_error"], score=0.0, verdict="rejected",
            reason="Không đọc được kết quả sqlmap từ stdout sandbox "
                   "(thiếu marker/JSON đứt)",
        )
        result: dict = {}
    elif usage_error:
        analysis = SqlmapAnalysis(
            patterns=["sqlmap_error"], score=0.0, verdict="rejected",
            reason="sqlmap thoát với lỗi option/usage (không scan được) — "
                   "không báo thật",
        )
        result = {}
    else:
        result = parse_sqlmap_result(emission["sqlmap_log"])
        if result["vulnerable"]:
            analysis = SqlmapAnalysis(
                patterns=["sqlmap_injectable"], signals=["sqlmap_injectable"],
                score=SCORE_SQLMAP_INJECTABLE,
                verdict=("verified" if SCORE_SQLMAP_INJECTABLE >= threshold
                         else "rejected"),
                reason=(
                    "sqlmap xác nhận parameter "
                    f"'{', '.join(result['parameters']) or param}' injectable "
                    f"({', '.join(result['types']) or 'n/a'})"
                    + (f" — DBMS {result['dbms']}" if result["dbms"] else "")
                    + ". PoC chỉ chứng minh injection — KHÔNG dump dữ liệu, "
                      "KHÔNG đọc file hệ thống"
                ),
            )
        elif result["not_injectable"]:
            analysis = SqlmapAnalysis(
                patterns=["not_injectable"], score=0.0, verdict="rejected",
                reason="sqlmap: mọi param đã test không injectable với profile "
                       "an toàn (error/boolean, level 1 risk 1) — không báo thật",
            )
        else:
            analysis = SqlmapAnalysis(
                patterns=["no_confirmation"], score=0.1, verdict="rejected",
                reason="sqlmap không xác nhận được injection (kết luận không "
                       "rõ) — không báo thật",
            )

    evidence = _write_evidence(
        candidate, threshold, analysis, delay_s, baseline,
        base_res.get("session_id"), emission, poc_res.get("session_id"),
        violations, result,
    )
    base_sid = base_res.get("session_id")
    poc_sid = poc_res.get("session_id")
    await _update_verdict(
        analysis.verdict, analysis.score,
        analysis.reason if analysis.verdict == "rejected" else None,
        evidence, poc_sid, base_sid,
    )
    await add_log(
        pool, run_id,
        f"Verify SQLi Candidate #{candidate_id}: {analysis.verdict} "
        f"(score {analysis.score:.2f} / ngưỡng {threshold:.2f}) · sqlmap "
        f"technique {SQLMAP_TECHNIQUE}, level {SQLMAP_LEVEL}, risk {SQLMAP_RISK}, "
        f"delay {format_delay(delay_s)}s · violations: "
        f"{', '.join(violations) or 'không'} · patterns: "
        f"{', '.join(analysis.patterns) or '—'}"
        + (f" · evidence: {evidence}" if evidence else ""),
    )
    return _summary(analysis.verdict, analysis.score, analysis.reason,
                    analysis, evidence, base_sid, poc_sid, result,
                    violations, delay_s)


def _write_evidence(
    candidate: dict,
    threshold: float,
    analysis: SqlmapAnalysis,
    delay_s: float | None,
    baseline: ProbeProfile | None,
    baseline_session_id: int | None,
    emission: dict | None,
    poc_session_id: int | None,
    violations: list[str],
    result: dict,
) -> str | None:
    """Ghi evidence SQLi ra volume ({run}/sqli/) — path ghi vào
    candidates.verify_evidence_path. IO lỗi → None (không chết verify)."""
    record = _evidence_record(candidate, threshold, analysis,
                              delay_s if delay_s is not None else 0.0,
                              baseline, baseline_session_id, emission,
                              poc_session_id, violations, result)
    try:
        base = Path(settings.evidence_dir) / str(candidate["run_id"]) / "sqli"
        base.mkdir(parents=True, exist_ok=True)
        path = base / f"{candidate['id']:03d}-verify.json"
        path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        return str(path)
    except OSError as exc:
        log.warning("run %d: không ghi được sqli evidence (%s)",
                    candidate["run_id"], exc)
        return None
