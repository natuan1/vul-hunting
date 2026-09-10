"""Catalog batch B (ticket #16) — lớp **exposed secrets** (trufflehog
verify-key): quét nội dung URL nhạy cảm phát hiện được từ Recon (.env, bucket,
JS bundle, backup files) → secret HỢP LỆ (đã verify-key với provider, tính
năng `--only-verified` của trufflehog) → Candidate class `secret` severity
`high`; **evidence che bớt key — chỉ hiện prefix**.

Verify (vòng xác minh): sandbox quét LẠI nội dung URL hiện tại (baseline
không thu body để không bao giờ đưa key vào evidence; rescan chạy trufflehog
KHÔNG verification vì egress proxy của sandbox chỉ cho target trong Scope —
provider API là host ngoài Scope) → đối chiếu detector + prefix với detection →
vẫn còn exposed → Finding; key đã bị xoá/đổi → rejected kèm pattern log.
Evidence của cả hai phase KHÔNG bao giờ chứa secret đầy đủ.

Detection dùng tool `trufflehog-urls` (wrapper trong tooling image) như mọi
Tool Execution: Scope Validator + rate limit + guardrails; verify chạy trong
sandbox bridge (ADR-0003) như mọi payload — agent không bao giờ fetch trực tiếp.
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

import asyncpg

from . import detect, sandbox
from .config import settings
from .detect import CANDIDATE_COLS, CandidateRow
from .sqli import delay_for_run, format_delay
from .tools import (
    ToolContext,
    add_log,
    build_context,
    execute_tool,
    filter_scope,
    jsonl_lines,
)
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

log = logging.getLogger("secrets")

# class Candidate của lớp này + severity "cao" theo đề bài (secret hợp lệ)
SECRET_CANDIDATE_CLASS = "secret"
SECRET_SEVERITY = "high"

# tool wrapper trong tooling image (stdin: danh sách URL)
TRUFFLEHOG_URLS_TOOL = "trufflehog-urls"

# URL nhạy cảm hay chứa secret: .env, JS bundle, backup files (.bak/.old/
# .sql/.zip/.tar.gz…), bucket/object storage (S3, Azure Blob, GCS, Dropbox),
# keys/certs, .git. Heuristic pre-filter — trufflehog mới là người quyết.
SECRET_URL_RE = re.compile(
    r"("
    r"\.env\b|\.js\b|\.json\b|\.bak\b|\.backup\b|\.old\b|\.save\b|\.swp\b"
    r"|\.sql\b|\.dump\b|\.zip\b|\.gz\b|\.tgz\b|\.rar\b|\.7z\b"
    r"|\.yml\b|\.yaml\b|\.ini\b|\.conf\b|\.config\b|\.xml\b"
    r"|\.pem\b|\.key\b|\.p12\b|\.pfx\b|id_rsa"
    r"|\.git\b|\.htpasswd\b|\.htaccess\b"
    r"|s3[.-]amazonaws|\.blob\.core\.windows|storage\.googleapis"
    r"|dl\.dropboxusercontent|bucket"
    r")",
    re.IGNORECASE,
)

# số ký tự prefix được phép hiển thị của một secret (đề bài: chỉ hiện prefix)
MASK_KEEP = 4
MASK_TAIL = "…"

# secret đã verify-key vẫn còn nguyên ở URL hiện tại → bằng chứng quyết định
SCORE_STILL_EXPOSED = 0.95


# ───────────────────────────── seam thuần (có test) ─────────────────────────────


def mask_secret(raw: str, keep: int = MASK_KEEP) -> str:
    """Che secret: chỉ giữ prefix `keep` ký tự + dấu …; key ngắn (phần bị che
    ít hơn phần hiện) → che TOÀN BỘ. Đã có dấu … ở cuối (bản mask của wrapper)
    thì giữ nguyên — idempotent. Quy tắc này PHẢI khớp bản nhúng trong
    build_secret_rescan_script (sandbox không có code worker)."""
    raw = str(raw or "")
    if raw.endswith(MASK_TAIL):
        return raw
    if len(raw) < keep * 2:
        return MASK_TAIL
    return raw[:keep] + MASK_TAIL


def secret_fingerprint(raw: str) -> str:
    """Vân tay của secret (sha256 truncated) — dùng để đối chiếu verify mà
    KHÔNG lộ thêm gì: hash không đảo ngược được key entropy cao, evidence vẫn
    chỉ hiện prefix. Key bị rotate → fingerprint lệch dù prefix giống nhau."""
    return hashlib.sha256(str(raw or "").encode()).hexdigest()[:12]


def secret_marker(detector: str, masked: str, fingerprint: str) -> str:
    """Marker lưu vào candidates.matcher_name: `detector|prefix|fingerprint` —
    verify dùng để đối chiếu secret ở URL hiện tại có còn là CÙNG secret
    không (rotate key → fingerprint lệch → secret_changed)."""
    return f"{detector}|{masked}|{fingerprint}"


def parse_secret_marker(matcher_name: str) -> tuple[str, str, str]:
    """Ngược lại secret_marker → (detector, masked, fingerprint); lạ →
    ('', '', '')."""
    parts = str(matcher_name or "").split("|", 2)
    if len(parts) != 3:
        return "", "", ""
    return parts[0].strip(), parts[1].strip(), parts[2].strip()


def select_secret_urls(urls: list[str], max_targets: int | None = None) -> list[str]:
    """Chọn URL đáng quét secret (.env, bucket, JS bundle, backup…): giữ thứ
    tự, dedupe, cap để giữ nhịp điều độ (mặc định SECRETS_MAX_TARGETS)."""
    cap = settings.secrets_max_targets if max_targets is None else max_targets
    out: list[str] = []
    seen: set[str] = set()
    for u in urls or []:
        if u in seen or not SECRET_URL_RE.search(u):
            continue
        seen.add(u)
        out.append(u)
    return out[:cap]


def parse_trufflehog_jsonl(stdout: str) -> list[dict]:
    """Output JSONL của wrapper trufflehog-urls → list hit đã verified.

    Chấp nhận CẢ 2 hình dạng (phòng hờ wrapper đổi): wrapper format
    {url, detector, verified, masked, raw_length} và raw trufflehog format
    {SourceMetadata.Data.File, DetectorName, Verified, Raw/RawV2}. Secret raw
    (nếu lỡ có) bị mask NGAY TẠI ĐÂY — parser không bao giờ trả key nguyên.
    Chỉ hit `verified` (verify-key với provider thành công) được giữ."""
    hits: list[dict] = []
    seen: set[tuple] = set()
    for line in jsonl_lines(stdout):
        src = line.get("SourceMetadata") or {}
        data = src.get("Data") or {}
        # wrapper format mang `url` sẵn; raw trufflehog filesystem source thì
        # file nằm ở Data.Filesystem.file (khác source khác dùng Data.File)
        url = str(
            line.get("url")
            or (data.get("Filesystem") or {}).get("file")
            or data.get("File")
            or ""
        ).strip()
        detector = str(line.get("detector") or line.get("DetectorName") or "").strip()
        verified = bool(line.get("verified", line.get("Verified", False)))
        raw = str(line.get("raw") or line.get("Raw") or line.get("RawV2") or "")
        masked = mask_secret(line.get("masked") or raw)
        fingerprint = str(
            line.get("fingerprint") or secret_fingerprint(raw)
        ).strip()
        try:
            raw_length = int(line.get("raw_length") or len(raw))
        except (TypeError, ValueError):
            raw_length = len(raw)
        if not url or not detector or not verified:
            continue
        if not url.startswith(("http://", "https://")):
            # raw trufflehog filesystem source để lại path cục bộ — không ánh
            # xạ được về URL target thì DROP (không tạo Candidate rác)
            continue
        key = (url, detector, fingerprint)
        if key in seen:
            continue
        seen.add(key)
        hits.append(
            {
                "url": url,
                "detector": detector,
                "verified": True,
                "masked": masked,
                "fingerprint": fingerprint,
                "raw_length": raw_length,
            }
        )
    return hits


def write_secret_evidence(run_id: int, name: str | int, record: dict) -> str | None:
    """Ghi evidence secret ra volume ({run}/secrets/) — record chỉ chứa field
    đã mask (parser + script rescan đảm bảo). IO lỗi → None (không chết Run)."""
    try:
        base = Path(settings.evidence_dir) / str(run_id) / "secrets"
        base.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(name))
        path = base / f"{safe}.json"
        path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        return str(path)
    except OSError as exc:
        log.warning("run %d: không ghi được secret evidence (%s)", run_id, exc)
        return None


# ───────────────────────────── probe scripts (sandbox) ─────────────────────────────


def build_secret_baseline_script(url: str) -> str:
    """Baseline script (sh) chạy TRONG sandbox: python3 fetch `url`, KHÔNG
    follow redirect, ghi status/headers/content-type/body-length — RIÊNG việc
    KHÔNG ghi body: nội dung .env/backup chứa secret, evidence không được mang
    nó về (AC #16: evidence không chứa key đầy đủ)."""
    return (
        "python3 - <<'PY'\n"
        "import json, os, urllib.request, urllib.error\n"
        f"URL = {json.dumps(url)}\n"
        f"MARKER = {json.dumps(PROBE_MARKER)}\n"
        "\n"
        "\n"
        "class _NoRedirect(urllib.request.HTTPRedirectHandler):\n"
        "    def redirect_request(self, req, fp, code, msg, headers, newurl):\n"
        "        return None  # KHÔNG follow redirect\n"
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
        "except urllib.error.HTTPError as exc:  # 4xx/5xx vẫn là response để xét\n"
        "    resp = exc\n"
        "except Exception as exc:\n"
        "    _emit({\"url\": URL, \"status\": 0, \"error\": str(exc)[:300],\n"
        "           \"headers\": {}, \"content_type\": \"\", \"body_length\": 0,\n"
        "           \"body\": \"\"})\n"
        "    raise SystemExit(0)\n"
        "body = resp.read(65536)  # đọc rồi BỎ — chỉ đo độ dài, không ghi evidence\n"
        "_emit({\n"
        "    \"url\": URL,\n"
        "    \"status\": resp.getcode() or 0,\n"
        "    \"headers\": {str(k).lower(): str(v) for k, v in resp.headers.items()},\n"
        "    \"content_type\": str(resp.headers.get(\"content-type\", \"\")),\n"
        "    \"body_length\": int(resp.headers.get(\"content-length\") or 0) or len(body),\n"
        "    \"body\": \"\",  # KHÔNG thu body — tránh đưa secret vào evidence\n"
        "})\n"
        "PY"
    )


def build_secret_rescan_script(url: str) -> str:
    """Rescan script (sh) chạy TRONG sandbox: fetch URL hiện tại → trufflehog
    quét nội dung — KHÔNG verification (`--no-verification`: provider API là
    host ngoài Scope, egress proxy sẽ chặn → tắt cho sạch, verify-key đã làm
    ở Detection Phase) → parse + MASK (prefix only) trước khi in. Stdout của
    session không bao giờ chứa secret raw (trufflehog JSONL đổ vào file, không
    in ra; chỉ bản đã mask được emit sau PROBE_MARKER)."""
    return (
        "set -u\n"
        f"URL={json.dumps(url)}\n"
        "D=$(mktemp -d)\n"
        "code=$(curl -sS -m 25 -o \"$D/target\" -w '%{http_code}' \"$URL\" 2>/dev/null || echo 0)\n"
        "size=$(wc -c < \"$D/target\" 2>/dev/null || echo 0)\n"
        "# trufflehog KHÔNG verification (egress proxy chỉ cho target trong Scope);\n"
        "# JSONL đổ vào file — KHÔNG in ra stdout vì chứa Raw secret\n"
        "trufflehog filesystem \"$D\" --json --no-verification --no-update \\\n"
        "  >\"$D/th.jsonl\" 2>/dev/null || true\n"
        "export TH_URL=\"$URL\" TH_CODE=\"$code\" TH_SIZE=\"$size\" TH_LOG=\"$D/th.jsonl\"\n"
        "python3 - <<'PY'\n"
        "import hashlib, json, os\n"
        f"MARKER = {json.dumps(PROBE_MARKER)}\n"
        "MASK_KEEP = 4  # PHẢI khớp mask_secret() của worker (tests/test_secrets.py)\n"
        "\n"
        "\n"
        "def _mask(raw):\n"
        "    raw = str(raw or \"\")\n"
        "    if len(raw) < MASK_KEEP * 2:  # phần che ít hơn phần hiện → che hết\n"
        "        return \"…\"\n"
        "    return raw[:MASK_KEEP] + \"…\"\n"
        "\n"
        "\n"
        "def _fingerprint(raw):\n"
        "    # vân tay đối chiếu — sha256 truncated, không đảo ngược được\n"
        "    return hashlib.sha256(str(raw or \"\").encode()).hexdigest()[:12]\n"
        "\n"
        "\n"
        "def _int(value):\n"
        "    try:\n"
        "        return int(str(value or \"0\").strip() or 0)\n"
        "    except ValueError:\n"
        "        return 0\n"
        "\n"
        "\n"
        "try:\n"
        "    lines = open(os.environ.get(\"TH_LOG\", \"\"), encoding=\"utf-8\",\n"
        "                 errors=\"replace\").read().splitlines()\n"
        "except OSError:\n"
        "    lines = []\n"
        "secrets, seen = [], set()\n"
        "for line in lines:\n"
        "    line = line.strip()\n"
        "    if not line.startswith(\"{\"):\n"
        "        continue\n"
        "    try:\n"
        "        obj = json.loads(line)\n"
        "    except ValueError:\n"
        "        continue\n"
        "    if not isinstance(obj, dict):\n"
        "        continue\n"
        "    detector = str(obj.get(\"DetectorName\") or \"\")\n"
        "    raw = str(obj.get(\"Raw\") or obj.get(\"RawV2\") or \"\")\n"
        "    masked = _mask(obj.get(\"masked\") or raw)\n"
        "    key = (detector, _fingerprint(raw))\n"
        "    if not detector or key in seen:\n"
        "        continue\n"
        "    seen.add(key)\n"
        "    secrets.append({\"detector\": detector, \"masked\": masked,\n"
        "                    \"fingerprint\": _fingerprint(raw),\n"
        "                    \"raw_length\": _int(obj.get(\"raw_length\") or len(raw))})\n"
        "print(MARKER)\n"
        "print(json.dumps({\n"
        "    \"url\": os.environ.get(\"TH_URL\", \"\"),\n"
        "    \"http_status\": _int(os.environ.get(\"TH_CODE\")),\n"
        "    \"content_length\": _int(os.environ.get(\"TH_SIZE\")),\n"
        "    \"secrets\": secrets,\n"
        "}, ensure_ascii=False))\n"
        "PY"
    )


def parse_secret_rescan(stdout: str) -> dict | None:
    """Đọc kết quả rescan từ stdout sandbox: dict ở dòng đầu tiên không trống
    SAU marker; thiếu marker/JSON đứt → None. Field trả về đã mask sẵn bởi
    script; secrets rỗng/không hợp lệ bị bỏ."""
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
                "http_status": int(raw.get("http_status") or 0),
                "content_length": int(raw.get("content_length") or 0),
                "secrets": [
                    {
                        "detector": str(h.get("detector") or ""),
                        "masked": str(h.get("masked") or ""),
                        "fingerprint": str(h.get("fingerprint") or ""),
                        "raw_length": int(h.get("raw_length") or 0),
                    }
                    for h in (raw.get("secrets") or []) if isinstance(h, dict)
                ],
            }
    return None


# ───────────────────────────── phân tích (seam thuần) ─────────────────────────────


@dataclass
class SecretAnalysis:
    """Kết quả phân tích rescan so với detection: pattern log (mọi pattern
    khớp), tín hiệu khai thác được, confidence 0.0–1.0, verdict theo ngưỡng."""

    patterns: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    score: float = 0.0
    verdict: str = "rejected"
    reason: str = ""
    diff: dict = field(default_factory=dict)


def _baseline_waf(baseline: ProbeProfile) -> bool:
    """Baseline bị chặn WAF? Không có body (không thu) nên xét status + header
    values (vd server: cloudflare)."""
    if baseline.status in _WAF_BLOCK_STATUSES:
        return True
    blob = " ".join(baseline.headers.values()).lower()
    return any(m in blob for m in _WAF_MARKERS)


def analyze_secret(
    baseline: ProbeProfile | None,
    rescan: dict | None,
    expected_detector: str,
    expected_masked: str,
    threshold: float | None = None,
    expected_fingerprint: str = "",
) -> SecretAnalysis:
    """Đối chiếu rescan (sandbox quét lại URL hiện tại) với detection:
    - CÙNG detector + CÙNG fingerprint → vẫn còn exposed → verified (0.95);
      fingerprint thiếu (evidence cũ) thì hạ xuống so prefix;
    - WAF chặn baseline / probe lỗi / rescan hỏng → rejected (không báo thật);
    - URL không còn serve (4xx/5xx) hoặc không còn secret → no_longer_exposed;
    - còn serve nhưng secret KHÁC (detector/fingerprint lệch) → secret_changed.
    """
    threshold = default_threshold() if threshold is None else float(threshold)
    diff = {
        "baseline_status": baseline.status if baseline else None,
        "rescan_http_status": (rescan or {}).get("http_status"),
        "content_length": (rescan or {}).get("content_length"),
        "fresh_hits": len((rescan or {}).get("secrets") or []),
    }

    def _reject(patterns: list[str], score: float, reason: str) -> SecretAnalysis:
        return SecretAnalysis(patterns=patterns, score=score,
                              verdict="rejected", reason=reason, diff=diff)

    if baseline is None or baseline.error:
        return _reject(["probe_error"], 0.0,
                       f"Không đọc được profile baseline từ sandbox: "
                       f"{baseline.error if baseline else 'thiếu baseline'}")
    if _baseline_waf(baseline):
        return _reject(["waf_block"], 0.0,
                       f"URL bị chặn (HTTP {baseline.status}) khi probe baseline "
                       "— không xác minh được, không báo thật")
    if rescan is None:
        return _reject(["probe_error"], 0.0,
                       "Không đọc được kết quả rescan từ stdout sandbox "
                       "(thiếu marker/JSON đứt)")

    if not expected_detector or not expected_masked:
        return _reject(["no_detection_reference"], 0.0,
                       "Candidate không mang marker detection (detector|prefix) "
                       "để đối chiếu — không xác minh được")

    if not 200 <= rescan["http_status"] < 300:
        return _reject(
            ["no_longer_exposed"], 0.0,
            f"URL không còn phục vụ nội dung gốc (HTTP {rescan['http_status']}) — "
            "secret có thể đã bị xoá, không còn report được",
        )

    def _same_secret(hit: dict) -> bool:
        if hit["detector"] != expected_detector:
            return False
        hit_fp = hit.get("fingerprint") or ""
        if expected_fingerprint and hit_fp:
            return hit_fp == expected_fingerprint
        return hit["masked"] == expected_masked  # fallback evidence cũ

    matched = [h for h in rescan["secrets"] if _same_secret(h)]
    if matched:
        return SecretAnalysis(
            patterns=["secret_still_exposed"], signals=["secret_still_exposed"],
            score=SCORE_STILL_EXPOSED,
            verdict="verified" if SCORE_STILL_EXPOSED >= threshold else "rejected",
            reason=(
                f"Secret '{expected_detector}' (prefix {expected_masked}, đã "
                "verify-key ở Detection Phase) VẪN còn được phục vụ tại URL — "
                "rescan sandbox xác nhận lại. Evidence chỉ chứa prefix đã che."
            ),
            diff=diff,
        )
    if rescan["secrets"]:
        return _reject(
            ["secret_changed"], 0.2,
            "URL còn serve secret nhưng KHÁC secret đã detect (detector/"
            "fingerprint lệch — key có thể đã rotate) — không báo Finding trên "
            "secret cũ",
        )
    return _reject(
        ["no_longer_exposed"], 0.0,
        "Nội dung còn được phục vụ nhưng rescan không còn thấy secret đã "
        "detect — có thể đã bị xoá/đổi, không report được",
    )


# ───────────────────────────── detection pipeline (async) ─────────────────────────────


async def run_secret_detection(
    pool: asyncpg.Pool,
    run: asyncpg.Record | dict,
    tool_runner=None,
    live_urls: list[str] | None = None,
    classed_urls: list[str] | None = None,
) -> dict:
    """Detection batch B của 1 Run (chạy sau Detection Phase chính, như batch
    A): chọn URL nhạy cảm (.env/bucket/JS/backup) từ bề mặt đã thu → tool
    `trufflehog-urls` quét với `--only-verified` (verify-key) → secret hợp lệ
    → Candidate class `secret` severity `high` kèm evidence ĐÃ CHE key. Tool
    lỗi coi như không phát hiện gì; target ngoài Scope bị chặn như mọi Tool
    Execution."""
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

    # build_targets: dedupe + cap theo Detection Phase chính; select: lọc URL
    # nhạy cảm + cap riêng của lớp secret (minimum testing necessary)
    targets = select_secret_urls(detect.build_targets(live_urls, classed_urls))
    if not targets:
        return {"candidates": 0, "blocked": 0}
    allowed, blocked = await filter_scope(pool, ctx, targets, TRUFFLEHOG_URLS_TOOL)
    await add_log(
        pool, run_id,
        f"Batch B: {len(allowed)}/{len(targets)} URL nhạy cảm trong Scope "
        f"(validator chặn {blocked}) — trufflehog-urls (verify-key, "
        f"cap {settings.secrets_max_targets})",
    )
    if not allowed:
        return {"candidates": 0, "blocked": blocked}

    res = await execute_tool(
        pool, ctx, TRUFFLEHOG_URLS_TOOL,
        ["--delay", format_delay(delay_for_run(run["rate_limit_rps"]))],
        stdin="\n".join(allowed), runner=tool_runner,
        docker_args=[
            # pacing + header định danh cho từng fetch trong wrapper (rate
            # limit của Run áp cả cấp request, không chỉ lúc launch tool)
            "-e", f"FETCH_DELAY_S={format_delay(delay_for_run(run['rate_limit_rps']))}",
            *[
                env
                for name, value in (ctx.ident or {}).items()
                for env in (f"IDENT_HEADER_NAME={name}", f"IDENT_HEADER_VALUE={value}")
            ],
        ],
    )
    if res.exit_code != 0:
        await add_log(
            pool, run_id,
            f"trufflehog-urls exit {res.exit_code} — không có Candidate secret",
            level="error",
        )
        return {"candidates": 0, "blocked": blocked}

    rows: list[CandidateRow] = []
    seen: set[tuple] = set()
    for hit in parse_trufflehog_jsonl(res.stdout):
        key = (hit["url"], SECRET_CANDIDATE_CLASS, detect.param_key(hit["url"]))
        if key in seen:
            continue
        seen.add(key)
        evidence_path = write_secret_evidence(run_id, len(rows) + 1, {
            "schema": "vulhunt.secret-detection-evidence/1",
            "url": hit["url"],
            "detector": hit["detector"],
            "verified": hit["verified"],
            "masked": hit["masked"],       # chỉ prefix — KHÔNG bao giờ raw
            "fingerprint": hit["fingerprint"],  # vân tay đối chiếu verify
            "raw_length": hit["raw_length"],
            "note": "Secret đã che (prefix + fingerprint) — key đầy đủ không nằm trong evidence",
        })
        rows.append(
            CandidateRow(
                run_id=run_id,
                target=hit["url"],
                cls=SECRET_CANDIDATE_CLASS,
                param=key[2],
                template_id=f"{TRUFFLEHOG_URLS_TOOL}/{hit['detector']}",
                title=f"Exposed secrets ({hit['detector']})",
                severity=SECRET_SEVERITY,
                matcher_name=secret_marker(
                    hit["detector"], hit["masked"], hit["fingerprint"]
                ),
                status="new",
                evidence_path=evidence_path,
            )
        )
    await detect._insert_candidates(pool, rows)
    await add_log(
        pool, run_id,
        f"Batch B: {len(rows)} Candidate secret (đã verify-key; evidence chỉ "
        f"chứa prefix) — chờ vòng xác minh rescan",
    )
    return {"candidates": len(rows), "blocked": blocked}


# ───────────────────────────── verify pipeline (async) ─────────────────────────────


# RETURNING dùng đúng CANDIDATE_COLS của detect (giống httpverify/verify)
_VERDICT_SQL = f"""
UPDATE candidates SET status = $2, confidence = $3, confidence_threshold = $4,
    reject_reason = $5, verify_evidence_path = $6, verify_session_id = $7,
    baseline_session_id = $8
WHERE id = $1 RETURNING {CANDIDATE_COLS}
"""


def _evidence_record(
    candidate: dict,
    threshold: float,
    analysis: SecretAnalysis,
    baseline: ProbeProfile | None,
    baseline_session_id: int | None,
    rescan: dict | None,
    poc_session_id: int | None,
) -> dict:
    """Nội dung file evidence của vòng verify secret — baseline (KHÔNG body) +
    rescan (đã mask) + phân tích. Không field nào có thể chứa secret đầy đủ."""
    expected_detector, expected_masked, expected_fingerprint = parse_secret_marker(
        candidate.get("matcher_name") or ""
    )
    return {
        "schema": "vulhunt.secret-verify-evidence/1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate["id"],
        "run_id": candidate["run_id"],
        "class": candidate.get("class"),
        "target": candidate.get("target"),
        "expected": {
            "detector": expected_detector,
            "masked": expected_masked,
            "fingerprint": expected_fingerprint,
        },
        "threshold": threshold,
        "baseline": baseline.to_dict() if baseline else {"skipped": True},
        "rescan": rescan or {"skipped": True},
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
        "note": "Evidence chỉ chứa prefix đã che — KHÔNG bao giờ chứa secret đầy đủ.",
    }


async def run_secret_verification(
    pool: asyncpg.Pool,
    candidate: dict,
    probe: "ProbeCallable | None" = None,
    threshold: float | None = None,
) -> dict:
    """Trọn vòng verify 1 Candidate class `secret`: baseline capture (KHÔNG
    thu body) → rescan sandbox (fetch + trufflehog KHÔNG verification, mask
    trước khi emit) → đối chiếu detector + prefix với detection → vẫn còn
    exposed → Finding; đã bị xoá/đổi → rejected kèm pattern log.

    `probe(script, target)` là seam thực thi (mặc định sandbox.run_verify_
    session — container ephemeral, scope + egress + rate limit). Contract lỗi
    giống verify redirect: target bị chặn scope → ProbeBlocked (trả lifecycle
    về cũ); class khác 'secret' → ValueError; lỗi môi trường → RuntimeError.
    """
    candidate_id = candidate["id"]
    run_id = candidate["run_id"]
    cls = str(candidate.get("class") or "").strip()
    if cls != SECRET_CANDIDATE_CLASS:
        raise ValueError(
            f"class '{cls}' không phải lớp exposed secrets "
            f"(chỉ nhận '{SECRET_CANDIDATE_CLASS}')"
        )
    threshold = default_threshold() if threshold is None else float(threshold)
    expected_detector, expected_masked, expected_fingerprint = parse_secret_marker(
        candidate.get("matcher_name") or ""
    )
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
                 analysis: SecretAnalysis, evidence: str | None,
                 base_sid: int | None, poc_sid: int | None) -> dict:
        return {
            "candidate_id": candidate_id,
            "run_id": run_id,
            "class": cls,
            "expected": {
                "detector": expected_detector,
                "masked": expected_masked,
                "fingerprint": expected_fingerprint,
            },
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

    if probe is None:
        run = await sandbox.resolve_run(pool, run_id)
        if run is None:
            raise ValueError("không có Run nào — không thể xác minh qua sandbox")

        async def probe(script: str, target: str, _run: asyncpg.Record = run) -> dict:
            return await sandbox.run_verify_session(pool, _run, script, target)

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

    base_res = await _run_probe(build_secret_baseline_script(candidate["target"]))
    baseline = parse_probe(base_res.get("stdout") or "")

    # WAF chặn baseline → dừng TRƯỚC rescan (minimum testing necessary)
    pre_reject = None
    if baseline is None:
        pre_reject = SecretAnalysis(
            patterns=["probe_error"], score=0.0, verdict="rejected",
            reason="Không đọc được profile baseline từ stdout sandbox "
                   "(thiếu marker/JSON đứt)",
        )
    elif _baseline_waf(baseline):
        pre_reject = analyze_secret(baseline, None, expected_detector,
                                    expected_masked, threshold,
                                    expected_fingerprint)

    if pre_reject is not None:
        evidence = write_secret_evidence(run_id, f"{candidate_id:03d}-verify", {
            **_evidence_record(candidate, threshold, pre_reject, baseline,
                               base_res.get("session_id"), None, None),
        })
        await _update_verdict(pre_reject.verdict, pre_reject.score,
                              pre_reject.reason, evidence,
                              None, base_res.get("session_id"))
        await add_log(
            pool, run_id,
            f"Verify secret Candidate #{candidate_id}: {pre_reject.verdict} · "
            f"patterns: {', '.join(pre_reject.patterns)}"
            + (f" · evidence: {evidence}" if evidence else ""),
        )
        return _summary(pre_reject.verdict, pre_reject.score, pre_reject.reason,
                        pre_reject, evidence, base_res.get("session_id"), None)

    poc_res = await _run_probe(build_secret_rescan_script(candidate["target"]))
    rescan = parse_secret_rescan(poc_res.get("stdout") or "")
    analysis = analyze_secret(baseline, rescan, expected_detector,
                              expected_masked, threshold, expected_fingerprint)

    evidence = write_secret_evidence(run_id, f"{candidate_id:03d}-verify",
                                     _evidence_record(
                                         candidate, threshold, analysis, baseline,
                                         base_res.get("session_id"), rescan,
                                         poc_res.get("session_id")))
    base_sid = base_res.get("session_id")
    poc_sid = poc_res.get("session_id")
    await _update_verdict(
        analysis.verdict, analysis.score,
        analysis.reason if analysis.verdict == "rejected" else None,
        evidence, poc_sid, base_sid,
    )
    await add_log(
        pool, run_id,
        f"Verify secret Candidate #{candidate_id}: {analysis.verdict} "
        f"(score {analysis.score:.2f} / ngưỡng {threshold:.2f}) · patterns: "
        f"{', '.join(analysis.patterns) or '—'}"
        + (f" · evidence: {evidence}" if evidence else ""),
    )
    return _summary(analysis.verdict, analysis.score, analysis.reason,
                    analysis, evidence, base_sid, poc_sid)
