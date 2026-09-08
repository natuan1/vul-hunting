"""Detection Phase (ticket #10) — nuclei quét bề mặt từ Recon → Candidate.

Chạy NGAY SAU Recon Phase trong cùng Run: nuclei (templates baked sẵn trong
tooling image) quét live host + URL đã có nhãn class từ giai đoạn 2. Mỗi
finding → 1 **Candidate** (status `new`) kèm **Evidence** (raw request/
response, template id, matcher) lưu file JSON trên docker volume + path trong
DB — nguồn cho vòng xác minh (ticket #12+).

Cơ chế an toàn kế thừa từ Recon: MỌI target đưa vào nuclei và MỌI matched-at
trong kết quả đều qua Scope Validator (theo host, có audit) — target ngoài
Scope không có request nào đi ra và không thành Candidate; rate limit của Run
áp cho launch (RateLimiter) lẫn request của nuclei (-rl/-c).
"""

import json
import logging
import re
from collections import namedtuple
from pathlib import Path

import asyncpg

from .config import settings
from .recon import normalize_url, url_param_names
from .tools import (
    ToolContext,
    add_log,
    build_context,
    execute_tool,
    filter_scope,
    jsonl_lines,
)

log = logging.getLogger("detect")

# lifecycle của Candidate (migration 0008 CHECK ràng buộc cùng bộ này)
STATUSES = ("new", "verifying", "verified", "rejected")

# vocab lớp lỗ hổng — thứ tự trong tuple là thứ tự ưu tiên khi 1 template
# mang nhiều tag khớp (vd tags ["xss","reflected"] → class "xss"); không khớp
# tag nào thì "misc" (CVE, exposure, ...)
_CLASS_VOCAB = (
    "xss", "sqli", "ssrf", "redirect", "ssti", "lfi", "rce", "idor",
    "crlf", "cors", "takeover", "exposure", "debug", "misconfig", "disclosure",
)

_SEVERITIES = ("info", "low", "medium", "high", "critical")

_SAFE_FILENAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")

# ───────────────────────────── seam thuần (có test) ─────────────────────────────


def parse_nuclei_jsonl(stdout: str) -> list[dict]:
    """nuclei -j → 1 finding JSON/dòng; dòng rác bỏ qua."""
    return jsonl_lines(stdout)


def map_class(tags: list) -> str:
    """Class của Candidate = tag của template khớp vocab (ưu tiên thứ tự
    vocab); không khớp → 'misc'."""
    tagset = {str(t).lower() for t in (tags or [])}
    for cls in _CLASS_VOCAB:
        if cls in tagset:
            return cls
    return "misc"


def param_key(target: str) -> str:
    """Tên param của target (sorted, nối phẩy) — thành phần dedupe
    'cùng asset + class + param'; target không có query → rỗng."""
    return ",".join(url_param_names(target))


def build_nuclei_args(rate_limit_rps: float | None, ident: dict[str, str]) -> list[str]:
    """Args cho nuclei: templates baked trong image (không tải lúc chạy),
    loại template headless (cần browser); template OOB dùng interactsh public
    server (ticket #13) — nuclei tự register/poll riêng cho từng lần chạy và
    nhúng interaction vào finding JSON, không dùng registration per-Run của
    worker; throttle theo rate limit của Run + header định danh."""
    args = [
        "-silent", "-nc", "-j",
        "-t", settings.nuclei_templates_dir,
        "-etags", "headless",
    ]
    if rate_limit_rps and rate_limit_rps > 0:
        n = str(max(1, round(rate_limit_rps)))
        args += ["-rl", n, "-c", n]
    for name, value in (ident or {}).items():
        args += ["-H", f"{name}: {value}"]
    return args


def build_targets(
    live_urls: list, classed_urls: list, max_targets: int | None = None
) -> list[str]:
    """Danh sách target cho nuclei: live host (URL httpx) trước, URL đã phân
    loại class sau; dedupe giữ thứ tự, cắt theo cap để giữ nhịp điều độ."""
    cap = settings.detection_max_targets if max_targets is None else max_targets
    out: list[str] = []
    seen: set[str] = set()
    for t in list(live_urls or []) + list(classed_urls or []):
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out[:cap]


def write_evidence(run_id: int, index: int, finding: dict) -> str | None:
    """Ghi evidence (raw finding JSON: request/response, template id, matcher)
    ra volume; trả path hoặc None nếu IO lỗi (volume chết không làm chết Run)."""
    try:
        base = Path(settings.evidence_dir) / str(run_id) / "candidates"
        base.mkdir(parents=True, exist_ok=True)
        tid = _SAFE_FILENAME_RE.sub("_", str(finding.get("template-id") or "template"))
        path = base / f"{index:03d}-{tid}.json"
        path.write_text(json.dumps(finding, ensure_ascii=False), encoding="utf-8")
        return str(path)
    except OSError as exc:
        log.warning("run %d: không ghi được evidence (%s)", run_id, exc)
        return None


def validate_status(status: str) -> str:
    """Nhận một trong 4 trạng thái lifecycle, chuẩn hoá lowercase; khác → lỗi."""
    s = (status or "").strip().lower()
    if s not in STATUSES:
        raise ValueError(f"status phải là một trong {', '.join(STATUSES)}")
    return s


def validate_severity(severity: str) -> str:
    """Validate giá trị severity cho filter — khác vocab → lỗi."""
    s = str(severity or "").strip().lower()
    if s not in _SEVERITIES:
        raise ValueError(f"severity phải là một trong {', '.join(_SEVERITIES)}")
    return s


def _severity(value) -> str:
    """Chuẩn hoá severity từ output nuclei — lạ/không có thì 'info'."""
    try:
        return validate_severity(value)
    except ValueError:
        return "info"


# ───────────────────────────── pipeline (async) ─────────────────────────────


def _severity_rank_sql() -> str:
    """ORDER BY severity theo mức nghiêm trọng giảm dần — suy từ _SEVERITIES
    (một nguồn sự thật, không lặp literal ở đây)."""
    order = ", ".join(f"'{s}'" for s in reversed(_SEVERITIES))
    return f"array_position(ARRAY[{order}], severity)"


CandidateRow = namedtuple(
    "CandidateRow",
    # cột SQL là "class" nhưng 'class' là keyword Python → field tên cls
    "run_id target cls param template_id title severity matcher_name status evidence_path",
)

CANDIDATE_COLS = (
    "id, run_id, target, class, param, template_id, title, severity, "
    "matcher_name, status, evidence_path, first_seen, "
    # kết quả vòng xác minh (ticket #12)
    "confidence, confidence_threshold, reject_reason, verify_evidence_path, "
    "verify_session_id, baseline_session_id, "
    # OOB callback (ticket #13): count hiển thị UI + path evidence callback
    "oob_callback_count, oob_evidence_path"
)

_SELECT_CANDIDATES = f"SELECT {CANDIDATE_COLS}\nFROM candidates\n"

_INSERT_CANDIDATES_SQL = """
INSERT INTO candidates (run_id, target, class, param, template_id,
                        title, severity, matcher_name, status, evidence_path)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (run_id, target, class, param) DO NOTHING
"""


async def _insert_candidates(pool, rows: list[CandidateRow]) -> None:
    if not rows:
        return
    async with pool.acquire() as conn:
        await conn.executemany(_INSERT_CANDIDATES_SQL, rows)


async def _load_targets(pool: asyncpg.Pool, run_id: int) -> tuple[list[str], list[str]]:
    """Target từ DB: URL httpx của live host + URL đã có nhãn class (giai đoạn 2)."""
    async with pool.acquire() as conn:
        live = [
            r["http_url"] or f"https://{r['host']}"
            for r in await conn.fetch(
                "SELECT host, http_url FROM recon_assets WHERE run_id = $1 AND is_live",
                run_id,
            )
        ]
        classed = [
            r["url"]
            for r in await conn.fetch(
                "SELECT url FROM recon_urls WHERE run_id = $1 "
                "AND array_length(classes, 1) > 0",
                run_id,
            )
        ]
    return live, classed


async def run_detection_phase(
    pool: asyncpg.Pool,
    run: asyncpg.Record | dict,
    tool_runner=None,
    live_urls: list[str] | None = None,
    classed_urls: list[str] | None = None,
) -> dict:
    """Detection Phase của 1 Run (chạy sau Recon Phase). `run` cần id,
    rate_limit_rps, ident_header_name/value, scope_snapshot, allow_non_prod.
    Trả {candidates, blocked} để log cuối Run.

    Tool lỗi (exit ≠ 0) coi như không phát hiện gì — không làm chết Run; chỉ
    lỗi môi trường (docker) ném lên cho jobqueue retry.
    """
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
        db_live, db_classed = await _load_targets(pool, run_id)
        live_urls = db_live if live_urls is None else live_urls
        classed_urls = db_classed if classed_urls is None else classed_urls

    all_targets = build_targets(live_urls, classed_urls)
    targets, blocked = await filter_scope(pool, ctx, all_targets, "nuclei")
    await add_log(
        pool, run_id,
        f"Detection Phase: nuclei quét {len(targets)} target "
        f"(validator chặn {blocked})",
    )
    if not targets:
        return {"candidates": 0, "blocked": blocked}

    res = await execute_tool(
        pool, ctx, "nuclei",
        build_nuclei_args(run["rate_limit_rps"], ctx.ident),
        stdin="\n".join(targets), runner=tool_runner,
    )
    if res.exit_code != 0:
        await add_log(
            pool, run_id, f"nuclei exit {res.exit_code} — không có Candidate",
            level="error",
        )
        return {"candidates": 0, "blocked": blocked}

    # mỗi finding: matched-at qua validator lần nữa (phòng hờ), dedupe theo
    # (target + class + param) — finding đầu tiên thắng, template sau bị bỏ
    rows: list[CandidateRow] = []
    seen_keys: set[tuple] = set()
    for finding in parse_nuclei_jsonl(res.stdout):
        raw_target = str(finding.get("matched-at") or finding.get("host") or "").strip()
        if not raw_target:
            continue
        ok, n = await filter_scope(pool, ctx, [raw_target], "nuclei")
        blocked += n
        if not ok:
            continue
        target = ok[0]
        cls = map_class((finding.get("info") or {}).get("tags"))
        key = (target, cls, param_key(target))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        info = finding.get("info") or {}
        rows.append(
            CandidateRow(
                run_id=run_id,
                target=target,
                cls=cls,
                param=key[2],
                template_id=str(finding.get("template-id") or ""),
                title=str(info.get("name") or ""),
                severity=_severity(info.get("severity")),
                matcher_name=str(finding.get("matcher-name") or ""),
                status="new",
                evidence_path=write_evidence(run_id, len(rows) + 1, finding),
            )
        )
    await _insert_candidates(pool, rows)
    await add_log(
        pool, run_id,
        f"Detection: {len(rows)} Candidate (đã dedupe cùng asset+class+param) · "
        f"evidence lưu {settings.evidence_dir}/{run_id}/candidates/",
    )
    return {"candidates": len(rows), "blocked": blocked}


# ───────────────────────────── API cho Findings screen ─────────────────────────────


async def counts_for(pool: asyncpg.Pool, run_id: int) -> dict:
    """Bộ đếm Candidate của Run theo status (dùng cho run detail + findings)."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT status, count(*) AS n FROM candidates WHERE run_id = $1 GROUP BY status",
            run_id,
        )
    counts = {s: 0 for s in STATUSES}
    for r in rows:
        counts[r["status"]] = r["n"]
    counts["total"] = sum(counts.values())
    return counts


async def list_candidates(
    pool: asyncpg.Pool,
    run_id: int | None = None,
    status: str | None = None,
    class_: str | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> dict:
    """List Candidate + bộ đếm theo status — filter theo Run/status/class/
    severity. Bộ đếm tôn trọng filter run/class/severity (nhưng KHÔNG theo
    status — để badges còn làm nút chuyển filter). Status/severity không hợp
    lệ raise ValueError (endpoint map thành 422)."""
    base: list[tuple[str, object]] = []
    if run_id is not None:
        base.append(("run_id = ?", run_id))
    if class_:
        base.append(("class = ?", class_))
    if severity:
        base.append(("severity = ?", validate_severity(severity)))
    status_pair = ("status = ?", validate_status(status)) if status else None

    def _where(pairs: list[tuple[str, object]]) -> tuple[str, list]:
        if not pairs:
            return "", []
        params = [v for _, v in pairs]
        conds = [c.replace("?", f"${i + 1}") for i, (c, _) in enumerate(pairs)]
        return "WHERE " + " AND ".join(conds), params

    items_where, items_params = _where(base + ([status_pair] if status_pair else []))
    counts_where, counts_params = _where(base)

    async with pool.acquire() as conn:
        items = [
            dict(r)
            for r in await conn.fetch(
                f"{_SELECT_CANDIDATES}{items_where} "
                f"ORDER BY {_severity_rank_sql()}, id DESC LIMIT ${len(items_params) + 1}",
                *items_params,
                limit,
            )
        ]
        counts_rows = await conn.fetch(
            f"SELECT status, count(*) AS n FROM candidates {counts_where} GROUP BY status",
            *counts_params,
        )
    by_status = {s: 0 for s in STATUSES}
    for r in counts_rows:
        by_status[r["status"]] = r["n"]
    return {
        "counts": {"total": sum(by_status.values()), **by_status},
        "items": items,
    }


async def get_candidate(pool: asyncpg.Pool, candidate_id: int) -> dict | None:
    """Chi tiết 1 Candidate (Findings detail)."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(f"{_SELECT_CANDIDATES}WHERE id = $1", candidate_id)
    return dict(row) if row else None


async def set_status(pool: asyncpg.Pool, candidate_id: int, status: str) -> dict | None:
    """Chuyển trạng thái lifecycle — 1 round-trip duy nhất (UPDATE … RETURNING);
    id không tồn tại → None."""
    s = validate_status(status)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"UPDATE candidates SET status = $2 WHERE id = $1 "
            f"RETURNING {CANDIDATE_COLS}",
            candidate_id,
            s,
        )
    return dict(row) if row else None


# cap đọc evidence để không ngập UI — file đầy đủ vẫn nằm trên volume
EVIDENCE_READ_CAP = 200_000

# cột path evidence được phép đọc (whitelist — không nhận string lạ từ caller)
_EVIDENCE_PATH_COLUMNS = ("evidence_path", "verify_evidence_path", "oob_evidence_path")


async def read_evidence(
    pool: asyncpg.Pool, candidate_id: int, path_column: str = "evidence_path"
) -> dict | None:
    """Nội dung evidence file của Candidate (evidence viewer): `evidence_path`
    (Detection Phase) hoặc `verify_evidence_path` (vòng xác minh, ticket #12).
    Path trong DB luôn phải nằm dưới evidence_dir — chặn truy cập ngoài thư
    mục evidence."""
    if path_column not in _EVIDENCE_PATH_COLUMNS:
        raise ValueError(f"cột evidence không hợp lệ: {path_column}")
    async with pool.acquire() as conn:
        path = await conn.fetchval(
            f"SELECT {path_column} FROM candidates WHERE id = $1", candidate_id
        )
    if not path:
        return None
    base = Path(settings.evidence_dir).resolve()
    target = Path(path).resolve()
    # path-jail CHÍNH XÁC: file phải nằm TRONG evidence_dir (startswith trần
    # sẽ khớp nhầm thư mục anh em như /data/evidence-evil)
    if target != base and base not in target.parents:
        log.warning("evidence path %s nằm ngoài %s — từ chối", path, base)
        return None
    try:
        content = target.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("đọc evidence %s lỗi: %s", path, exc)
        return None
    return {
        "path": path,
        "truncated": len(content) > EVIDENCE_READ_CAP,
        "content": content[:EVIDENCE_READ_CAP],
    }
