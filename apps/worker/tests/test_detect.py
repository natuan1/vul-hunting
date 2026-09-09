"""Test Detection core (ticket #10) — nuclei → Candidate + Evidence.

Các seam thuần: parser JSONL của nuclei, map class từ template tags, args
builder, danh sách target, ghi evidence file, validate status; pipeline với
tool giả (âm tính: matched-at ngoài Scope bị chặn tại validator, không bao
giờ thành Candidate).

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests -q
"""

import json

import pytest

from app.detect import (
    map_class,
    parse_nuclei_jsonl,
    build_nuclei_args,
    build_targets,
    param_key,
    run_detection_phase,
    validate_status,
    write_evidence,
)
from app.tools import build_context, filter_scope
from fakes import FakePool, FakeRunner

SNAPSHOT = [
    {"asset_identifier": "app.other.com", "asset_type": "URL"},
]

FINDING = {
    "template-id": "reflected-xss",
    "info": {
        "name": "Reflected XSS",
        "severity": "medium",
        "tags": ["xss", "reflected"],
    },
    "host": "https://app.other.com",
    "matched-at": "https://app.other.com/login?q=1",
    "matcher-name": "multi-pattern",
    "type": "http",
}


def _nuclei_stdout(*findings: dict) -> str:
    lines = [json.dumps(f) for f in findings]
    lines.insert(1, "dòng rác không phải json")  # nuclei in lẫn stderr-linh tinh
    return "\n".join(lines)


@pytest.fixture(autouse=True)
def _isolated_dirs(tmp_path, monkeypatch):
    """Pipeline test không được đụng evidence/artifact thật trên volume."""
    from app import config

    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))
    monkeypatch.setattr(config.settings, "artifacts_dir", str(tmp_path / "artifacts"))


# ── parser ──


def test_parse_nuclei_jsonl_lấy_json_bỏ_dòng_rác():
    out = _nuclei_stdout(FINDING, FINDING)
    findings = parse_nuclei_jsonl(out)
    assert len(findings) == 2
    assert findings[0]["template-id"] == "reflected-xss"


def test_parse_nuclei_jsonl_rỗng():
    assert parse_nuclei_jsonl("") == []
    assert parse_nuclei_jsonl("[INF] không phải json\n{đứt}") == []


# ── map_class: tags nuclei ∩ vocab lớp lỗ hổng ──


def test_map_class_giao_với_vocab_ưu_tiên_thứ_tự_vocab():
    assert map_class(["cve", "xss", "reflected"]) == "xss"
    assert map_class(["xss", "sqli"]) in ("xss", "sqli")


def test_map_class_không_match_vocab_trả_misc():
    assert map_class(["cve2024", "wordpress"]) == "misc"
    assert map_class([]) == "misc"


# ── map_class batch A (#15): 7 lớp HTTP-only ra đúng class qua tag/alias ──


def test_map_class_batch_a_bảy_lớp_ra_đúng_class():
    assert map_class(["cors", "misconfig"]) == "cors"
    assert map_class(["listing", "misconfig"]) == "dirlist"
    assert map_class(["graphql", "misconfig"]) == "graphql"
    assert map_class(["crlf"]) == "crlf"
    assert map_class(["ssti"]) == "ssti"
    assert map_class(["config", "misconfig"]) == "headers"
    # info disclosure/debug endpoints — gộp exposure/debug/disclosure về 1 lớp
    assert map_class(["exposure"]) == "disclosure"
    assert map_class(["debug"]) == "disclosure"
    assert map_class(["disclosure"]) == "disclosure"


def test_map_class_batch_a_không_đổi_hành_vi_class_cũ():
    assert map_class(["xss", "reflected"]) == "xss"
    assert map_class(["ssrf"]) == "ssrf"
    assert map_class(["redirect"]) == "redirect"


# ── build_nuclei_args ──


def test_build_nuclei_args_có_templates_ni_silent_và_json(monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "nuclei_templates_dir", "/home/tooler/nuclei-templates")
    args = build_nuclei_args(None, {})
    flat = " ".join(args)
    assert "-silent" in args and "-nc" in args and "-j" in args
    assert "-t /home/tooler/nuclei-templates" in flat
    assert "-etags headless" in flat  # không chạy template headless (cần browser)
    assert "-ni" not in args  # ticket #13: template OOB dùng interactsh public server
    assert "-rl" not in args and "-c" not in args


def test_build_nuclei_args_rate_limit_và_header_định_danh():
    from app import config

    args = build_nuclei_args(2.6, {"X-Bug-Bounty": "HackerOne-tuan"})
    flat = " ".join(args)
    assert "-rl 3" in flat and "-c 3" in flat  # 2.6 → 3 (int, như httpx -rl)
    assert "-H X-Bug-Bounty: HackerOne-tuan" in flat


# ── build_targets: dedupe + cap ──


def test_build_targets_dedupe_live_ước_classed_sau_và_cap():
    live = ["https://a.com/", "https://b.com/x"]
    classed = ["https://b.com/x", "https://c.com/?q=1", "https://d.com/"]
    targets = build_targets(live, classed, max_targets=3)
    assert targets == ["https://a.com/", "https://b.com/x", "https://c.com/?q=1"]


# ── param_key: tên param của target (dedupe asset + class + param) ──


def test_param_key_lấy_param_sorted_gọp_phẩy():
    assert param_key("https://a.com/x?b=1&a=2") == "a,b"
    assert param_key("https://a.com/x") == ""
    assert param_key("a.example.com") == ""


# ── validate_status: lifecycle của Candidate ──


def test_validate_status_chỉ_nhận_4_trạng_thái():
    for s in ("new", "verifying", "verified", "rejected"):
        assert validate_status(s) == s
    with pytest.raises(ValueError):
        validate_status("hacked")


@pytest.mark.asyncio
async def test_list_candidates_filter_status_severity_sai_báo_lỗi():
    from app.detect import list_candidates

    with pytest.raises(ValueError):
        await list_candidates(FakePool(), status="hacked")
    with pytest.raises(ValueError):
        await list_candidates(FakePool(), severity="khủng khiếp")


# ── write_evidence: file JSON trên volume + path trả về ──


def test_write_evidence_ghi_file_json_đầy_dữ_liệu():
    path = write_evidence(7, 3, FINDING)
    assert path is not None
    content = json.loads(open(path, encoding="utf-8").read())
    assert content["template-id"] == "reflected-xss"
    assert content["info"]["severity"] == "medium"


def test_write_evidence_template_id_có_ký_tự_lạ_vẫn_an_toàn():
    path = write_evidence(7, 1, {**FINDING, "template-id": "http/cves/2021/CVE-2021-1"})
    assert path is not None and "/" not in path.rsplit("/", 1)[1].rsplit("-", 2)[0]


def test_write_evidence_io_lỗi_trả_none_không_chết(monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "evidence_dir", "/proc/không-ghi-được/x")
    assert write_evidence(7, 1, FINDING) is None


# ── filter_scope (dùng chung tools.py): theo host, có audit ──


@pytest.mark.asyncio
async def test_filter_scope_chặn_target_ngoài_scope_có_audit():
    from app.scope_validator import check_target

    ctx = build_context(1, None, None, None, SNAPSHOT, False)
    pool = FakePool()
    allowed, blocked = await filter_scope(
        pool, ctx, ["https://app.other.com/a?x=1", "https://evil.com/b"], "nuclei"
    )
    assert allowed == ["https://app.other.com/a?x=1"]
    assert blocked == 1
    blocked_rows = [p for _, sql, p in pool.executes if "scope_audit_log" in sql]
    assert any(p[2] == "evil.com" for p in blocked_rows)
    # cửa vào cuối cùng vẫn là check_target
    assert not check_target("evil.com", SNAPSHOT).allowed


# ── pipeline với tool giả ──

RUN_ROW = {
    "id": 1,
    "program_name": "Example",
    "rate_limit_rps": None,
    "ident_header_name": "X-Bug-Bounty",
    "ident_header_value": "HackerOne-tuan",
    "scope_snapshot": json.dumps(SNAPSHOT),
    "allow_non_prod": False,
}


def _candidate_rows(pool: FakePool):
    rows = []
    for _, sql, params in pool.executes:
        if "candidates" in sql and "INSERT" in sql.upper():
            rows.extend(params)
    return rows


@pytest.mark.asyncio
async def test_pipeline_tạo_candidate_đúng_class_với_evidence_đầy_đủ():
    runner = FakeRunner({"nuclei": _nuclei_stdout(FINDING)})
    pool = FakePool()
    summary = await run_detection_phase(
        pool, RUN_ROW, tool_runner=runner,
        live_urls=["https://app.other.com/login?q=1"], classed_urls=[],
    )

    assert [t for t, _, _ in runner.calls] == ["nuclei"]
    stdin = runner.calls[0][2]
    assert "https://app.other.com/login?q=1" in stdin

    rows = _candidate_rows(pool)
    assert len(rows) == 1
    row = rows[0]
    # (run_id, target, class, param, template_id, title, severity, matcher_name, status, evidence_path)
    assert row[0] == 1  # run_id
    assert row[1] == "https://app.other.com/login?q=1"  # target
    assert row[2] == "xss"  # class từ template tags
    assert row[3] == "q"  # param
    assert row[4] == "reflected-xss"  # template_id
    assert row[6] == "medium"  # severity
    assert row[7] == "multi-pattern"  # matcher_name
    assert row[8] == "new"  # status
    # evidence file thật + path ghi trong DB
    import os

    assert row[9] and os.path.exists(row[9])
    assert summary == {"candidates": 1, "blocked": 0}


@pytest.mark.asyncio
async def test_pipeline_class_headers_ép_severity_không_vượt_low():
    """#15: security headers chỉ informational — severity mặc định thấp dù
    template report cao hơn."""
    headers_finding = {
        **FINDING,
        "template-id": "missing-security-header",
        "info": {
            "name": "Missing Security Header",
            "severity": "high",
            "tags": ["misconfig", "config"],
        },
    }
    runner = FakeRunner({"nuclei": _nuclei_stdout(headers_finding)})
    pool = FakePool()
    await run_detection_phase(
        pool, RUN_ROW, tool_runner=runner,
        live_urls=["https://app.other.com/login"], classed_urls=[],
    )
    rows = _candidate_rows(pool)
    assert len(rows) == 1
    assert rows[0][2] == "headers"  # class
    assert rows[0][6] == "low"      # severity ép về low


# ── pipeline âm tính ──


    evil = {
        **FINDING,
        "host": "https://evil.com",
        "matched-at": "https://evil.com/x?q=1",
    }
    runner = FakeRunner({"nuclei": _nuclei_stdout(evil)})
    pool = FakePool()
    summary = await run_detection_phase(
        pool, RUN_ROW, tool_runner=runner,
        live_urls=["https://app.other.com/login"], classed_urls=[],
    )
    assert summary["candidates"] == 0
    assert summary["blocked"] >= 1
    assert _candidate_rows(pool) == []
    blocked = [p for _, sql, p in pool.executes if "scope_audit_log" in sql]
    assert any(p[2] == "evil.com" for p in blocked)


@pytest.mark.asyncio
async def test_pipeline_dedupe_cùng_asset_class_param_chỉ_1_row():
    f2 = {
        **FINDING,
        "template-id": "another-xss-template",
        "info": {**FINDING["info"], "name": "Another XSS"},
    }
    runner = FakeRunner({"nuclei": _nuclei_stdout(FINDING, f2)})
    pool = FakePool()
    summary = await run_detection_phase(
        pool, RUN_ROW, tool_runner=runner,
        live_urls=["https://app.other.com/login?q=1"], classed_urls=[],
    )
    rows = _candidate_rows(pool)
    assert len(rows) == 1
    assert rows[0][4] == "reflected-xss"  # finding đầu tiên giữ nguyên
    assert summary["candidates"] == 1


@pytest.mark.asyncio
async def test_pipeline_không_target_thì_không_chạy_nuclei():
    runner = FakeRunner({"nuclei": ""})
    pool = FakePool()
    summary = await run_detection_phase(
        pool, RUN_ROW, tool_runner=runner, live_urls=[], classed_urls=[]
    )
    assert summary == {"candidates": 0, "blocked": 0}
    assert runner.calls == []


@pytest.mark.asyncio
async def test_pipeline_nuclei_lỗi_không_tạo_candidate():
    from app.tools import ToolResult

    class FailingNuclei(FakeRunner):
        async def __call__(self, tool, args, stdin=None, docker_args=None):
            result = await super().__call__(tool, args, stdin, docker_args)
            if tool == "nuclei":
                return ToolResult(1, "", "nuclei chết")
            return result

    runner = FailingNuclei({"nuclei": _nuclei_stdout(FINDING)})
    pool = FakePool()
    summary = await run_detection_phase(
        pool, RUN_ROW, tool_runner=runner,
        live_urls=["https://app.other.com/login"], classed_urls=[],
    )
    assert summary == {"candidates": 0, "blocked": 0}
    assert _candidate_rows(pool) == []
