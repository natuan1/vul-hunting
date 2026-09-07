"""Test Recon Phase 2 (ticket #9) — katana crawl + gau/waymore URL lịch sử +
gf slicing thành bảng URLs + params gắn nhãn class.

Các seam thuần được test: chuẩn hoá URL, trích param, parser output tool,
args builder; pipeline test với tool giả (âm tính: URL ngoài Scope bị chặn
tại validator, không bao giờ lên DB hay vào stdin của gf-slice).

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests -q
"""

import json

import pytest

from app.recon import (
    GF_SLICE_TOOL,
    archive_docker_args,
    build_archive_args,
    build_katana_args,
    normalize_url,
    parse_gf_slice_json,
    parse_url_lines,
    run_recon_phase,
    run_url_phase,
    url_param_names,
)
from app.tools import ToolContext, ToolResult, build_context
from fakes import FakePool, FakeRunner
from app.scope_validator import check_target

SNAPSHOT = [
    {"asset_identifier": "*.example.com", "asset_type": "WILDCARD"},
    {"asset_identifier": "app.other.com", "asset_type": "URL"},
]


@pytest.fixture(autouse=True)
def _isolated_artifacts(tmp_path, monkeypatch):
    """Pipeline test không được đụng artifact thật của volume/container."""
    from app import config

    monkeypatch.setattr(config.settings, "artifacts_dir", str(tmp_path / "artifacts"))


# ── normalize_url: chìa khoá dedupe crawled ↔ lịch sử ──


def test_normalize_url_chuẩn_hoá_scheme_host_và_bỏ_fragment():
    assert normalize_url("HTTPS://A.Example.COM/Path/X#frag") == "https://a.example.com/Path/X"


def test_normalize_url_bỏ_port_mặc_định_giữ_port_lạ():
    assert normalize_url("http://a.com:80/x") == "http://a.com/x"
    assert normalize_url("https://a.com:443") == "https://a.com/"
    assert normalize_url("http://a.com:8080/x?y=1") == "http://a.com:8080/x?y=1"


def test_normalize_url_path_rỗng_thành_gạch():
    assert normalize_url("https://a.com") == "https://a.com/"
    assert normalize_url("https://a.com?x=1") == "https://a.com/?x=1"


def test_normalize_url_bỏ_dòng_rác_và_scheme_lạ():
    assert normalize_url("notaurl") is None
    assert normalize_url("ftp://a.com/x") is None
    assert normalize_url("") is None
    assert normalize_url("//a.com/x") is None


def test_normalize_url_sắp_xếp_query_để_dedupe_đúng():
    """Cùng 1 bộ param, thứ tự khác nhau (hay gặp giữa crawled và lịch sử)
    phải ra CÙNG một URL chuẩn hoá."""
    assert normalize_url("https://a.com/?b=2&a=1") == normalize_url("https://a.com/?a=1&b=2")
    assert normalize_url("https://a.com/?b=2&a=1") == "https://a.com/?a=1&b=2"


# ── url_param_names: params cho bảng URLs + params ──


def test_url_param_names_trả_danh_sách_unique_sorted():
    assert url_param_names("https://a.com/p?b=2&a=1&a=3") == ["a", "b"]


def test_url_param_names_param_không_giá_trị_và_không_query():
    assert url_param_names("https://a.com/p?x&y=") == ["x", "y"]
    assert url_param_names("https://a.com/p") == []


def test_url_param_names_bỏ_qua_fragment():
    assert url_param_names("https://a.com/?q=1#frag?fake=2") == ["q"]


# ── parse_url_lines: output thẳng của katana/gau/waymore ──


def test_parse_url_lines_chỉ_lấy_dòng_url_giữ_thứ_tự():
    out = "https://a.com/x\ndòng rác\nhttp://b.com:8080/y?z=1\n\nhttps://a.com/x\n"
    assert parse_url_lines(out) == ["https://a.com/x", "http://b.com:8080/y?z=1"]


def test_parse_url_lines_stdin_rỗng():
    assert parse_url_lines("") == []


# ── parse_gf_slice_json: output JSONL của gf-slice ──


def test_parse_gf_slice_json_map_url_với_classes():
    out = "\n".join(
        [
            json.dumps({"url": "https://a.com/?q=1", "classes": ["xss", "redirect"]}),
            json.dumps({"url": "https://b.com/", "classes": []}),
            "rác không phải json",
        ]
    )
    assert parse_gf_slice_json(out) == {
        "https://a.com/?q=1": ["xss", "redirect"],
        "https://b.com/": [],
    }


def test_parse_gf_slice_json_rỗng():
    assert parse_gf_slice_json("") == {}


# ── args builder ──


def test_build_katana_args_có_rate_limit_và_header_định_danh():
    args = build_katana_args(2.6, {"X-Bug-Bounty": "HackerOne-tuan"})
    assert args[:4] == ["-silent", "-no-color", "-d", "3"]
    assert "-rate-limit" in args and "3" in args  # 2.6 → 3 (int, như httpx -rl)
    assert "-concurrency" in args and "3" in args
    flat = " ".join(args)
    assert "-H X-Bug-Bounty: HackerOne-tuan" in flat


def test_build_katana_args_không_rate_limit_thì_không_flag():
    args = build_katana_args(None, {})
    assert "-rate-limit" not in args and "-concurrency" not in args


def test_build_katana_args_rate_limit_bằng_0_cũng_không_flag():
    assert "-rate-limit" not in build_katana_args(0, {})


def test_build_archive_args_gau_và_waymore():
    assert build_archive_args("gau", "example.com") == ["--subs", "example.com"]
    assert build_archive_args("waymore", "example.com") == [
        "-i", "example.com", "-mode", "U", "--stream",
    ]
    with pytest.raises(ValueError):
        build_archive_args("katana", "example.com")


def test_archive_docker_args_otx_key_khi_có(monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "otx_api_key", "secret-key")
    assert archive_docker_args() == ["-e", "OTX_API_KEY=secret-key"]

    monkeypatch.setattr(config.settings, "otx_api_key", "")
    assert archive_docker_args() is None


# ── run_url_phase với tool giả (doubles dùng chung ở fakes.py) ──


class FailingKatanaRunner(FakeRunner):
    """Katana luôn exit != 0 (tool lỗi — không phát hiện gì từ tool này)."""

    async def __call__(self, tool, args, stdin=None, docker_args=None):
        result = await super().__call__(tool, args, stdin, docker_args)
        if tool == "katana":
            return ToolResult(1, result.stdout, "katana chết")
        return result


def _audit_rows(pool: FakePool):
    return [p for _, sql, p in pool.executes if "scope_audit_log" in sql]


def _url_rows(pool: FakePool):
    """Tất cả row INSERT vào recon_urls (executemany)."""
    rows = []
    for _, sql, params in pool.executes:
        if "recon_urls" in sql and "INSERT" in sql.upper():
            rows.extend(params)
    return rows


def _gf_stdin(runner: FakeRunner) -> str:
    return "\n".join(stdin or "" for tool, _, stdin in runner.calls if tool == GF_SLICE_TOOL)


def _ctx(run_id: int = 1) -> ToolContext:
    return build_context(run_id, None, "X-Bug-Bounty", "HackerOne-tuan", SNAPSHOT, False)


LIVE_RECORD = {
    "host": "app.other.com",
    "url": "https://app.other.com/login?id=1",
    "status_code": 200,
    "title": "Login",
}


@pytest.mark.asyncio
async def test_run_url_phase_dedupe_crawled_với_lich_sử_gộp_sources():
    """Cùng 1 URL (khác fragment/hoa-thường) từ katana seed và gau → ĐÚNG 1 row,
    sources gộp cả hai — tiêu chí dedupe của ticket."""
    runner = FakeRunner(
        {
            "katana": "https://app.other.com/login?id=1&next=/admin\n",
            "gau": "https://APP.other.com/login?id=1#top\n",
            "waymore": "",
        }
    )
    pool = FakePool()
    summary = await run_url_phase(
        pool, _ctx(), None, [LIVE_RECORD], ["app.other.com"], tool_runner=runner
    )

    rows = _url_rows(pool)
    same = [r for r in rows if r[1] == "https://app.other.com/login?id=1"]
    assert len(same) == 1
    assert set(same[0][4]) == {"katana", "gau"}
    # URL crawl riêng của katana vẫn là row riêng
    assert any(r[1] == "https://app.other.com/login?id=1&next=/admin" for r in rows)
    assert summary["urls"] == 2


@pytest.mark.asyncio
async def test_run_url_phase_params_và_classes_vào_db():
    runner = FakeRunner(
        {
            "katana": "https://app.other.com/login?id=1&next=/admin\n",
            "gau": "",
            "waymore": "",
        }
    )
    pool = FakePool()
    await run_url_phase(pool, _ctx(), None, [LIVE_RECORD], ["app.other.com"], tool_runner=runner)

    # gf-slice nhận đúng URL đã chuẩn hoá (dedupe) qua stdin
    assert "https://app.other.com/login?id=1&next=/admin" in _gf_stdin(runner)

    rows = _url_rows(pool)
    by_url = {r[1]: r for r in rows}
    row = by_url["https://app.other.com/login?id=1&next=/admin"]
    assert row[2] == "app.other.com"
    assert row[3] == ["id", "next"]  # params

    row_seed = by_url["https://app.other.com/login?id=1"]
    assert row_seed[3] == ["id"]
    assert row_seed[5] == []  # gf-slice không trả gì → không class


@pytest.mark.asyncio
async def test_run_url_phase_gf_slice_gắn_classes_từ_stdout():
    """gf-slice trả JSONL {url, classes} → classes đúng row, row không match thì rỗng."""
    runner = FakeRunner(
        {
            "katana": "https://app.other.com/l?x=1\n",
            "gau": "",
            "waymore": "",
            GF_SLICE_TOOL: json.dumps(
                {"url": "https://app.other.com/l?x=1", "classes": ["xss"]}
            ),
        }
    )
    pool = FakePool()
    summary = await run_url_phase(pool, _ctx(), None, [LIVE_RECORD], ["app.other.com"], tool_runner=runner)
    rows = _url_rows(pool)
    assert rows[0][5] == ["xss"]
    assert summary["urls_classed"] == 1


@pytest.mark.asyncio
async def test_run_url_phase_âm_tính_url_ngoài_scope_không_lên_db():
    """gau 'trả về' URL ngoài Scope — phải bị chặn tại validator: không lên DB,
    không vào stdin gf-slice, có audit log."""
    runner = FakeRunner(
        {
            "katana": "https://app.other.com/ok?a=1\nhttps://evil-outside.com/a?b=1\n",
            "gau": "https://example.com.evil.io/x?c=2\n",
            "waymore": "",
        }
    )
    pool = FakePool()
    summary = await run_url_phase(pool, _ctx(), None, [LIVE_RECORD], ["app.other.com"], tool_runner=runner)

    assert summary["urls"] == 2  # seed live host + 1 URL crawl trong Scope
    assert summary["blocked"] == 2
    rows = _url_rows(pool)
    assert {r[1] for r in rows} == {
        "https://app.other.com/login?id=1",
        "https://app.other.com/ok?a=1",
    }
    gf_in = _gf_stdin(runner)
    assert "evil" not in gf_in

    blocked = [p for p in _audit_rows(pool) if "blocked" in p[3]]
    assert {p[2] for p in blocked} >= {"evil-outside.com", "example.com.evil.io"}


@pytest.mark.asyncio
async def test_run_url_phase_rate_limit_vào_args_katana():
    runner = FakeRunner({"katana": "", "gau": "", "waymore": ""})
    pool = FakePool()
    await run_url_phase(pool, _ctx(), 2.6, [LIVE_RECORD], ["app.other.com"], tool_runner=runner)
    katana_args = " ".join(a for tool, args, _ in runner.calls if tool == "katana" for a in args)
    assert "-rate-limit 3" in katana_args
    assert "-concurrency 3" in katana_args


@pytest.mark.asyncio
async def test_run_url_phase_otx_key_truyền_vào_docker_args_waymore(monkeypatch):
    from app import config

    runner = FakeRunner({"katana": "", "gau": "", "waymore": ""})
    monkeypatch.setattr(config.settings, "otx_api_key", "secret")
    pool = FakePool()
    await run_url_phase(pool, _ctx(), None, [LIVE_RECORD], ["app.other.com"], tool_runner=runner)
    waymore_idx = [i for i, (tool, _, _) in enumerate(runner.calls) if tool == "waymore"]
    assert waymore_idx
    for i in waymore_idx:
        assert runner.docker_calls[i] == ["-e", "OTX_API_KEY=secret"]
    # gau không cần key
    gau_idx = [i for i, (tool, _, _) in enumerate(runner.calls) if tool == "gau"]
    for i in gau_idx:
        assert runner.docker_calls[i] is None


@pytest.mark.asyncio
async def test_run_url_phase_không_có_url_nào_thì_không_gọi_gf_slice():
    runner = FakeRunner({"katana": "", "gau": "", "waymore": ""})
    pool = FakePool()
    summary = await run_url_phase(pool, _ctx(), None, [], ["app.other.com"], tool_runner=runner)
    assert summary == {"urls": 0, "urls_classed": 0, "blocked": 0}
    assert all(tool != GF_SLICE_TOOL for tool, _, _ in runner.calls)
    assert _url_rows(pool) == []


@pytest.mark.asyncio
async def test_run_url_phase_katana_lỗi_thì_seed_không_gán_nguồn_katana():
    """Provenance: katana exit != 0 → coi như tool không phát hiện gì, seed
    (của httpx) không được ghi vào recon_urls với nguồn katana."""
    runner = FailingKatanaRunner({"katana": "https://app.other.com/x?a=1\n", "gau": "", "waymore": ""})
    pool = FakePool()
    summary = await run_url_phase(pool, _ctx(), None, [LIVE_RECORD], ["app.other.com"], tool_runner=runner)
    assert summary["urls"] == 0
    assert _url_rows(pool) == []
    assert any(tool == "gau" for tool, _, _ in runner.calls)  # bước sau vẫn chạy


@pytest.mark.asyncio
async def test_run_url_phase_seed_live_host_là_nguồn_katana():
    """Seed (live host từ httpx) được đưa vào stdin katana và lưu DB source=katana."""
    runner = FakeRunner({"katana": "", "gau": "", "waymore": ""})
    pool = FakePool()
    summary = await run_url_phase(pool, _ctx(), None, [LIVE_RECORD], ["app.other.com"], tool_runner=runner)
    katana_stdin = next(stdin for tool, _, stdin in runner.calls if tool == "katana")
    assert "https://app.other.com/login?id=1" in katana_stdin
    rows = _url_rows(pool)
    assert rows[0][1] == "https://app.other.com/login?id=1"
    assert set(rows[0][4]) == {"katana"}


# ── tích hợp qua run_recon_phase: chuỗi tool đầy đủ ──

RUN_ROW = {
    "id": 1,
    "program_name": "Example",
    "rate_limit_rps": None,
    "ident_header_name": "X-Bug-Bounty",
    "ident_header_value": "HackerOne-tuan",
    "scope_snapshot": json.dumps(SNAPSHOT),
    "allow_non_prod": False,
}


@pytest.mark.asyncio
async def test_pipeline_chuỗi_đầy_dựa_trên_live_host():
    """httpx có live host → katana crawl seed, gau + waymore chạy TỪNG domain gốc,
    gf-slice chốt hạ — đúng thứ tự."""
    runner = FakeRunner(
        {
            "subfinder": "",
            "amass": "",
            "dnsx": "",
            "naabu": "",
            "httpx": json.dumps(LIVE_RECORD),
            "katana": "",
            "gau": "",
            "waymore": "",
        }
    )
    pool = FakePool()
    summary = await run_recon_phase(pool, RUN_ROW, tool_runner=runner)
    assert [t for t, _, _ in runner.calls] == [
        "subfinder", "subfinder", "amass", "amass",
        "dnsx", "naabu", "httpx",
        "katana", "gau", "gau", "waymore", "waymore",
        GF_SLICE_TOOL,
    ]
    assert summary["urls"] == 1  # seed live host


@pytest.mark.asyncio
async def test_pipeline_không_live_host_thì_không_crawl_nhưng_vẫn_lich_sử():
    """Không live host → bỏ katana + gf-slice (không có URL), gau/waymore vẫn chạy."""
    runner = FakeRunner({"subfinder": "", "amass": "", "dnsx": "", "naabu": "", "httpx": ""})
    pool = FakePool()
    summary = await run_recon_phase(pool, RUN_ROW, tool_runner=runner)
    assert [t for t, _, _ in runner.calls] == [
        "subfinder", "subfinder", "amass", "amass",
        "dnsx", "naabu", "httpx",
        "gau", "gau", "waymore", "waymore",
    ]
    assert summary["urls"] == 0
    assert summary["live_hosts"] == 0
