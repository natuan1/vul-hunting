"""Test Recon Phase 1 (ticket #8) — các seam thuần: parser, root domain,
lọc qua Scope Validator, và pipeline với tool giả (âm tính: target ngoài
scope bị chặn tại validator, không có request nào đi ra).

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests -q
"""

import json

import pytest

from app.recon import (
    _discovery_args,
    _harvest_amass_files,
    build_httpx_targets,
    parse_dnsx_json,
    parse_host_lines,
    parse_httpx_json,
    parse_naabu_json,
    recon_roots,
    run_recon_phase,
    unique_hosts,
)
from app.scope_validator import check_target
from app.tools import TargetBlockedError, ToolResult

SNAPSHOT = [
    {"asset_identifier": "*.example.com", "asset_type": "WILDCARD"},
    {"asset_identifier": "app.other.com", "asset_type": "URL"},
    {"asset_identifier": "com.example.app", "asset_type": "GOOGLE_PLAY_APP"},
]


@pytest.fixture(autouse=True)
def _isolated_artifacts(tmp_path, monkeypatch):
    """Pipeline test không được đụng artifact thật của volume/container."""
    from app import config

    monkeypatch.setattr(
        config.settings, "artifacts_dir", str(tmp_path / "artifacts")
    )


# ── recon_roots: domain gốc để enumerate ──


def test_recon_roots_lấy_base_wildcard_và_host_url():
    assert recon_roots(SNAPSHOT) == ["example.com", "app.other.com"]


def test_recon_roots_không_có_host_asset_trả_rỗng():
    assert recon_roots([{"asset_identifier": "x.y", "asset_type": "OTHER"}]) == []


# ── parser ──


def test_parse_host_lines_dạng_thẳng_và_json():
    out = "a.example.com\nb.example.com\n"
    assert parse_host_lines(out) == ["a.example.com", "b.example.com"]


def test_parse_host_lines_bỏ_dòng_rỗng_và_json_không_host():
    out = "\n{\"message\":\"no hosts\"}\n  \n"
    assert parse_host_lines(out) == []


def test_parse_host_lines_bỏ_dòng_không_phải_hostname():
    """amass v5 in preamble 'Session Scope / FQDN:' trước kết quả — những dòng
    có khoảng trắng/ký tự lạ không phải hostname, không được thành target."""
    out = "Session Scope\n\nFQDN:\n\nwiki.example.com\nrubyonrails.org\n"
    assert parse_host_lines(out) == ["wiki.example.com", "rubyonrails.org"]


def test_unique_hosts_giữ_thứ_tự_chuẩn_hoá_và_bỏ_trùng():
    hosts = unique_hosts(["A.Example.com", "a.example.com", "", "b.example.com."])
    assert hosts == ["a.example.com", "b.example.com"]


def test_parse_dnsx_json_lấy_a_và_cname():
    out = "\n".join(
        [
            json.dumps({"host": "old.example.com", "a": ["1.2.3.4"], "cname": ["old.github.io"]}),
            json.dumps({"host": "new.example.com", "a": ["1.2.3.5", "1.2.3.6"]}),
            "rác không phải json",
        ]
    )
    recs = parse_dnsx_json(out)
    assert recs["old.example.com"] == {"a": ["1.2.3.4"], "cname": "old.github.io"}
    assert recs["new.example.com"] == {"a": ["1.2.3.5", "1.2.3.6"], "cname": None}


def test_parse_dnsx_json_chuỗi_cname_được_giữ_nguyên():
    out = json.dumps({"host": "x.example.com", "cname": ["a.old.io", "b.fallback.com"]})
    recs = parse_dnsx_json(out)
    assert recs["x.example.com"]["cname"] == "a.old.io,b.fallback.com"


def test_parse_naabu_json_gom_cổng_theo_host():
    out = "\n".join(
        [
            json.dumps({"host": "a.example.com", "ip": "1.1.1.1", "port": 443}),
            json.dumps({"host": "a.example.com", "ip": "1.1.1.1", "port": 80}),
            json.dumps({"host": "b.example.com", "ip": "1.1.1.2", "port": 8080}),
        ]
    )
    ports = parse_naabu_json(out)
    assert ports == {"a.example.com": [80, 443], "b.example.com": [8080]}


def test_parse_httpx_json_lấy_url_status_title():
    out = json.dumps(
        {
            "url": "https://a.example.com",
            "host": "a.example.com",
            "status_code": 200,
            "title": "Example App",
        }
    )
    recs = parse_httpx_json(out)
    assert recs == [
        {"host": "a.example.com", "url": "https://a.example.com", "status_code": 200,
         "title": "Example App"}
    ]


def test_build_httpx_targets_cổng_mở_thành_host_port_không_có_cổng_thì_host_trần():
    ports = {"a.example.com": [80, 443], "b.example.com": []}
    targets = build_httpx_targets(["a.example.com", "b.example.com"], ports)
    assert targets == ["a.example.com:80", "a.example.com:443", "b.example.com"]


# ── pipeline với tool giả ──


class FakeRunner:
    """Tool runner giả: map (tool, args) → (exit_code, stdout, stderr), ghi lại
    mọi lần gọi để test âm tính kiểm tra request không lọt ra ngoài."""

    def __init__(self, outputs: dict[str, str]):
        self.outputs = outputs  # tool → stdout
        self.calls: list[tuple[str, list[str], str | None]] = []

    async def __call__(
        self, tool: str, args: list[str], stdin: str | None = None,
        docker_args: list[str] | None = None,
    ):
        self.calls.append((tool, args, stdin))
        self.docker_calls = getattr(self, "docker_calls", [])
        self.docker_calls.append(docker_args)
        return ToolResult(0, self.outputs.get(tool, ""), "")


class FakeConn:
    def __init__(self, parent):
        self.parent = parent

    async def execute(self, sql, *params):
        self.parent.executes.append((sql.strip().split()[0].lower(), sql, params))

    async def fetchval(self, sql, *params):
        self.parent.executes.append(("fetchval", sql, params))
        return next(self.parent.ids)  # id tool_executions tăng dần

    async def fetchrow(self, sql, *params):
        self.parent.executes.append(("fetchrow", sql, params))
        return {"count": 0}

    async def fetch(self, sql, *params):
        return []


class FakePool:
    def __init__(self):
        self.executes = []
        self.ids = iter(range(1, 10_000))

    def acquire(self):
        return self

    async def __aenter__(self):
        return FakeConn(self)

    async def __aexit__(self, *exc):
        return False


def _audit_rows(pool: FakePool):
    return [p for _, sql, p in pool.executes if "scope_audit_log" in sql]


def _recon_upserts(pool: FakePool):
    return [(sql, p) for _, sql, p in pool.executes if "recon_assets" in sql]


def _downstream_stdins(runner: FakeRunner) -> str:
    """Mọi thứ mà dnsx/naabu/httpx nhận qua stdin — tức mọi thứ có thể tạo
    request ra ngoài."""
    chunks = [stdin or "" for tool, _, stdin in runner.calls if tool in ("dnsx", "naabu", "httpx")]
    return "\n".join(chunks)


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
async def test_pipeline_chạy_đủ_chuỗi_5_tool_theo_thứ_tự():
    runner = FakeRunner(
        {
            "subfinder": "a.example.com\nb.example.com\n",
            "amass": "b.example.com\nc.example.com\n",
            "dnsx": json.dumps({"host": "a.example.com", "a": ["1.2.3.4"], "cname": ["x.github.io"]}),
            "naabu": json.dumps({"host": "a.example.com", "port": 443}),
            "httpx": json.dumps(
                {"url": "https://a.example.com", "host": "a.example.com",
                 "status_code": 200, "title": "Hi"}
            ),
        }
    )
    pool = FakePool()
    summary = await run_recon_phase(pool, RUN_ROW, tool_runner=runner)

    # subfinder/amass chạy trên TỪNG domain gốc, rồi dnsx → naabu → httpx
    assert [t for t, _, _ in runner.calls] == [
        "subfinder", "subfinder", "amass", "amass", "dnsx", "naabu", "httpx",
    ]
    # 3 subdomain từ discovery + 1 seed là asset URL tường minh (app.other.com)
    assert summary["subdomains"] == 4
    assert summary["live_hosts"] == 1
    # subdomain + live host phải lên DB để UI xem được
    upserts = _recon_upserts(pool)
    assert any("a.example.com" in repr(p) for _, p in upserts)
    # CNAME lưu kèm host — UPDATE recon_assets SET cname
    assert any("cname" in sql for sql, _ in upserts)


@pytest.mark.asyncio
async def test_pipeline_âm_tính_asset_ngoài_scope_bị_chặn_không_request_nào_ra():
    """subfinder 'trả về' 1 host ngoài scope — phải bị chặn tại validator,
    không bao giờ xuất hiện ở stdin của dnsx/naabu/httpx."""
    runner = FakeRunner(
        {
            "subfinder": "a.example.com\nevil-outside.com\nexample.com.evil.io\n",
            "amass": "",
            "dnsx": json.dumps({"host": "a.example.com", "a": ["1.2.3.4"]}),
            "naabu": "",
            "httpx": "",
        }
    )
    pool = FakePool()
    await run_recon_phase(pool, RUN_ROW, tool_runner=runner)

    downstream = _downstream_stdins(runner)
    assert "evil-outside.com" not in downstream
    assert "example.com.evil.io" not in downstream
    assert "a.example.com" in downstream  # in-scope vẫn chạy bình thường

    blocked = [p for p in _audit_rows(pool) if "blocked" in p[3]]
    assert {p[2] for p in blocked} >= {"evil-outside.com", "example.com.evil.io"}
    # host ngoài scope không được lên DB
    assert all("evil" not in repr(p) for _, p in _recon_upserts(pool))


@pytest.mark.asyncio
async def test_pipeline_root_được_validate_trước_khi_discovery_chạy():
    runner = FakeRunner({"subfinder": "", "amass": ""})
    pool = FakePool()
    await run_recon_phase(pool, RUN_ROW, tool_runner=runner)
    audited = [p[2] for p in _audit_rows(pool)]
    assert "example.com" in audited and "app.other.com" in audited


@pytest.mark.asyncio
async def test_pipeline_header_định_danh_vào_args_httpx():
    runner = FakeRunner({"subfinder": "a.example.com\n", "amass": "", "dnsx": "", "naabu": "", "httpx": ""})
    await run_recon_phase(FakePool(), RUN_ROW, tool_runner=runner)
    httpx_args = next(args for tool, args, _ in runner.calls if tool == "httpx")
    flat = " ".join(httpx_args)
    assert "X-Bug-Bounty: HackerOne-tuan" in flat


def test_check_target_vẫn_là_cửa_vào_cuối_cùng():
    assert check_target("a.example.com", SNAPSHOT).allowed
    assert not check_target("evil.com", SNAPSHOT).allowed


@pytest.mark.asyncio
async def test_pipeline_tool_exit_khác_0_không_làm_chết_chuỗi():
    """Tool lỗi (vd subfinder exit 1) → các bước sau vẫn chạy với những gì có."""

    class FlakyRunner(FakeRunner):
        async def __call__(self, tool, args, stdin=None, docker_args=None):
            result = await super().__call__(tool, args, stdin, docker_args)
            if tool == "subfinder":
                return ToolResult(1, "", "api key hết hạn")
            return result

    runner = FlakyRunner(
        {
            "amass": "a.example.com\n",
            "dnsx": json.dumps({"host": "a.example.com", "a": ["1.2.3.4"]}),
            "naabu": "",
            "httpx": "",
        }
    )
    pool = FakePool()
    summary = await run_recon_phase(pool, RUN_ROW, tool_runner=runner)
    # a.example.com từ amass + seed app.other.com = 2 host trong Scope
    assert summary["subdomains"] == 2
    assert [t for t, _, _ in runner.calls] == [
        "subfinder", "subfinder", "amass", "amass", "dnsx", "naabu", "httpx",
    ]


def test_target_blocked_error_tồn_tại_để_tool_nhận_lỗi_tường_minh():
    assert issubclass(TargetBlockedError, Exception)


# ── amass v5: output file qua volume ──


def test_discovery_args_subfinder_không_mount():
    args, docker_args = _discovery_args("subfinder", "example.com", 7)
    assert args == ["-d", "example.com", "-json", "-silent"]
    assert docker_args is None


def test_discovery_args_amass_mount_volume_khi_config(monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "recon_volume", "vul-hunting_recon_data")
    args, docker_args = _discovery_args("amass", "example.com", 7)
    assert "-oA" in args and "/out/amass-7-example.com" in args
    assert docker_args == ["-v", "vul-hunting_recon_data:/out", "-u", "0:0"]

    monkeypatch.setattr(config.settings, "recon_volume", "")
    args, docker_args = _discovery_args("amass", "example.com", 7)
    assert "-oA" not in args and docker_args is None


def test_harvest_amass_files_đọc_cả_json_mà_txt(tmp_path, monkeypatch):
    import json as _json

    from app import config

    base = tmp_path / "artifacts" / "7"
    base.mkdir(parents=True)
    (base / "amass-7-example.com.json").write_text(
        _json.dumps([{"name": "a.example.com"}, {"name": "b.example.com"}]),
        encoding="utf-8",
    )
    (base / "amass-7-example.com.txt").write_text(
        "Session Scope\n\nc.example.com\n", encoding="utf-8"
    )
    monkeypatch.setattr(config.settings, "artifacts_dir", str(tmp_path / "artifacts"))
    hosts = _harvest_amass_files(7, "example.com")
    assert hosts == ["a.example.com", "b.example.com", "c.example.com"]


def test_harvest_amass_files_không_có_file_trả_rỗng(tmp_path, monkeypatch):
    from app import config

    monkeypatch.setattr(config.settings, "artifacts_dir", str(tmp_path))
    assert _harvest_amass_files(99, "example.com") == []


@pytest.mark.asyncio
async def test_pipeline_rate_limit_đi_vào_args_naabu_và_httpx():
    """Rate limit của Run phải áp cho tool có throttle riêng: httpx (-rl,
    request/s) và naabu (-rate, packet/s)."""
    runner = FakeRunner({"subfinder": "a.example.com\n", "amass": "", "dnsx": "", "naabu": "", "httpx": ""})
    run_row = dict(RUN_ROW)
    run_row["rate_limit_rps"] = 2.6
    await run_recon_phase(FakePool(), run_row, tool_runner=runner)
    naabu_args = " ".join(
        a for tool, args, _ in runner.calls if tool == "naabu" for a in args
    )
    httpx_args = " ".join(
        a for tool, args, _ in runner.calls if tool == "httpx" for a in args
    )
    assert "-rate 3" in naabu_args  # -rate là int (2.6 → 3)
    assert "-rl 3" in httpx_args
