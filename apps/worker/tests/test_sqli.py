"""Test batch B — lớp SQLi (sqlmap trong sandbox, ticket #16).

sqlmap CHỈ chạy trong sandbox bridge với profile an toàn mức thấp:
error-based/boolean (--technique=BE), level=1 risk=1, threads=1, delay theo
rate limit của Run — KHÔNG time-based, KHÔNG dump dữ liệu, KHÔNG đọc file hệ
thống ("minimum testing necessary" — PoC chỉ chứng minh injection). Dấu hiệu
dump/đọc file trong output → guardrails HALT Run + cảnh báo, không tiếp tục.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_sqli.py -q
"""

import json

import pytest

from app import config, guardrails
from app.sqli import (
    SQLI_VERIFY_CLASSES,
    build_sqlmap_args,
    build_sqlmap_script,
    delay_for_run,
    format_delay,
    is_usage_error,
    parse_sqlmap_emission,
    parse_sqlmap_result,
    run_sqli_verification,
    scan_violations,
)
from app.verify import PROBE_MARKER
from test_oob_pipeline import FakeProbe, OOBFakePool as ScriptPool

SNAPSHOT = [{"asset_identifier": "app.other.com", "asset_type": "URL"}]

# sqlmap log mô phỏng — boolean + error-based đúng profile, có injection point
VULN_LOG = """[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
sqlmap identified the following injection point(s) with a total of 17 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=3 AND 3456=3456
---
Parameter: id (GET)
    Type: error-based
    Payload: id=3 AND (SELECT 3456 FROM(SELECT COUNT(*),CONCAT(0x71,5.5))x)
---
[INFO] the back-end DBMS is MySQL >= 5.0
"""

NEG_LOG = (
    "[INFO] testing 'AND boolean-based blind'...\n"
    "[WARNING] all tested parameters do not appear to be injectable\n"
)

# log có DẤU HIỆU dump — stop-condition phải halt, không tiếp tục
DUMP_LOG = (
    VULN_LOG
    + "[INFO] fetching entries for table 'users'\n"
    + '[INFO] retrieved: "admin"\n'
)


def _verdict_updates(pool):
    return [
        p
        for _, sql, p in pool.executes
        if "UPDATE candidates SET status" in sql and "verify_evidence_path = $6" in sql
    ]


def _lifecycle_updates(pool):
    return [
        p
        for _, sql, p in pool.executes
        if "UPDATE candidates SET status = $2" in sql
    ]


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))
    monkeypatch.setattr(config.settings, "artifacts_dir", str(tmp_path / "artifacts"))
    monkeypatch.setattr(config.settings, "verify_confidence_threshold", 0.85)


# ─────────────────────────── pure seams ───────────────────────────


def test_build_sqlmap_args_profile_an_toàn_không_cờ_phá_hoại():
    """AC #16: profile an toàn ghi rõ — error-based/boolean, level/risk thấp,
    1 thread, KHÔNG cờ dump/đọc file/os-shell."""
    args = build_sqlmap_args("https://app.other.com/item?id=3", "id", 2.0)
    text = " ".join(args)
    for banned in (
        "--dump", "--dump-all", "--common-tables", "--common-columns",
        "--file-read", "--file-write", "--file-dest",
        "--os-shell", "--os-pwn", "--os-cmd", "--sql-shell",
        "--reg-read", "--technique=T", "--technique=Q", "--threads=4",
        "--risk=3", "--level=5",
    ):
        assert banned not in text, f"cờ phá hoại xuất hiện: {banned}"
    assert "--technique=BE" in args          # boolean + error-based duy nhất
    assert "--level=1" in args and "--risk=1" in args
    assert "--threads=1" in args             # không dồn dập
    assert "--batch" in args                 # không tương tác
    assert "--flush-session" in args         # session sạch mỗi lần chạy
    assert args[args.index("-u") + 1] == "https://app.other.com/item?id=3"
    assert args[args.index("-p") + 1] == "id"
    assert f"--delay={format_delay(2.0)}" in args


def test_delay_for_run_rate_limit_nghiêm_ngặt():
    """AC #16: sqlmap tôn trọng rate limit của Run — sàn 1 req/s, Run chậm hơn
    thì delay đúng nghịch đảo rps."""
    assert delay_for_run(None) == 1.0    # không cấu hình → sàn
    assert delay_for_run(0) == 1.0
    assert delay_for_run(1.0) == 1.0
    assert delay_for_run(0.5) == 2.0     # 0.5 req/s → 1 request mỗi 2s
    assert delay_for_run(4.0) == 1.0     # nhanh hơn sàn vẫn bị kẹp tại 1s
    assert format_delay(2.0) == "2"
    assert format_delay(0.5) == "0.5"


def test_scan_violations_bắt_dump_đọc_file_kỹ_thuật_ngoài_profile():
    """AC #16: stop-condition — dấu hiệu dump/đọc file/kỹ thuật ngoài BE phải
    bị phát hiện để guardrails halt."""
    assert scan_violations("--dump --os-shell") == ["--dump", "--os-shell"]
    assert "fetching entries" in scan_violations(
        "[INFO] fetching entries for table 'users'"
    )
    assert "--file-read" in scan_violations("sqlmap -u x --file-read=/etc/passwd")
    assert "Type: time-based blind" in scan_violations("Type: time-based blind")
    assert "Type: UNION query" in scan_violations("Type: UNION query")
    # log SẠCH (boolean + error-based) không bị báo oan
    assert scan_violations(VULN_LOG) == []
    assert scan_violations("") == []


def test_usage_error_không_coisan_dump():
    """Usage/help của sqlmap chứa '--dump'… trong văn bản trợ giúp — không được
    coi là dấu hiệu dump thật (tránh HALT oan Run khi sqlmap lỗi option)."""
    usage = "Usage: sqlmap [options]\n       --dump    Dump DBMS database\n"
    assert scan_violations(usage) != []          # pattern vẫn khớp văn bản…
    assert is_usage_error(usage) is True         # …nhưng nhận diện là usage
    assert is_usage_error(VULN_LOG) is False
    assert is_usage_error(DUMP_LOG) is False


def test_parse_sqlmap_result_nhận_injection_point_và_negative():
    r = parse_sqlmap_result(VULN_LOG)
    assert r["vulnerable"] is True
    assert r["not_injectable"] is False
    assert r["parameters"] == ["id"]
    assert r["types"] == ["boolean-based blind", "error-based"]
    assert len(r["payloads"]) == 2
    assert r["dbms"].startswith("MySQL")

    neg = parse_sqlmap_result(NEG_LOG)
    assert neg["vulnerable"] is False
    assert neg["not_injectable"] is True

    assert parse_sqlmap_result("")["vulnerable"] is False
    assert parse_sqlmap_result("noise only")["not_injectable"] is False


def test_parse_sqlmap_emission_đọc_marker_json():
    payload = {
        "url": "https://app.other.com/item?id=3",
        "param": "id",
        "delay_s": "1",
        "exit_code": 0,
        "sqlmap_log": VULN_LOG,
    }
    stdout = f"{PROBE_MARKER}\n{json.dumps(payload)}\n"
    assert parse_sqlmap_emission(stdout) == payload
    assert parse_sqlmap_emission("no marker") is None
    assert parse_sqlmap_emission(f"{PROBE_MARKER}\nbroke{{") is None


def test_build_sqlmap_script_chứa_profile_và_không_cờ_phá_hoại():
    """AC #16: profile an toàn nằm ngay trong script sandbox (skill cũng ghi
    rõ); KHÔNG có cờ dump/đọc file dù chỉ 1 ký tự."""
    script = build_sqlmap_script("https://app.other.com/item?id=3", "id", 1.0)
    assert "sqlmap" in script
    assert "--technique=BE" in script and "--level=1" in script and "--risk=1" in script
    assert "--threads=1" in script and "--delay=1" in script
    for banned in ("--dump", "--file-read", "--file-write", "--os-shell",
                   "--sql-shell", "--reg-read", "--os-pwn"):
        assert banned not in script
    assert "https://app.other.com/item?id=3" in script
    assert " id" in script.replace("-p 'id'", "-p 'id'")  # param có trong cmd
    assert PROBE_MARKER in script


# ─────────────────────────── verify pipeline ───────────────────────────


def _candidate(**over):
    base = {
        "id": 21,
        "run_id": 1,
        "target": "https://app.other.com/item?id=3",
        "class": "sqli",
        "param": "id",
        "template_id": "nuclei/sqli-error",
        "title": "SQL Injection",
        "severity": "high",
        "matcher_name": "",
        "status": "new",
        "evidence_path": None,
        "first_seen": "2026-01-01T00:00:00Z",
    }
    base.update(over)
    return base


def _baseline_stdout(status=200):
    profile = {
        "url": "https://app.other.com/item?id=3",
        "status": status,
        "headers": {},
        "content_type": "text/html",
        "body_length": 100,
        "body": "ok",
    }
    return f"{PROBE_MARKER}\n{json.dumps(profile)}\n"


def _sqlmap_stdout(log):
    payload = {
        "url": "https://app.other.com/item?id=3",
        "param": "id",
        "delay_s": 1,
        "exit_code": 0,
        "sqlmap_log": log,
    }
    return f"{PROBE_MARKER}\n{json.dumps(payload)}\n"


@pytest.mark.asyncio
async def test_verify_sqli_vulnerable_verified_không_dump():
    """AC #16: sqlmap chứng minh injection (error/boolean) → Finding; PoC là
    payload injection, KHÔNG dump dữ liệu; profile an toàn ghi trong evidence."""
    probe = FakeProbe([_baseline_stdout(), _sqlmap_stdout(VULN_LOG)])
    pool = ScriptPool()
    summary = await run_sqli_verification(
        pool, _candidate(), probe=probe, delay_s=1.0,
    )

    assert summary["verdict"] == "verified"
    assert summary["score"] >= 0.85
    assert "sqlmap_injectable" in summary["signals"]
    assert len(probe.calls) == 2  # baseline + sqlmap session
    script = probe.calls[1][0]
    assert "sqlmap" in script
    # profile an toàn trong script — không cờ phá hoại nào
    assert "--technique=BE" in script
    assert "--dump" not in script and "--file-read" not in script

    verdicts = _verdict_updates(pool)
    assert verdicts and verdicts[-1][1] == "verified"
    evidence = json.loads(open(verdicts[-1][5], encoding="utf-8").read())
    assert evidence["schema"] == "vulhunt.sqli-evidence/1"
    assert evidence["safety"]["technique"] == "BE"
    assert evidence["safety"]["level"] == 1 and evidence["safety"]["risk"] == 1
    assert evidence["sqlmap"]["vulnerable"] is True
    assert evidence["violations"] == []  # stop-condition sạch
    assert "boolean-based blind" in evidence["sqlmap"]["types"]


@pytest.mark.asyncio
async def test_verify_sqli_dấu_hiệu_dump_guardrails_halt_không_tiếp_tục():
    """AC #16: sqlmap có dấu hiệu dump → guardrails HALT + cảnh báo, KHÔNG
    tiếp tục — không verdict, lifecycle trả về cũ, Run dừng chờ người dùng."""
    probe = FakeProbe([_baseline_stdout(), _sqlmap_stdout(DUMP_LOG)])
    pool = ScriptPool()
    with pytest.raises(guardrails.RunHalted):
        await run_sqli_verification(pool, _candidate(), probe=probe, delay_s=1.0)

    # lifecycle trả về cũ (không kẹt verifying), không có verdict nào
    updates = _lifecycle_updates(pool)
    assert updates and updates[-1][1] == "new"
    verdicts = _verdict_updates(pool)
    assert all(p[1] in ("new", "verifying") for p in verdicts)  # KHÔNG verdict
    assert not any(p[1] in ("verified", "rejected") for p in verdicts)
    # halt_run đã được gọi
    assert [1 for _, sql, _ in pool.executes if "status = 'halted'" in sql]


@pytest.mark.asyncio
async def test_verify_sqli_dấu_hiệu_đọc_file_cũng_bị_halt():
    probe = FakeProbe([
        _baseline_stdout(),
        _sqlmap_stdout(VULN_LOG + "[INFO] reading file contents\n"),
    ])
    pool = ScriptPool()
    with pytest.raises(guardrails.RunHalted):
        await run_sqli_verification(pool, _candidate(), probe=probe, delay_s=1.0)
    assert _lifecycle_updates(pool)[-1][1] == "new"


@pytest.mark.asyncio
async def test_verify_sqli_usage_error_không_halt_oan_chỉ_rejected():
    """sqlmap lỗi option → in usage/help (chứa '--dump' trong văn bản trợ giúp)
    — KHÔNG HALT oan Run: chỉ rejected với pattern sqlmap_error."""
    usage = "Usage: sqlmap [options]\n       --dump    Dump DBMS database\nsqlmap: error: unrecognized option\n"
    probe = FakeProbe([_baseline_stdout(), _sqlmap_stdout(usage)])
    pool = ScriptPool()
    summary = await run_sqli_verification(pool, _candidate(), probe=probe, delay_s=1.0)
    assert summary["verdict"] == "rejected"
    assert "sqlmap_error" in summary["patterns"]
    # KHÔNG có halt nào được gọi
    assert not [1 for _, sql, _ in pool.executes if "status = 'halted'" in sql]
    verdicts = _verdict_updates(pool)
    assert verdicts[-1][1] == "rejected"


@pytest.mark.asyncio
async def test_verify_sqli_waf_ở_baseline_không_chạy_sqlmap():
    """Rate limit nghiêm ngặt: baseline bị chặn → dừng TRƯỚC sqlmap, không
    lãng phí thêm request (minimum testing necessary)."""
    probe = FakeProbe([_baseline_stdout(status=403)])
    pool = ScriptPool()
    summary = await run_sqli_verification(pool, _candidate(), probe=probe, delay_s=1.0)
    assert summary["verdict"] == "rejected"
    assert "waf_block" in summary["patterns"]
    assert len(probe.calls) == 1  # sqlmap KHÔNG chạy


@pytest.mark.asyncio
async def test_verify_sqli_không_injectable_rejected_không_báo_thật():
    probe = FakeProbe([_baseline_stdout(), _sqlmap_stdout(NEG_LOG)])
    pool = ScriptPool()
    summary = await run_sqli_verification(pool, _candidate(), probe=probe, delay_s=1.0)
    assert summary["verdict"] == "rejected"
    assert "not_injectable" in summary["patterns"]
    verdicts = _verdict_updates(pool)
    assert verdicts[-1][1] == "rejected"


@pytest.mark.asyncio
async def test_verify_sqli_log_không_parse_được_rejected():
    probe = FakeProbe([_baseline_stdout(), _sqlmap_stdout("sqlmap crashed\n")])
    pool = ScriptPool()
    summary = await run_sqli_verification(pool, _candidate(), probe=probe, delay_s=1.0)
    assert summary["verdict"] == "rejected"
    assert "no_confirmation" in summary["patterns"]


@pytest.mark.asyncio
async def test_verify_sqli_emission_hỏng_rejected_probe_error():
    probe = FakeProbe([_baseline_stdout(), "no marker\n"])
    pool = ScriptPool()
    summary = await run_sqli_verification(pool, _candidate(), probe=probe, delay_s=1.0)
    assert summary["verdict"] == "rejected"
    assert "probe_error" in summary["patterns"]


@pytest.mark.asyncio
async def test_verify_sqli_không_param_rejected_không_chạy_probe():
    probe = FakeProbe([])
    pool = ScriptPool()
    summary = await run_sqli_verification(
        pool, _candidate(param=""), probe=probe, delay_s=1.0,
    )
    assert summary["verdict"] == "rejected"
    assert "no_param" in summary["patterns"]
    assert probe.calls == []


@pytest.mark.asyncio
async def test_verify_sqli_target_bị_chặn_trả_lifecycle_và_raise():
    from app.verify import ProbeBlocked

    async def blocked(script, target):
        return {"session_id": 9, "status": "blocked", "stdout": "", "stderr": "",
                "reason": "evil.com không thuộc Scope của Run"}

    pool = ScriptPool()
    with pytest.raises(ProbeBlocked):
        await run_sqli_verification(pool, _candidate(), probe=blocked, delay_s=1.0)
    updates = _lifecycle_updates(pool)
    assert updates and updates[-1][1] == "new"


@pytest.mark.asyncio
async def test_verify_sqli_class_khác_valueerror():
    probe = FakeProbe([])
    pool = ScriptPool()
    with pytest.raises(ValueError):
        await run_sqli_verification(
            pool, _candidate(**{"class": "redirect"}), probe=probe, delay_s=1.0,
        )
    assert probe.calls == []


def test_sqli_verify_classes_chỉ_một_lớp():
    assert SQLI_VERIFY_CLASSES == ("sqli",)
