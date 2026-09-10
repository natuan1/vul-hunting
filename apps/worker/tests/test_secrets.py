"""Test batch B — lớp exposed secrets (trufflehog verify-key, ticket #16).

Detection: tool `trufflehog-urls` quét nội dung URL nhạy cảm (.env, bucket,
JS bundle, backup files) với `--only-verified` — secret ĐÃ verify-key mới
thành Candidate class `secret` severity `high`; evidence che bớt key (chỉ
prefix). Verify: sandbox quét lại nội dung URL (không verification — egress
proxy chặn provider API) + đối chiếu detector/prefix → Finding; evidence
KHÔNG bao giờ chứa key đầy đủ.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_secrets.py -q
"""

import hashlib
import json

import pytest

from app import config
from app.secrets_scan import (
    SECRET_CANDIDATE_CLASS,
    SECRET_SEVERITY,
    build_secret_baseline_script,
    build_secret_rescan_script,
    mask_secret,
    parse_secret_marker,
    parse_secret_rescan,
    parse_trufflehog_jsonl,
    run_secret_detection,
    run_secret_verification,
    select_secret_urls,
    secret_fingerprint,
    secret_marker,
)
from app.verify import PROBE_MARKER
from fakes import FakeRunner
from test_oob_pipeline import FakeProbe, OOBFakePool as ScriptPool

# fake secret "bị lộ" trên target mô phỏng — không bao giờ được xuất hiện
# NGUYÊN trong evidence
FAKE_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_FP = secret_fingerprint(FAKE_KEY)

SNAPSHOT = [{"asset_identifier": "app.other.com", "asset_type": "URL"}]

RUN = {
    "id": 1,
    "rate_limit_rps": None,
    "ident_header_name": None,
    "ident_header_value": None,
    "scope_snapshot": SNAPSHOT,
    "allow_non_prod": False,
}

# fake secret "bị lộ" trên target mô phỏng — không bao giờ được xuất hiện
# NGUYÊN trong evidence
FAKE_KEY = "AKIAIOSFODNN7EXAMPLE"


def _rows(pool):
    rows = []
    for _, sql, params in pool.executes:
        if "INSERT INTO candidates" in sql:
            rows.extend(params)
    return rows


def _verdict_updates(pool):
    return [
        p
        for _, sql, p in pool.executes
        if "UPDATE candidates SET status" in sql and "verify_evidence_path = $6" in sql
    ]


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))
    monkeypatch.setattr(config.settings, "artifacts_dir", str(tmp_path / "artifacts"))
    monkeypatch.setattr(config.settings, "verify_confidence_threshold", 0.85)


# ─────────────────────────── pure seams ───────────────────────────


def test_select_secret_urls_chỉ_lấy_env_js_backup_bucket():
    urls = [
        "https://app.other.com/",
        "https://app.other.com/.env",
        "https://app.other.com/.env.local",
        "https://app.other.com/static/app.min.js?v=2",
        "https://app.other.com/backup/site.tar.gz",
        "https://s3.amazonaws.com/app.other.com-assets/dump.sql",
        "https://app.other.com/contact",
        "https://app.other.com/api/users?id=1",
    ]
    picked = select_secret_urls(urls)
    assert "https://app.other.com/.env" in picked
    assert "https://app.other.com/.env.local" in picked
    assert "https://app.other.com/static/app.min.js?v=2" in picked
    assert "https://app.other.com/backup/site.tar.gz" in picked
    assert "https://s3.amazonaws.com/app.other.com-assets/dump.sql" in picked
    # URL thường không được quét — giữ nguyên tắc minimum testing necessary
    assert "https://app.other.com/contact" not in picked
    assert "https://app.other.com/" not in picked
    assert "https://app.other.com/api/users?id=1" not in picked


def test_select_secret_urls_dedupe_giữ_thứ_tự_và_cap():
    urls = [
        "https://app.other.com/.env",
        "https://app.other.com/.env",
        *[f"https://app.other.com/{i}.bak" for i in range(10)],
    ]
    picked = select_secret_urls(urls, max_targets=5)
    assert picked[0] == "https://app.other.com/.env"
    assert len(picked) == 5  # dedupe 11 → 10 URL unique, cap 5
    assert len(set(picked)) == len(picked)


def test_mask_secret_chỉ_hiện_prefix():
    masked = mask_secret(FAKE_KEY)
    assert masked == "AKIA…"
    assert FAKE_KEY not in masked
    assert "EXAMPLE" not in masked
    # key ngắn — phần bị che ít hơn phần hiện → che toàn bộ
    assert mask_secret("short") == "…"
    assert mask_secret("1234567") == "…"
    assert mask_secret("") == "…"
    # không bao giờ dài hơn gốc
    assert len(mask_secret("abcdefghij")) <= 5


def test_secret_marker_ghép_detector_prefix_và_fingerprint():
    marker = secret_marker("AWS", "AKIA…", "aa11bb22cc33")
    assert marker == "AWS|AKIA…|aa11bb22cc33"
    assert parse_secret_marker(marker) == ("AWS", "AKIA…", "aa11bb22cc33")
    assert parse_secret_marker("weird") == ("", "", "")


def test_secret_fingerprint_ổn_định_không_đảo_ngược_được():
    fp = secret_fingerprint(FAKE_KEY)
    assert fp == hashlib.sha256(FAKE_KEY.encode()).hexdigest()[:12]
    assert FAKE_KEY not in fp
    assert secret_fingerprint(FAKE_KEY) == secret_fingerprint(FAKE_KEY)


def test_parse_trufflehog_jsonl_chỉ_nhận_verified_không_rò_key():
    # dòng 1: wrapper format (đã rewrite url + xoá Raw); dòng 2: raw trufflehog
    # format (fallback an toàn — parser tự mask + tự tính fingerprint);
    # dòng 3: filesystem path thuần (không URL → DROP); dòng 4: unverified;
    # dòng 5 rác
    raw_ghp = "ghp_" + "x" * 36
    stdout = "\n".join(
        [
            json.dumps(
                {
                    "url": "https://app.other.com/.env",
                    "detector": "AWS",
                    "verified": True,
                    "masked": "AKIA…",
                    "fingerprint": FAKE_FP,
                    "raw_length": 20,
                }
            ),
            json.dumps(
                {
                    "SourceMetadata": {"Data": {"File": "https://app.other.com/app.js"}},
                    "DetectorName": "GitHub",
                    "DecoderName": "plain",
                    "Verified": True,
                    "Raw": raw_ghp,
                }
            ),
            json.dumps(
                {
                    "SourceMetadata": {
                        "Data": {"Filesystem": {"file": "/tmp/x/0003.txt", "line": 1}}
                    },
                    "DetectorName": "Stripe",
                    "DecoderName": "PLAIN",
                    "Verified": True,
                    "Raw": "sk_live_" + "y" * 24,
                }
            ),
            json.dumps(
                {
                    "url": "https://app.other.com/.env.local",
                    "detector": "Stripe",
                    "verified": False,
                    "masked": "sk_l…",
                    "raw_length": 32,
                }
            ),
            "not json at all",
        ]
    )
    hits = parse_trufflehog_jsonl(stdout)
    assert len(hits) == 2  # chỉ verified + có URL ánh xạ được
    assert hits[0] == {
        "url": "https://app.other.com/.env",
        "detector": "AWS",
        "verified": True,
        "masked": "AKIA…",
        "fingerprint": FAKE_FP,
        "raw_length": 20,
    }
    assert hits[1]["detector"] == "GitHub"
    assert hits[1]["url"] == "https://app.other.com/app.js"
    assert hits[1]["fingerprint"] == secret_fingerprint(raw_ghp)  # tự tính
    # hit filesystem path thuần (không URL) bị bỏ — không tạo Candidate rác
    assert all(h["url"].startswith("http") for h in hits)
    # key raw KHÔNG BAO GIỜ lọt ra ngoài parser — chỉ prefix + fingerprint
    dumped = json.dumps(hits)
    full_ghp = raw_ghp
    assert full_ghp not in dumped
    assert "x" * 36 not in dumped
    assert hits[1]["masked"] == "ghp_…"


def test_parse_secret_rescan_đọc_marker_json():
    payload = {
        "url": "https://app.other.com/.env",
        "http_status": 200,
        "content_length": 123,
        "secrets": [
            {"detector": "AWS", "masked": "AKIA…", "fingerprint": FAKE_FP,
             "raw_length": 20}
        ],
    }
    stdout = f"{PROBE_MARKER}\n{json.dumps(payload)}\n"
    res = parse_secret_rescan(stdout)
    assert res == payload
    assert parse_secret_rescan("no marker here") is None
    assert parse_secret_rescan(f"{PROBE_MARKER}\nbroken{{") is None


def test_build_secret_rescan_script_không_bật_verification():
    script = build_secret_rescan_script("https://app.other.com/.env")
    assert "trufflehog" in script
    # sandbox egress proxy chỉ cho target trong Scope — verification với
    # provider API sẽ bị chặn: tắt để không tạo egress noise + chậm
    assert "--no-verification" in script
    assert "--json" in script
    assert "https://app.other.com/.env" in script
    # script mask secret trước khi in (prefix only)
    assert "mask" in script


def test_build_secret_baseline_script_không_ghi_body():
    """Baseline không thu body — tránh đưa nội dung (chứa key) vào evidence."""
    script = build_secret_baseline_script("https://app.other.com/.env")
    assert PROBE_MARKER in script
    assert "https://app.other.com/.env" in script
    assert '"body": ""' in script  # body rỗng — chỉ status/headers/length


# ─────────────────────────── detection pipeline ───────────────────────────


def _wrapper_output():
    return "\n".join(
        [
            json.dumps(
                {
                    "url": "https://app.other.com/.env",
                    "detector": "AWS",
                    "verified": True,
                    "masked": "AKIA…",
                    "fingerprint": FAKE_FP,
                    "raw_length": 20,
                }
            ),
            # unverified — KHÔNG thành Candidate
            json.dumps(
                {
                    "url": "https://app.other.com/static/app.min.js",
                    "detector": "GitHub",
                    "verified": False,
                    "masked": "ghp_…",
                    "fingerprint": secret_fingerprint("ghp_x"),
                    "raw_length": 40,
                }
            ),
        ]
    ) + "\n"


@pytest.mark.asyncio
async def test_detection_secret_verified_thành_candidate_high_evidence_che_key():
    runner = FakeRunner({"trufflehog-urls": _wrapper_output()})
    pool = ScriptPool()
    summary = await run_secret_detection(
        pool,
        RUN,
        tool_runner=runner,
        live_urls=[
            "https://app.other.com/.env",
            "https://app.other.com/static/app.min.js",
            "https://app.other.com/contact",
        ],
        classed_urls=[],
    )

    # chỉ 1 lần gọi tool với stdin = URL nhạy cảm (không có /contact)
    assert [c[0] for c in runner.calls] == ["trufflehog-urls"]
    stdin = runner.calls[0][2]
    assert "https://app.other.com/.env" in stdin
    assert "app.min.js" in stdin
    assert "/contact" not in stdin
    # pacing + header định danh truyền vào container wrapper (rate limit của
    # Run áp cả cấp request, không chỉ lúc launch tool)
    docker_args = runner.docker_calls[0] or []
    docker_text = " ".join(docker_args)
    assert "FETCH_DELAY_S=1" in docker_text  # rate_limit_rps None → sàn 1s

    rows = _rows(pool)
    assert len(rows) == 1  # unverified bị bỏ
    row = rows[0]
    assert row.cls == SECRET_CANDIDATE_CLASS == "secret"
    assert row.severity == SECRET_SEVERITY == "high"
    assert row.template_id == "trufflehog-urls/AWS"
    # detector + prefix + fingerprint cho verify đối chiếu (rotate → lệch fp)
    assert row.matcher_name == f"AWS|AKIA…|{FAKE_FP}"
    assert "AWS" in row.title
    assert row.status == "new"

    # evidence file không chứa key nguyên bản (chỉ masked + fingerprint)
    import pathlib

    files = list(pathlib.Path(config.settings.evidence_dir).rglob("*.json"))
    assert len(files) == 1
    text = files[0].read_text(encoding="utf-8")
    record = json.loads(text)
    assert record["schema"] == "vulhunt.secret-detection-evidence/1"
    assert record["detector"] == "AWS"
    assert record["masked"] == "AKIA…"
    assert record["verified"] is True
    assert record["fingerprint"] == FAKE_FP
    assert FAKE_KEY not in text
    assert summary == {"candidates": 1, "blocked": 0}


@pytest.mark.asyncio
async def test_detection_target_ngoài_scope_bị_chặn_không_chạy_tool():
    runner = FakeRunner({"trufflehog-urls": _wrapper_output()})
    pool = ScriptPool()
    summary = await run_secret_detection(
        pool, RUN, tool_runner=runner,
        live_urls=["https://evil.example/.env"], classed_urls=[],
    )
    assert summary == {"candidates": 0, "blocked": 1}
    assert runner.calls == []
    assert _rows(pool) == []


@pytest.mark.asyncio
async def test_detection_không_url_nhạy_cảm_không_chạy_tool():
    runner = FakeRunner({})
    pool = ScriptPool()
    summary = await run_secret_detection(
        pool, RUN, tool_runner=runner,
        live_urls=["https://app.other.com/", "https://app.other.com/contact"],
        classed_urls=[],
    )
    assert summary == {"candidates": 0, "blocked": 0}
    assert runner.calls == []


@pytest.mark.asyncio
async def test_detection_tool_lỗi_không_thành_candidate():
    class FailRunner(FakeRunner):
        async def __call__(self, tool, args, stdin=None, docker_args=None):
            await super().__call__(tool, args, stdin, docker_args)
            from app.tools import ToolResult

            return ToolResult(1, "", "trufflehog boom")

    runner = FailRunner({"trufflehog-urls": _wrapper_output()})
    pool = ScriptPool()
    summary = await run_secret_detection(
        pool, RUN, tool_runner=runner,
        live_urls=["https://app.other.com/.env"], classed_urls=[],
    )
    assert summary["candidates"] == 0
    assert _rows(pool) == []


@pytest.mark.asyncio
async def test_detection_output_rác_không_thành_candidate():
    runner = FakeRunner({"trufflehog-urls": "trufflehog: no findings\n"})
    pool = ScriptPool()
    summary = await run_secret_detection(
        pool, RUN, tool_runner=runner,
        live_urls=["https://app.other.com/.env"], classed_urls=[],
    )
    assert summary["candidates"] == 0
    assert _rows(pool) == []


# ─────────────────────────── verify pipeline ───────────────────────────


def _candidate(**over):
    base = {
        "id": 12,
        "run_id": 1,
        "target": "https://app.other.com/.env",
        "class": "secret",
        "param": "",
        "template_id": "trufflehog-urls/AWS",
        "title": "Exposed secrets (AWS)",
        "severity": "high",
        "matcher_name": f"AWS|AKIA…|{FAKE_FP}",
        "status": "new",
        "evidence_path": None,
        "first_seen": "2026-01-01T00:00:00Z",
    }
    base.update(over)
    return base


def _baseline_stdout(status=200, length=123):
    profile = {
        "url": "https://app.other.com/.env",
        "status": status,
        "headers": {},
        "content_type": "text/plain",
        "body_length": length,
        "body": "",
    }
    return f"{PROBE_MARKER}\n{json.dumps(profile)}\n"


def _rescan_stdout(hits, status=200, length=123):
    payload = {
        "url": "https://app.other.com/.env",
        "http_status": status,
        "content_length": length,
        "secrets": hits,
    }
    return f"{PROBE_MARKER}\n{json.dumps(payload)}\n"


def _hit(**over):
    hit = {
        "detector": "AWS", "masked": "AKIA…",
        "fingerprint": FAKE_FP, "raw_length": 20,
    }
    hit.update(over)
    return hit


@pytest.mark.asyncio
async def test_verify_secret_còn_exposed_verified_evidence_không_chứa_key():
    """AC #16: fake secret trên target mô phỏng → Candidate → verify ra Finding,
    evidence KHÔNG chứa key đầy đủ (chỉ prefix đã che)."""
    probe = FakeProbe([_baseline_stdout(), _rescan_stdout([_hit()])])
    pool = ScriptPool()
    summary = await run_secret_verification(pool, _candidate(), probe=probe)

    assert summary["verdict"] == "verified"
    assert summary["score"] >= 0.85
    assert "secret_still_exposed" in summary["signals"]
    # đúng 2 probe: baseline vô hại + rescan sandbox
    assert len(probe.calls) == 2
    # rescan script chạy trufflehog, KHÔNG chứa key nguyên bản
    assert "trufflehog" in probe.calls[1][0]
    assert FAKE_KEY not in probe.calls[1][0]

    verdicts = _verdict_updates(pool)
    assert verdicts and verdicts[-1][1] == "verified"
    evidence_path = verdicts[-1][5]
    text = open(evidence_path, encoding="utf-8").read()
    assert FAKE_KEY not in text  # key đầy đủ không bao giờ vào evidence
    assert "AKIA…" in text       # chỉ prefix
    record = json.loads(text)
    assert record["schema"] == "vulhunt.secret-verify-evidence/1"
    assert record["rescan"]["secrets"] == [_hit()]
    assert record["expected"] == {
        "detector": "AWS", "masked": "AKIA…", "fingerprint": FAKE_FP,
    }
    # baseline profile không có body — không mang nội dung chứa key vào evidence
    assert record["baseline"]["body"] == ""


@pytest.mark.asyncio
async def test_verify_secret_waf_ở_baseline_không_chạy_rescan():
    probe = FakeProbe([_baseline_stdout(status=403)])
    pool = ScriptPool()
    summary = await run_secret_verification(pool, _candidate(), probe=probe)
    assert summary["verdict"] == "rejected"
    assert "waf_block" in summary["patterns"]
    assert len(probe.calls) == 1  # rescan không chạy — minimum testing
    verdicts = _verdict_updates(pool)
    assert verdicts[-1][1] == "rejected"


@pytest.mark.asyncio
async def test_verify_secret_nội_dung_đã_mất_rejected():
    probe = FakeProbe([_baseline_stdout(status=200, length=0),
                       _rescan_stdout([], status=404, length=0)])
    pool = ScriptPool()
    summary = await run_secret_verification(pool, _candidate(), probe=probe)
    assert summary["verdict"] == "rejected"
    assert "no_longer_exposed" in summary["patterns"]


@pytest.mark.asyncio
async def test_verify_secret_vẫn_serve_nhưng_không_còn_key_rejected():
    probe = FakeProbe([_baseline_stdout(), _rescan_stdout([])])
    pool = ScriptPool()
    summary = await run_secret_verification(pool, _candidate(), probe=probe)
    assert summary["verdict"] == "rejected"
    assert "no_longer_exposed" in summary["patterns"]
    verdicts = _verdict_updates(pool)
    assert verdicts[-1][1] == "rejected"


@pytest.mark.asyncio
async def test_verify_secret_key_đã_rotate_rejected():
    """Nội dung còn serve nhưng secret KHÁC (fingerprint lệch dù detector +
    prefix giống — key đã rotate) — không được báo Finding trên secret cũ."""
    probe = FakeProbe([
        _baseline_stdout(),
        _rescan_stdout([_hit(fingerprint="bb22cc33dd44")]),
    ])
    pool = ScriptPool()
    summary = await run_secret_verification(pool, _candidate(), probe=probe)
    assert summary["verdict"] == "rejected"
    assert "secret_changed" in summary["patterns"]


@pytest.mark.asyncio
async def test_verify_secret_detector_khác_rejected():
    probe = FakeProbe([_baseline_stdout(), _rescan_stdout([_hit(detector="Slack")])])
    pool = ScriptPool()
    summary = await run_secret_verification(pool, _candidate(), probe=probe)
    assert summary["verdict"] == "rejected"
    assert "secret_changed" in summary["patterns"]


@pytest.mark.asyncio
async def test_verify_secret_rescan_hỏng_rejected_probe_error():
    probe = FakeProbe([_baseline_stdout(), "no marker\n"])
    pool = ScriptPool()
    summary = await run_secret_verification(pool, _candidate(), probe=probe)
    assert summary["verdict"] == "rejected"
    assert "probe_error" in summary["patterns"]


@pytest.mark.asyncio
async def test_verify_secret_target_bị_chặn_trả_lifecycle_và_raise():
    from app.verify import ProbeBlocked

    async def blocked(script, target):
        return {"session_id": 9, "status": "blocked", "stdout": "", "stderr": "",
                "reason": "evil.com không thuộc Scope của Run"}

    pool = ScriptPool()
    with pytest.raises(ProbeBlocked):
        await run_secret_verification(pool, _candidate(), probe=blocked)
    updates = [p for _, sql, p in pool.executes
               if "UPDATE candidates SET status = $2" in sql]
    assert updates and updates[-1][1] == "new"  # không verdict oan


@pytest.mark.asyncio
async def test_verify_secret_class_khác_valueerror():
    probe = FakeProbe([])
    pool = ScriptPool()
    with pytest.raises(ValueError):
        await run_secret_verification(pool, _candidate(**{"class": "redirect"}), probe=probe)
    assert probe.calls == []
