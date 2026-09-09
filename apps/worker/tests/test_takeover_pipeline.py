"""Test pipeline subdomain takeover (ticket #14) — detection + verify với
tool runner, probe và deploy GIẢ.

Detection: CNAME từ recon_assets → subzy-run + nuclei (-tags takeover) →
Candidate class `takeover` (match ngoài Scope bị chặn, không thành Candidate).
Verify: fingerprint probe trong sandbox → PoC page (username + token) → deploy
→ confirm probe qua subdomain. Dương tính: PoC được phục vụ → Finding. Âm
tính: fingerprint match nhưng không deploy/confirm được → rejected
(không báo thật); chưa có hosting → needs_manual kèm hướng dẫn.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_takeover_pipeline.py -q
"""

import json

import pytest

from app import config
from app.takeover import (
    DeployResult,
    TakeoverHostingError,
    build_poc_page,
    new_takeover_token,
    run_takeover_detection,
    run_takeover_verification,
)
from app.verify import PROBE_MARKER
from fakes import FakeRunner
from test_oob_pipeline import OOBFakePool as ScriptPool

SNAPSHOT = [{"asset_identifier": "*.victim.com", "asset_type": "URL"}]

RUN = {
    "id": 1,
    "rate_limit_rps": 1.0,
    "ident_header_name": None,
    "ident_header_value": None,
    "scope_snapshot": SNAPSHOT,
    "allow_non_prod": False,
}

CANDIDATE = {
    "id": 9,
    "run_id": 1,
    "target": "http://sub.victim.com",
    "class": "takeover",
    "param": "",
    "template_id": "takeover/subzy",
    "title": "GitHub Pages",
    "severity": "high",
    "matcher_name": "fingerprint",
    "status": "new",
    "evidence_path": None,
    "first_seen": "2026-01-01T00:00:00Z",
}

FINGERPRINT_BODY = "There isn't a GitHub Pages site here."


def _probe_stdout(status=200, body="ok"):
    profile = {
        "url": "http://sub.victim.com/",
        "status": status,
        "headers": {"content-type": "text/html"},
        "content_type": "text/html",
        "body_length": len(body),
        "body": body,
    }
    return f"{PROBE_MARKER}\n{json.dumps(profile)}\n"


class FakeProbe:
    """Probe giả: thứ tự lần gọi → stdout; ghi lại (script, target)."""

    def __init__(self, stdouts):
        self.stdouts = stdouts
        self.calls = []
        self.next_id = iter(range(101, 200))

    async def __call__(self, script, target):
        self.calls.append((script, target))
        return {
            "session_id": next(self.next_id),
            "status": "ok",
            "stdout": self.stdouts[len(self.calls) - 1] if len(self.calls) <= len(self.stdouts) else "",
            "stderr": "",
        }


class FakeDeploy:
    """Deploy giả: ghi lại (claim_host, page_html, victim_host)."""

    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = result
        self.error = error

    async def __call__(self, claim_host, page_html, victim_host):
        self.calls.append((claim_host, page_html, victim_host))
        if self.error is not None:
            raise self.error
        return self.result or DeployResult(
            url=f"http://{victim_host}/", provider="github-pages", detail={"fake": True}
        )


def _verdict_updates(pool):
    return [p for _, sql, p in pool.executes
            if "UPDATE candidates SET status = $2, confidence" in sql]


def _manual_updates(pool):
    return [p for _, sql, p in pool.executes
            if "UPDATE candidates" in sql and "confidence = NULL" in sql]


def _verify_pool(cname="someuser.github.io"):
    pool = ScriptPool()
    pool.fetchrow_script["FROM recon_assets"] = (
        [{"host": "sub.victim.com", "cname": cname}] if cname else [None]
    )
    return pool


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))
    monkeypatch.setattr(config.settings, "artifacts_dir", str(tmp_path / "artifacts"))
    monkeypatch.setattr(config.settings, "verify_confidence_threshold", 0.85)
    monkeypatch.setattr(config.settings, "takeover_hosting", "")
    monkeypatch.setattr(config.settings, "hackerone_username", "natuan1")
    monkeypatch.setattr(config.settings, "intigriti_username", "")
    monkeypatch.setattr(config.settings, "takeover_verify_wait_s", 0.0)
    monkeypatch.setattr(config.settings, "takeover_verify_poll_s", 0.01)


# ─────────────────────────── detection pipeline ───────────────────────────


def _detection_pool(assets):
    pool = ScriptPool()
    pool.fetch_script["FROM recon_assets"] = [assets]
    return pool


def _subzy_stdout():
    return json.dumps([
        {"subdomain": "http://sub.victim.com", "status": "vulnerable",
         "engine": "GitHub Pages", "cname": ["someuser.github.io"],
         "fingerprint": "There isn't a GitHub Pages site here.",
         "http_status": 404, "vulnerable": True},
        {"subdomain": "http://evil.other.com", "status": "vulnerable",
         "engine": "GitHub Pages", "cname": ["x.github.io"],
         "fingerprint": "x", "http_status": 404, "vulnerable": True},
    ])


def _nuclei_finding():
    return json.dumps({
        "template-id": "takeovers/github-pages",
        "info": {"name": "GitHub Pages Takeover", "severity": "high",
                 "tags": ["takeover"]},
        "host": "sub.victim.com",
        "matched-at": "http://sub.victim.com",
        "matcher-name": "dns",
    })


@pytest.mark.asyncio
async def test_detection_cname_ra_candidate_ngoai_scope_bị_chặn():
    runner = FakeRunner({
        "subzy-run": _subzy_stdout(),
        "nuclei": _nuclei_finding(),
    })
    pool = _detection_pool([
        {"host": "sub.victim.com", "cname": "someuser.github.io"},
        {"host": "evil.other.com", "cname": "x.github.io"},
    ])
    summary = await run_takeover_detection(pool, RUN, tool_runner=runner)

    assert summary["candidates"] == 1
    assert summary["blocked"] == 1  # evil.other.com ngoài Scope
    # đúng 2 tool: subzy-run wrapper + nuclei takeovers
    tools = [c[0] for c in runner.calls]
    assert tools == ["subzy-run", "nuclei"]
    nuclei_args = runner.calls[1][1]
    assert "-tags" in nuclei_args and "takeover" in nuclei_args
    # stdin của subzy chỉ gồm host có CNAME
    assert "sub.victim.com" in (runner.calls[0][2] or "")
    # 1 Candidate duy nhất (subzy thắng, nuclei trùng target bị dedupe)
    inserts = [p for _, sql, p in pool.executes if "INSERT INTO candidates" in sql]
    assert inserts
    rows = inserts[0]
    assert len(rows) == 1
    assert rows[0].target == "http://sub.victim.com"
    assert rows[0].cls == "takeover" and rows[0].param == ""
    assert "takeover/" in rows[0].template_id
    # evidence file cho match
    import pathlib

    files = list(pathlib.Path(config.settings.evidence_dir).rglob("*.json"))
    assert files and "candidates" in str(files[0])


@pytest.mark.asyncio
async def test_detection_không_cname_không_chạy_tool():
    runner = FakeRunner({})
    pool = _detection_pool([])
    summary = await run_takeover_detection(pool, RUN, tool_runner=runner)
    assert summary == {"candidates": 0, "blocked": 0}
    assert runner.calls == []


@pytest.mark.asyncio
async def test_detection_tool_lỗi_không_thành_candidate():
    class FailRunner(FakeRunner):
        async def __call__(self, tool, args, stdin=None, docker_args=None):
            await super().__call__(tool, args, stdin, docker_args)
            from app.tools import ToolResult

            return ToolResult(1, "", "boom")

    runner = FailRunner({"subzy-run": "", "nuclei": ""})
    pool = _detection_pool([{"host": "sub.victim.com", "cname": "someuser.github.io"}])
    summary = await run_takeover_detection(pool, RUN, tool_runner=runner)
    assert summary["candidates"] == 0


# ─────────────────────────── verification pipeline ───────────────────────────


@pytest.mark.asyncio
async def test_verify_hosting_poc_được_phục_vụ_verified(monkeypatch):
    from app import takeover as tk

    monkeypatch.setattr(tk, "new_nonce", lambda: "abc123def456")
    token = new_takeover_token(9, "abc123def456")
    poc_body = build_poc_page("natuan1", token, "http://sub.victim.com", "GitHub Pages")
    probe = FakeProbe([
        _probe_stdout(404, FINGERPRINT_BODY),      # fingerprint còn bỏ hoang
        _probe_stdout(200, poc_body),              # confirm: PoC được phục vụ
    ])
    deploy = FakeDeploy()
    pool = _verify_pool()
    summary = await run_takeover_verification(
        pool, CANDIDATE, probe=probe, deploy=deploy
    )

    assert summary["verdict"] == "verified"
    assert summary["score"] >= 0.85
    assert "poc_served" in summary["signals"]
    assert summary["poc_url"] == "http://sub.victim.com/"
    assert summary["username"] == "natuan1"
    # probe đều qua sandbox: fingerprint rồi confirm — KHÔNG fetch ngoài sandbox
    assert len(probe.calls) == 2
    assert all("http://sub.victim.com/" in s for s, _ in probe.calls)
    # deploy nhận đúng claim host + PoC page chứa username + token
    assert len(deploy.calls) == 1
    claim_host, page, victim = deploy.calls[0]
    assert claim_host == "someuser.github.io" and victim == "sub.victim.com"
    assert "natuan1" in page and token in page
    # lifecycle: verifying → verified + evidence + session ids
    verifying = [p for _, sql, p in pool.executes
                 if "UPDATE candidates SET status = $2 WHERE id = $1" in sql]
    assert verifying and verifying[-1][1] == "verifying"
    final = _verdict_updates(pool)[-1]
    assert final[0] == 9 and final[1] == "verified"
    assert final[4] is None  # reject_reason
    assert "takeover/009.json" in final[5]
    assert final[6] == 102 and final[7] == 101  # confirm + fingerprint session
    evidence = json.loads(open(final[5], encoding="utf-8").read())
    assert evidence["schema"] == "vulhunt.takeover-evidence/1"
    assert evidence["fingerprint"]["service"] == "GitHub Pages"
    assert evidence["poc"]["username"] == "natuan1" and evidence["poc"]["token"] == token
    assert evidence["deploy"]["provider"] == "github-pages"
    assert evidence["confirm"]["status"] == 200


@pytest.mark.asyncio
async def test_verify_chưa_có_hosting_needs_manual_có_hướng_dẫn(monkeypatch):
    from app import takeover as tk

    monkeypatch.setattr(tk, "new_nonce", lambda: "abc123def456")
    probe = FakeProbe([_probe_stdout(404, FINGERPRINT_BODY)])
    pool = _verify_pool()
    summary = await run_takeover_verification(pool, CANDIDATE, probe=probe)

    assert summary["verdict"] == "needs_manual"
    assert "manual_verification_required" in summary["patterns"]
    assert "N/A" in summary["reason"]  # cảnh báo reput trong hướng dẫn
    assert len(probe.calls) == 1       # chỉ fingerprint probe — không deploy
    updates = _manual_updates(pool)
    assert updates and updates[0][1] == "needs_manual"
    evidence = json.loads(open(updates[0][2], encoding="utf-8").read())
    assert evidence["guidance"] and "someuser" in evidence["guidance"]


@pytest.mark.asyncio
async def test_verify_fingerprint_mất_rejected_không_deploy():
    probe = FakeProbe([_probe_stdout(200, "<html>site bình thường</html>")])
    deploy = FakeDeploy()
    pool = _verify_pool()
    summary = await run_takeover_verification(
        pool, CANDIDATE, probe=probe, deploy=deploy
    )
    assert summary["verdict"] == "rejected"
    assert "fingerprint_gone" in summary["patterns"]
    assert deploy.calls == []
    assert _verdict_updates(pool)[-1][1] == "rejected"


@pytest.mark.asyncio
async def test_verify_deploy_ok_nhưng_không_kiểm_soát_được_rejected(monkeypatch):
    from app import takeover as tk

    monkeypatch.setattr(tk, "new_nonce", lambda: "abc123def456")
    # deploy xong nhưng subdomain vẫn phục vụ trang bỏ hoang → không kiểm soát
    probe = FakeProbe([
        _probe_stdout(404, FINGERPRINT_BODY),
        _probe_stdout(404, FINGERPRINT_BODY),
    ])
    deploy = FakeDeploy()
    pool = _verify_pool()
    summary = await run_takeover_verification(
        pool, CANDIDATE, probe=probe, deploy=deploy
    )
    assert summary["verdict"] == "rejected"
    assert "no_control" in summary["patterns"]
    assert len(deploy.calls) == 1
    assert _verdict_updates(pool)[-1][1] == "rejected"
    assert "kiểm soát" in _verdict_updates(pool)[-1][4].lower()


@pytest.mark.asyncio
async def test_verify_claim_thất_bại_rejected_claim_failed():
    probe = FakeProbe([_probe_stdout(404, FINGERPRINT_BODY)])
    deploy = FakeDeploy(error=TakeoverHostingError("username đã bị chiếm"))
    pool = _verify_pool()
    summary = await run_takeover_verification(
        pool, CANDIDATE, probe=probe, deploy=deploy
    )
    assert summary["verdict"] == "rejected"
    assert "claim_failed" in summary["patterns"]
    assert len(probe.calls) == 1
    assert _verdict_updates(pool)[-1][1] == "rejected"


@pytest.mark.asyncio
async def test_verify_service_lạ_needs_manual_không_chạy_probe():
    probe = FakeProbe([])
    pool = _verify_pool(cname="random.host.example.com")
    summary = await run_takeover_verification(pool, CANDIDATE, probe=probe, deploy=FakeDeploy())
    assert summary["verdict"] == "needs_manual"
    assert "unknown_service" in summary["patterns"]
    assert probe.calls == []


@pytest.mark.asyncio
async def test_verify_không_cname_rejected():
    probe = FakeProbe([])
    pool = _verify_pool(cname=None)
    summary = await run_takeover_verification(pool, CANDIDATE, probe=probe)
    assert summary["verdict"] == "rejected"
    assert "no_cname" in summary["patterns"]
    assert probe.calls == []


@pytest.mark.asyncio
async def test_verify_thiếu_username_needs_manual(monkeypatch):
    monkeypatch.setattr(config.settings, "hackerone_username", "")
    monkeypatch.setattr(config.settings, "intigriti_username", "")
    probe = FakeProbe([])
    pool = _verify_pool()
    summary = await run_takeover_verification(pool, CANDIDATE, probe=probe)
    assert summary["verdict"] == "needs_manual"
    assert "missing_username" in summary["patterns"]
    assert probe.calls == []


@pytest.mark.asyncio
async def test_verify_target_bị_chặn_trả_lifecycle_về_và_raise():
    from app.verify import ProbeBlocked

    async def blocked(script, target):
        return {"session_id": 9, "status": "blocked", "stdout": "", "stderr": "",
                "reason": "victim.com không thuộc Scope của Run"}

    pool = _verify_pool()
    with pytest.raises(ProbeBlocked):
        await run_takeover_verification(pool, CANDIDATE, probe=blocked, deploy=FakeDeploy())
    updates = [p for _, sql, p in pool.executes if "UPDATE candidates SET status = $2" in sql]
    assert updates and updates[-1][1] == "new"  # không verdict oan


# ─────────────── end-to-end (AC1): detect → verify ra Finding ───────────────


@pytest.mark.asyncio
async def test_end_to_end_detect_rồi_verify_ra_finding_với_poc_hoạt_động(monkeypatch):
    """Target mô phỏng (CNAME trỏ service bỏ hoang) đi TRỌN ĐƯỜNG: detection
    sinh Candidate class takeover → verify với probe/deploy giả → Finding
    (verified) với PoC page chứa username được phục vụ qua subdomain."""
    from app import takeover as tk

    monkeypatch.setattr(tk, "new_nonce", lambda: "abc123def456")

    # ── detection: recon_assets có CNAME treo → subzy match ──
    runner = FakeRunner({
        "subzy-run": _subzy_stdout(),
        "nuclei": "[]",
    })
    pool = _detection_pool([
        {"host": "sub.victim.com", "cname": "someuser.github.io"},
    ])
    detection = await run_takeover_detection(pool, RUN, tool_runner=runner)
    assert detection["candidates"] == 1

    inserts = [p for _, sql, p in pool.executes if "INSERT INTO candidates" in sql]
    row = inserts[0][0]
    candidate = {
        "id": 21, "run_id": row.run_id, "target": row.target, "class": row.cls,
        "param": row.param, "template_id": row.template_id, "title": row.title,
        "severity": row.severity, "matcher_name": row.matcher_name,
        "status": "new", "evidence_path": row.evidence_path,
        "first_seen": "2026-01-01T00:00:00Z",
    }
    assert candidate["class"] == "takeover"
    assert candidate["target"] == "http://sub.victim.com"

    # ── verify: fingerprint → deploy PoC (username natuan1) → confirm serve ──
    token = new_takeover_token(21, "abc123def456")
    poc_body = build_poc_page("natuan1", token, candidate["target"], "GitHub Pages")

    class EndToEndProbe:
        """Probe 'sandbox' giả: lần 1 service bỏ hoang (404 marker), từ lần 2
        trở đi subdomain phục vụ PoC page (giống service thật sau claim)."""

        def __init__(self):
            self.calls = 0

        async def __call__(self, script, target):
            self.calls += 1
            body = FINGERPRINT_BODY if self.calls == 1 else poc_body
            return {
                "session_id": 500 + self.calls,
                "status": "ok",
                "stdout": _probe_stdout(404 if self.calls == 1 else 200, body),
                "stderr": "",
            }

    deployed: list[tuple] = []

    async def deploy(claim_host, page_html, victim_host):
        deployed.append((claim_host, page_html, victim_host))
        return DeployResult(url=f"http://{victim_host}/",
                            provider="github-pages", detail={"e2e": True})

    pool2 = _verify_pool()
    summary = await run_takeover_verification(
        pool2, candidate, probe=EndToEndProbe(), deploy=deploy
    )

    assert summary["verdict"] == "verified"
    assert "poc_served" in summary["signals"]
    # PoC page chứa username định danh + được deploy lên đúng claim host
    assert len(deployed) == 1
    claim_host, page, victim = deployed[0]
    assert claim_host == "someuser.github.io" and victim == "sub.victim.com"
    assert "natuan1" in page and token in page
    verdict = _verdict_updates(pool2)[-1]
    assert verdict[1] == "verified" and verdict[2] >= 0.85
    evidence = json.loads(open(verdict[5], encoding="utf-8").read())
    assert evidence["fingerprint"]["service"] == "GitHub Pages"
    assert evidence["poc"]["username"] == "natuan1"
    assert evidence["confirm"]["status"] == 200
