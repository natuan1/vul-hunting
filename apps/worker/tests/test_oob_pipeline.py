"""Test pipeline OOB (ticket #13) — orchestration register/poll/attach +
vòng xác minh OOB (blind ssrf) với probe và interactsh client GIẢ.

Dương tính: callback quay về trong cửa sổ chờ → verified kèm evidence OOB.
Âm tính: hết cửa sổ không callback → rejected (không báo thật); token của Run
khác không gắn chéo; target bị chặn scope → trả lifecycle về cũ.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_oob_pipeline.py -q
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app import config
from app.oob import (
    candidate_token,
    close_run_registrations,
    ensure_registration,
    poll_once,
    poll_registration,
    run_oob_verification,
)
from fakes import FakePool

NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)

CANDIDATE = {
    "id": 7,
    "run_id": 1,
    "target": "https://app.other.com/fetch?url=https://app.other.com/x",
    "class": "ssrf",
    "param": "url",
    "template_id": "blind-ssrf",
    "title": "Blind SSRF",
    "severity": "high",
    "matcher_name": "word",
    "status": "new",
    "evidence_path": None,
    "first_seen": "2026-01-01T00:00:00Z",
}


class FakeClient:
    """Interactsh client giả: ghi lại register/poll/deregister, trả callback
    theo kịch bản (queue poll response từng lượt)."""

    def __init__(self, poll_responses=None):
        self.poll_responses = list(poll_responses or [])
        self.registered = []
        self.polled = []
        self.deregistered = []
        self._reg_id = iter(range(10, 10000))

    async def register(self, host, public_key_b64, secret_key, correlation_id):
        self.registered.append((host, correlation_id))
        return f"https://{host}"

    async def poll(self, server_url, correlation_id, secret_key):
        self.polled.append((server_url, correlation_id))
        return self.poll_responses.pop(0) if self.poll_responses else ([], "")

    async def deregister(self, server_url, correlation_id, secret_key):
        self.deregistered.append((server_url, correlation_id))
        return True


class OOBFakeConn:
    """Conn ủy quyền mọi truy vấn về OOBFakePool (thay FakeConn mặc định)."""

    def __init__(self, parent):
        self.parent = parent

    async def execute(self, sql, *params):
        self.parent.executes.append((sql.strip().split()[0].lower(), sql, params))

    async def executemany(self, sql, rows):
        self.parent.executes.append(("executemany", sql, rows))

    async def fetchval(self, sql, *params):
        self.parent.executes.append(("fetchval", sql, params))
        return self.parent._pop_fetchval(sql)

    async def fetchrow(self, sql, *params):
        self.parent.executes.append(("fetchrow", sql, params))
        return self.parent._pop_script(self.parent.fetchrow_script, sql, None)

    async def fetch(self, sql, *params):
        self.parent.executes.append(("fetch", sql, params))
        return self.parent._pop_script(self.parent.fetch_script, sql, [])


class OOBFakePool(FakePool):
    """FakePool có script phản hồi theo SQL: fetchrow/fetch lấy lần lượt từ
    queue gắn theo bảng (registrations/candidates/callbacks)."""

    def __init__(self):
        super().__init__()
        self.fetchrow_script: dict[str, list] = {}
        self.fetch_script: dict[str, list] = {}
        self.fetchval_script: dict[str, list] = {}

    def acquire(self):
        return self

    async def __aenter__(self):
        return OOBFakeConn(self)

    async def __aexit__(self, *exc):
        return False

    def _pop_script(self, script: dict[str, list], sql: str, default):
        for key, items in script.items():
            if key in sql and items:
                return items.pop(0)
        return default

    def _pop_fetchval(self, sql: str):
        val = self._pop_script(self.fetchval_script, sql, None)
        return next(self.ids) if val is None else val


def reg_row(**over):
    base = {
        "id": 5,
        "run_id": 1,
        "server_url": "https://oast.pro",
        "domain": "abcdefghijklmnopqrst1234567890abc.oast.pro",
        "correlation_id": "abcdefghijklmnopqrst",
        "secret_key": "secret",
        "private_key": None,  # pipeline test không giải mã thật — client giả trả interaction sẵn
        "status": "active",
        "registered_at": NOW,
        "expires_at": NOW + timedelta(hours=24),
    }
    base.update(over)
    return base


def interaction(full_id, protocol="http", source="93.184.216.34:443"):
    return {
        "protocol": protocol,
        "unique-id": full_id.split(".")[0],
        "full-id": full_id,
        "remote-address": source,
        "timestamp": "2026-09-08T12:00:01Z",
        "raw-request": "GET / HTTP/1.1",
    }


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))
    monkeypatch.setattr(config.settings, "interactsh_server", "oast.pro,oast.live")
    monkeypatch.setattr(config.settings, "oob_verify_wait_s", 1.0)
    monkeypatch.setattr(config.settings, "oob_verify_poll_s", 0.01)
    monkeypatch.setattr(config.settings, "verify_confidence_threshold", 0.85)


def _attach_sql_executes(pool):
    return [p for _, sql, p in pool.executes if "UPDATE candidates SET" in sql and "oob_evidence_path" in sql]


def _verdict_updates(pool):
    return [
        p
        for _, sql, p in pool.executes
        if "UPDATE candidates SET status" in sql and "oob_evidence_path = $6" in sql
    ]


# ── ensure_registration: tái sử dụng session còn hạn, hết thì register mới ──


@pytest.mark.asyncio
async def test_ensure_registration_có_active_còn_hạn_thì_dùng_lại():
    pool = OOBFakePool()
    pool.fetchrow_script["oob_registrations"] = [reg_row()]
    client = FakeClient()
    reg = await ensure_registration(pool, 1, client)
    assert reg["id"] == 5 and reg["domain"].endswith("oast.pro")
    assert client.registered == []  # không register lại


@pytest.mark.asyncio
async def test_ensure_registration_chưa_có_thì_register_mới_ghi_db_and_log():
    pool = OOBFakePool()
    pool.fetchrow_script["oob_registrations"] = [
        None,  # chưa có active
        {**reg_row(), "id": 6, "domain": "zzzzzzzzzzzzzzzzzzzzz111111111.oast.pro"},
    ]
    client = FakeClient()
    reg = await ensure_registration(pool, 1, client)
    assert client.registered and client.registered[0][0] in ("oast.pro", "oast.live")
    inserts = [p for _, sql, p in pool.executes if "INSERT INTO oob_registrations" in sql]
    assert inserts and inserts[0][0] == 1  # run_id
    assert reg["domain"] == "zzzzzzzzzzzzzzzzzzzzz111111111.oast.pro"
    logs = [p for _, sql, p in pool.executes if "run_logs" in sql]
    assert any("OOB" in str(p) for row in logs for p in row)


# ── poll_registration: giải mã/giả interaction → lưu + gắn đúng Candidate ──


@pytest.mark.asyncio
async def test_poll_registration_gắn_callback_đúng_candidate_cùng_run(monkeypatch):
    pool = OOBFakePool()
    token = candidate_token(7, "ybndrfg8ejkmc")
    pool.fetchrow_script["FROM candidates"] = [
        {"id": 7, "run_id": 1, "class": "ssrf", "target": CANDIDATE["target"]},
    ]
    pool.fetch_script["FROM oob_callbacks"] = [
        [
            {
                "id": 1,
                "protocol": "http",
                "source": "93.184.216.34:443",
                "unique_id": token,
                "full_id": f"{token}.abcdefghijklmnopqrst1234567890abc",
                "occurred_at": NOW,
                "received_at": NOW,
                "raw_interaction": interaction(f"{token}.abcdefghijklmnopqrst1234567890abc"),
            }
        ],
    ]
    reg = reg_row()
    client = FakeClient()
    # client giả trả data để poll không thoát sớm; decrypt giả trả interaction
    # khớp token của Candidate #7
    from app import oob as oob_mod

    async def fake_poll(server_url, cid, secret):
        client.polled.append((server_url, cid))
        return (["x"], "key")

    client.poll = fake_poll
    monkeypatch.setattr(
        oob_mod, "decrypt_interactions",
        lambda *a, **k: [
            interaction(f"{candidate_token(7, 'ybndrfg8ejkmc')}.abcdefghijklmnopqrst1234567890abc")
        ],
    )
    result = await poll_registration(pool, reg, client)

    assert result["stored"] == 1 and len(result["matched"]) == 1
    assert result["matched"][0]["candidate_id"] == 7
    inserts = [p for _, sql, p in pool.executes if "INSERT INTO oob_callbacks" in sql]
    assert inserts and inserts[0][2] == 7  # candidate_id
    # evidence file + count được gắn
    attaches = _attach_sql_executes(pool)
    assert attaches and attaches[0][0] == 7 and "oob/007.json" in attaches[0][1]
    content = json.loads(open(attaches[0][1], encoding="utf-8").read())
    assert content["callbacks"][0]["protocol"] == "http"
    assert content["registration"]["correlation_id"] == "abcdefghijklmnopqrst"


@pytest.mark.asyncio
async def test_poll_registration_token_của_run_khác_không_gắn_chéo(monkeypatch):
    pool = OOBFakePool()
    pool.fetchrow_script["FROM candidates"] = [
        {"id": 7, "run_id": 99, "class": "ssrf", "target": "x"},  # Run khác!
    ]
    from app import oob as oob_mod

    monkeypatch.setattr(
        oob_mod, "decrypt_interactions",
        lambda *a, **k: [
            interaction(f"{candidate_token(7, 'ybndrfg8ejkmc')}.abcdefghijklmnopqrst1234567890abc")
        ],
    )
    result = await poll_registration(
        pool, reg_row(), FakeClient(poll_responses=[(["x"], "key")])
    )
    assert result["stored"] == 1
    assert result["matched"] == []  # không gắn
    inserts = [p for _, sql, p in pool.executes if "INSERT INTO oob_callbacks" in sql]
    assert inserts and inserts[0][2] is None  # callback trôi nổi


@pytest.mark.asyncio
async def test_poll_registration_không_data_thì_không_làm_gì():
    pool = OOBFakePool()
    result = await poll_registration(pool, reg_row(), FakeClient())
    assert result == {"stored": 0, "matched": []}
    assert not [1 for _, sql, _ in pool.executes if "INSERT INTO oob_callbacks" in sql]


# ── poll_once: sweep hết hạn + xoá cache cũ ──


@pytest.mark.asyncio
async def test_poll_once_hết_hạn_deregister_và_đánh_dấu_expired():
    pool = OOBFakePool()
    pool.fetch_script["FROM oob_registrations"] = [
        [reg_row(expires_at=NOW - timedelta(minutes=1))],  # active nhưng quá hạn
        [reg_row(expires_at=NOW - timedelta(minutes=1))],
    ]
    client = FakeClient()
    totals = await poll_once(pool, client)
    assert totals["expired"] == 1
    assert client.deregistered and client.deregistered[0][1] == "abcdefghijklmnopqrst"
    updates = [p for _, sql, p in pool.executes if "SET status = $2" in sql and "expired" in p]
    assert updates
    # cache cũ hơn retention bị xoá
    deletes = [sql for _, sql, _ in pool.executes if "DELETE FROM oob_callbacks" in sql]
    assert deletes


# ── close_run_registrations ──


@pytest.mark.asyncio
async def test_close_run_registrations_deregister_và_status_closed():
    pool = OOBFakePool()
    pool.fetch_script["FROM oob_registrations"] = [[reg_row()]]
    client = FakeClient()
    n = await close_run_registrations(pool, 1, client)
    assert n == 1
    assert client.deregistered
    closed = [p for _, sql, p in pool.executes if "SET status = $2" in sql and "closed" in p]
    assert closed and closed[0][1] == "closed" and 5 in closed[0][0]  # theo id registration


# ── vòng xác minh OOB ──


class FakeProbe:
    """Probe giả như test_verify_pipeline — map thứ tự gọi → stdout."""

    def __init__(self, stdouts):
        from app.verify import PROBE_MARKER

        self.stdouts = stdouts
        self.calls = []
        self.next_id = iter(range(101, 200))
        self.marker = PROBE_MARKER

    async def __call__(self, script, target):
        self.calls.append((script, target))
        return {
            "session_id": next(self.next_id),
            "status": "ok",
            "stdout": self.stdouts[len(self.calls) - 1] if len(self.calls) <= len(self.stdouts) else "",
            "stderr": "",
        }


def _probe_stdout(status=200, body="ok"):
    from app.verify import PROBE_MARKER

    profile = {
        "url": "https://app.other.com/fetch",
        "status": status,
        "headers": {},
        "content_type": "text/html",
        "body_length": len(body),
        "body": body,
    }
    return f"{PROBE_MARKER}\n{json.dumps(profile)}\n"


def _verify_pool(callback_full_ids):
    """Pool giả cho pipeline verify: registration sẵn (id 5) + fetchrow trả
    candidate khi poll match + fetch danh sách callbacks khi gắn evidence."""
    pool = OOBFakePool()
    # thứ tự fetchrow trong pipeline: 1) registration active → None (register mới)
    # → INSERT RETURNING reg; 2) candidates lookup mỗi interaction; còn lại None
    pool.fetchrow_script["oob_registrations"] = [None, reg_row()]
    token_ids = []
    for fid in callback_full_ids:
        pool.fetchrow_script["FROM candidates"] = (
            pool.fetchrow_script.get("FROM candidates", [])
            + [{"id": 7, "run_id": 1, "class": "ssrf", "target": CANDIDATE["target"]}]
        )
        token_ids.append(fid)
    pool.fetch_script["FROM oob_callbacks"] = [
        [
            {
                "id": 1,
                "protocol": "http",
                "source": "93.184.216.34:443",
                "unique_id": fid.split(".")[0],
                "full_id": fid,
                "occurred_at": NOW,
                "received_at": NOW,
                "raw_interaction": interaction(fid),
            }
        ]
        for fid in callback_full_ids
    ] or [[], [], []]
    return pool


@pytest.mark.asyncio
async def test_verify_oob_callback_về_verified_có_evidence(monkeypatch):
    from app import oob as oob_mod

    # cố định nonce để token payload (và callback khớp về) đoán được trong test
    monkeypatch.setattr(oob_mod, "new_nonce", lambda: "ybndrfg8ejkmc")
    token_id = f"{candidate_token(7, 'ybndrfg8ejkmc')}.abcdefghijklmnopqrst1234567890abc"
    monkeypatch.setattr(
        oob_mod, "decrypt_interactions", lambda *a, **k: [interaction(token_id)]
    )
    probe = FakeProbe([_probe_stdout(), _probe_stdout()])
    pool = _verify_pool([token_id])
    summary = await run_oob_verification(
        pool, CANDIDATE, probe=probe,
        client=FakeClient(poll_responses=[(["x"], "key")]),
    )

    assert summary["verdict"] == "verified"
    assert summary["score"] >= 0.85
    assert "oob_callback" in summary["signals"]
    assert summary["domain"].endswith("oast.pro")
    payload_url = f"http://c7nybndrfg8ejkmc.abcdefghijklmnopqrst1234567890abc.oast.pro"
    assert summary["payload"] == payload_url
    # baseline + PoC chạy qua sandbox (đúng 2 probe), payload chèn vào param url
    from app.verify import inject_param

    assert len(probe.calls) == 2
    assert inject_param(CANDIDATE["target"], "url", payload_url) in probe.calls[1][0]
    assert (
        inject_param(CANDIDATE["target"], "url", "https://example.com/")
        in probe.calls[0][0]
    )  # baseline vô hại
    # lifecycle: verifying → verified kèm evidence path
    verdicts = _verdict_updates(pool)
    assert verdicts and verdicts[-1][1] == "verified" and verdicts[-1][4] is None
    assert "oob/007.json" in verdicts[-1][5]
    evidence = json.loads(open(verdicts[-1][5], encoding="utf-8").read())
    assert evidence["analysis"]["signals"] == ["oob_callback"]
    assert evidence["callbacks"][0]["protocol"] == "http"
    assert evidence["payload"] == payload_url
    assert evidence["registration"]["correlation_id"] == "abcdefghijklmnopqrst"


@pytest.mark.asyncio
async def test_verify_oob_hết_cửa_sổ_không_callback_rejected_không_báo_thật(monkeypatch):
    from app import oob as oob_mod

    monkeypatch.setattr(
        oob_mod, "decrypt_interactions", lambda *a, **k: []  # không bao giờ có callback
    )
    probe = FakeProbe([_probe_stdout(), _probe_stdout()])
    pool = _verify_pool([])
    summary = await run_oob_verification(
        pool, CANDIDATE, probe=probe, client=FakeClient()
    )
    assert summary["verdict"] == "rejected"
    assert "no_oob_callback" in summary["patterns"]
    verdicts = _verdict_updates(pool)
    assert verdicts[-1][1] == "rejected"
    assert "callback" in verdicts[-1][4].lower()


@pytest.mark.asyncio
async def test_verify_oob_không_param_rejected_không_chạy_probe():
    probe = FakeProbe([])
    pool = _verify_pool([])
    summary = await run_oob_verification(pool, {**CANDIDATE, "param": ""}, probe=probe)
    assert summary["verdict"] == "rejected"
    assert "no_param" in summary["patterns"]
    assert probe.calls == []


@pytest.mark.asyncio
async def test_verify_oob_target_bị_chặn_trả_lifecycle_về_và_raise():
    from app.verify import ProbeBlocked

    async def blocked(script, target):
        return {"session_id": 9, "status": "blocked", "stdout": "", "stderr": "",
                "reason": "evil.com không thuộc Scope của Run"}

    pool = _verify_pool([])
    with pytest.raises(ProbeBlocked):
        await run_oob_verification(pool, CANDIDATE, probe=blocked, client=FakeClient())
    updates = [p for _, sql, p in pool.executes if "UPDATE candidates SET status = $2" in sql]
    assert updates and updates[-1][1] == "new"  # trả về như cũ, không verdict oan
