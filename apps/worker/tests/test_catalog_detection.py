"""Test detection batch A (ticket #15) — graphql-cop/graphw00f, crlfuzz,
SSTImap với tool runner giả.

Dương tính: hit introspection từ graphql-cop → Candidate class `graphql`;
URL vulnerable từ crlfuzz → class `crlf`; "exploitable" từ sstimap → class
`ssti`. Âm tính: target ngoài Scope bị chặn, tool lỗi → không Candidate.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_catalog_detection.py -q
"""

import json

import pytest

from app import config
from app.httpverify import run_catalog_detection, run_http_verification
from app.verify import PROBE_MARKER
from fakes import FakePool, FakeRunner
from test_oob_pipeline import OOBFakePool as ScriptPool

SNAPSHOT = [{"asset_identifier": "app.other.com", "asset_type": "URL"}]

RUN = {
    "id": 1,
    "rate_limit_rps": None,
    "ident_header_name": None,
    "ident_header_value": None,
    "scope_snapshot": SNAPSHOT,
    "allow_non_prod": False,
}


def _rows(pool):
    rows = []
    for _, sql, params in pool.executes:
        if "INSERT INTO candidates" in sql:
            rows.extend(params)
    return rows


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))
    monkeypatch.setattr(config.settings, "artifacts_dir", str(tmp_path / "artifacts"))


def _runner_outputs():
    return {
        "graphw00f": "\033[92m[*] Discovered GraphQL Engine: (Appollo Graphql)\033[0m\n",
        "graphql-cop": json.dumps([
            {"title": "Introspection", "danger": True, "result": True, "method": "POST"},
            {"title": "Field Suggestions", "danger": False, "result": False},
        ]),
        "crlfuzz": "https://app.other.com/search?q=1\n",
        "sstimap": "\033[92m[+]\033[0m Jinja2 plugin has confirmed injection with tag '{{7*7}}'\n",
    }


@pytest.mark.asyncio
async def test_detection_ba_tool_chuyên_dụng_ra_đúng_class():
    runner = FakeRunner(_runner_outputs())
    pool = ScriptPool()
    summary = await run_catalog_detection(
        pool, RUN, tool_runner=runner,
        live_urls=["https://app.other.com/graphql", "https://app.other.com/search?q=1"],
        classed_urls=[],
    )

    tools = [c[0] for c in runner.calls]
    assert tools.count("graphw00f") == 1  # chỉ URL trông như GraphQL
    assert tools.count("graphql-cop") == 1
    assert tools.count("crlfuzz") == 1
    assert tools.count("sstimap") == 1    # chỉ URL có param
    assert tools[0] == "graphw00f" and tools[1] == "graphql-cop"

    rows = _rows(pool)
    classes = sorted(r.cls for r in rows)
    assert classes == ["crlf", "graphql", "ssti"]
    graphql = next(r for r in rows if r.cls == "graphql")
    assert graphql.template_id == "graphql-cop/introspection"
    assert "Appollo" in graphql.title
    assert graphql.severity == "medium"
    crlf = next(r for r in rows if r.cls == "crlf")
    assert crlf.param == "q" and crlf.severity == "high"
    assert summary["candidates"] == 3 and summary["blocked"] == 0
    # evidence file thật cho từng hit
    import pathlib

    files = list(pathlib.Path(config.settings.evidence_dir).rglob("*.json"))
    assert len(files) >= 3


@pytest.mark.asyncio
async def test_detection_target_ngoài_scope_bị_chặn():
    runner = FakeRunner(_runner_outputs())
    pool = ScriptPool()
    summary = await run_catalog_detection(
        pool, RUN, tool_runner=runner,
        live_urls=["https://evil.example/graphql?q=1"], classed_urls=[],
    )
    assert summary["candidates"] == 0
    assert summary["blocked"] == 1
    assert _rows(pool) == []
    # không URL nào thuộc Scope → không tool chuyên dụng nào chạy với target
    assert all((c[2] or "") == "" or "evil.example" not in c[2] for c in runner.calls)


@pytest.mark.asyncio
async def test_detection_không_target_không_chạy_tool():
    runner = FakeRunner({})
    pool = ScriptPool()
    summary = await run_catalog_detection(pool, RUN, tool_runner=runner,
                                          live_urls=[], classed_urls=[])
    assert summary == {"candidates": 0, "blocked": 0}
    assert runner.calls == []


@pytest.mark.asyncio
async def test_detection_tool_lỗi_không_thành_candidate():
    from app.tools import ToolResult

    class FailRunner(FakeRunner):
        async def __call__(self, tool, args, stdin=None, docker_args=None):
            await super().__call__(tool, args, stdin, docker_args)
            return ToolResult(1, "", "tool chết")

    runner = FailRunner(_runner_outputs())
    pool = ScriptPool()
    summary = await run_catalog_detection(
        pool, RUN, tool_runner=runner,
        live_urls=["https://app.other.com/graphql", "https://app.other.com/search?q=1"],
        classed_urls=[],
    )
    assert summary["candidates"] == 0
    assert _rows(pool) == []


@pytest.mark.asyncio
async def test_end_to_end_detection_rồi_verify_ra_finding(monkeypatch):
    """AC: target mô phỏng GraphQL introspection đi TRỌN ĐƯỜNG — detection
    (graphql-cop) → Candidate class `graphql` → verify (probe giả trả
    __schema) → Finding (verified) kèm evidence."""
    runner = FakeRunner({
        "graphw00f": "",
        "graphql-cop": json.dumps([
            {"title": "Introspection", "danger": True, "result": True},
        ]),
    })
    pool = ScriptPool()
    detection = await run_catalog_detection(
        pool, RUN, tool_runner=runner,
        live_urls=["https://app.other.com/graphql"], classed_urls=[],
    )
    assert detection["candidates"] == 1
    row = _rows(pool)[0]
    candidate = {
        "id": 21, "run_id": row.run_id, "target": row.target, "class": row.cls,
        "param": row.param, "template_id": row.template_id, "title": row.title,
        "severity": row.severity, "matcher_name": row.matcher_name,
        "status": "new", "evidence_path": row.evidence_path,
        "first_seen": "2026-01-01T00:00:00Z",
    }
    assert candidate["class"] == "graphql"

    calls = []

    async def probe(script, target):
        calls.append((script, target))
        n = len(calls)
        body = (
            json.dumps({"data": {"__typename": "Query"}})
            if n == 1
            else json.dumps({"data": {"__schema": {"types": [{"name": "User"}]}}})
        )
        profile = {
            "url": target, "status": 200,
            "headers": {"content-type": "application/json"},
            "content_type": "application/json",
            "body_length": len(body), "body": body,
        }
        return {
            "session_id": 300 + n, "status": "ok",
            "stdout": f"{PROBE_MARKER}\n{json.dumps(profile)}\n", "stderr": "",
        }

    pool2 = FakePool()
    summary = await run_http_verification(pool2, candidate, probe=probe)
    assert summary["verdict"] == "verified" and summary["score"] >= 0.85
    assert len(calls) == 2  # baseline __typename + PoC __schema, đều qua sandbox
