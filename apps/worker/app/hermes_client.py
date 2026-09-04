"""Client gọi hermes gateway (API server OpenAI-compatible) từ worker.

Endpoints dùng:
- POST /v1/chat/completions  — one-shot, stateless
- POST /v1/runs              — agent run (có tool/skill), trả run_id
- GET  /v1/runs/{id}         — poll status (output + usage)
- GET  /v1/runs/{id}/events  — SSE lifecycle events
"""

import asyncio
import json
import os
import uuid
from typing import AsyncIterator

import httpx

HERMES_API_URL = os.environ.get("HERMES_API_URL", "http://hermes:8642").rstrip("/")
HERMES_API_KEY = os.environ.get("HERMES_API_KEY", "")
_HTTP_TIMEOUT = float(os.environ.get("HERMES_HTTP_TIMEOUT", "30"))


class HermesError(RuntimeError):
    pass


def _headers() -> dict:
    if not HERMES_API_KEY:
        raise HermesError("HERMES_API_KEY chưa được cấu hình cho worker")
    return {
        "Authorization": f"Bearer {HERMES_API_KEY}",
        "Content-Type": "application/json",
    }


async def chat_completion(prompt: str, *, model: str = "hermes-agent") -> dict:
    """One-shot qua /v1/chat/completions → {text, usage, model}."""
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            res = await client.post(
                f"{HERMES_API_URL}/v1/chat/completions",
                json=payload,
                headers=_headers(),
            )
    except httpx.HTTPError as exc:
        raise HermesError(f"không gọi được hermes gateway: {exc}") from exc
    if res.status_code != 200:
        raise HermesError(
            f"hermes /v1/chat/completions HTTP {res.status_code}: {res.text[:300]}"
        )
    data = res.json()
    text = ((data.get("choices") or [{}])[0].get("message") or {}).get("content", "")
    return {"text": text, "usage": data.get("usage") or {}, "model": data.get("model", model)}


async def start_run(prompt: str, *, instructions: str | None = None) -> str:
    """POST /v1/runs → run_id. Có Idempotency-Key để retry an toàn."""
    body: dict = {"input": prompt}
    if instructions:
        body["instructions"] = instructions
    headers = _headers()
    headers["Idempotency-Key"] = uuid.uuid4().hex
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            res = await client.post(f"{HERMES_API_URL}/v1/runs", json=body, headers=headers)
    except httpx.HTTPError as exc:
        raise HermesError(f"không gọi được hermes gateway: {exc}") from exc
    if res.status_code not in (200, 202):
        raise HermesError(f"hermes /v1/runs HTTP {res.status_code}: {res.text[:300]}")
    return res.json()["run_id"]


async def run_status(run_id: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            res = await client.get(
                f"{HERMES_API_URL}/v1/runs/{run_id}", headers=_headers()
            )
    except httpx.HTTPError as exc:
        raise HermesError(f"không gọi được hermes gateway: {exc}") from exc
    if res.status_code != 200:
        raise HermesError(f"hermes /v1/runs/{run_id} HTTP {res.status_code}")
    return res.json()


async def stream_run_events(run_id: str) -> AsyncIterator[dict]:
    """Đọc SSE GET /v1/runs/{id}/events, yield {'event': name, 'data': ...}."""
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream(
                "GET", f"{HERMES_API_URL}/v1/runs/{run_id}/events", headers=_headers()
            ) as res:
                if res.status_code != 200:
                    raise HermesError(
                        f"hermes SSE HTTP {res.status_code} cho run {run_id}"
                    )
                event_name: str | None = None
                async for line in res.aiter_lines():
                    if line.startswith("event:"):
                        event_name = line[len("event:"):].strip()
                    elif line.startswith("data:"):
                        raw = line[len("data:"):].strip()
                        try:
                            data = json.loads(raw)
                        except json.JSONDecodeError:
                            data = raw
                        yield {"event": event_name, "data": data}
    except httpx.HTTPError as exc:
        raise HermesError(f"SSE hermes lỗi: {exc}") from exc


async def health() -> dict:
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            res = await client.get(f"{HERMES_API_URL}/health")
    except httpx.HTTPError as exc:
        return {"reachable": False, "error": str(exc)}
    if res.status_code != 200:
        return {"reachable": False, "status_code": res.status_code}
    return {"reachable": True, **res.json()}


async def run_agent(prompt: str, *, timeout: float = 600.0, poll_interval: float = 2.0) -> dict:
    """Chạy 1 agent run: POST /v1/runs + đọc SSE song song + poll đến khi xong.

    Trả {run_id, status, text, usage, events_seen} — events_seen > 0 chứng minh SSE hoạt động.
    """
    run_id = await start_run(prompt)
    events: list[dict] = []

    async def _consume() -> None:
        try:
            async for ev in stream_run_events(run_id):
                events.append(ev)
        except (HermesError, asyncio.CancelledError):
            pass  # SSE có thể ngắt trước khi poll thấy terminal — không fatal

    consumer = asyncio.create_task(_consume())
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    status: dict = {}
    try:
        while True:
            status = await run_status(run_id)
            if status.get("status") in ("completed", "failed", "cancelled"):
                break
            if loop.time() > deadline:
                raise HermesError(f"run {run_id} quá {timeout:.0f}s chưa xong")
            await asyncio.sleep(poll_interval)
    finally:
        consumer.cancel()
    return {
        "run_id": run_id,
        "status": status.get("status"),
        "text": status.get("output"),
        "usage": status.get("usage") or {},
        "events_seen": len(events),
    }
