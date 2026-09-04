"""Client HackerOne Hacker API.

Auth: HTTP Basic `username:token` (đúng như curl example trong docs chính thức —
KHÔNG cần "API Token Identifier"). Token đọc từ env, không bao giờ được log.

Rate limit (docs): read 600 req/phút; structured_scopes 50 req/phút; 429 → backoff luỹ thừa.

Các generator trả dict đã chuẩn hoá về schema chung của worker:
- programs()  → {ref, handle, name, currency, policy, submission_state, state,
                 offers_bounties, open_scope, triage_active, started_accepting_at}
- scopes(ref) → {identifier, type, eligible_for_bounty, eligible_for_submission,
                 max_severity, instruction}
"""

import asyncio
import os
import random
from datetime import datetime
from typing import Any, AsyncIterator

import httpx

from .ratelimit import RateLimiter

BASE_URL = "https://api.hackerone.com"
PAGE_SIZE = 100
MAX_429_RETRIES = 6

_scope_limiter = RateLimiter(min_interval=1.3)  # ≈46 req/phút < 50


class HackerOneError(RuntimeError):
    pass


class HackerOneForbidden(HackerOneError):
    """403/404 trên MỘT program — bỏ qua, không fail cả sync."""

    pass


def _credentials() -> tuple[str, str]:
    username = os.environ.get("HACKERONE_USERNAME", "")
    token = os.environ.get("HACKERONE_API_TOKEN", "")
    if not username or not token:
        raise HackerOneError(
            "Thiếu HACKERONE_USERNAME / HACKERONE_API_TOKEN trong env của worker"
        )
    return username, token


async def _get(path: str, params: dict[str, Any], *, scoped: bool = False) -> dict:
    """GET 1 trang JSON; 429/5xx → backoff luỹ thừa; 401 → lỗi rõ ràng."""
    username, token = _credentials()
    if scoped:
        await _scope_limiter.wait()
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        for attempt in range(MAX_429_RETRIES):
            res = await client.get(path, params=params, auth=(username, token))
            if res.status_code == 429:
                delay = min(60.0, 1.5 * (2**attempt)) + random.uniform(0, 0.5)
                await asyncio.sleep(delay)
                continue
            if res.status_code == 401:
                raise HackerOneError(
                    "HackerOne 401 Unauthorized — kiểm tra HACKERONE_USERNAME và "
                    "HACKERONE_API_TOKEN trong .env"
                )
            if res.status_code >= 500:
                await asyncio.sleep(min(30.0, 2.0 * (attempt + 1)))
                continue
            if res.status_code in (403, 404) and scoped:
                raise HackerOneForbidden(
                    f"HackerOne {path} HTTP {res.status_code} — bỏ qua program này"
                )
            if res.status_code != 200:
                raise HackerOneError(
                    f"HackerOne {path} HTTP {res.status_code}: {res.text[:200]}"
                )
            return res.json()
    raise HackerOneError(
        f"HackerOne {path} vẫn 429 sau {MAX_429_RETRIES} lần backoff — thử sync lại sau"
    )


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


async def programs() -> AsyncIterator[dict]:
    """Tất cả program public + invite của user, chuẩn hoá."""
    page = 1
    while True:
        data = await _get(
            "/v1/hackers/programs", {"page[number]": page, "page[size]": PAGE_SIZE}
        )
        items = data.get("data") or []
        if not items:
            return
        for item in items:
            attrs = item.get("attributes") or {}
            handle = attrs.get("handle")
            if not handle:
                continue
            yield {
                "ref": handle,
                "handle": handle,
                "name": attrs.get("name") or handle,
                "currency": attrs.get("currency"),
                "policy": attrs.get("policy"),
                "submission_state": attrs.get("submission_state"),
                "state": attrs.get("state"),
                "offers_bounties": bool(attrs.get("offers_bounties")),
                "min_bounty": None,  # H1 không public bảng bounty cho hacker
                "max_bounty": None,
                "open_scope": attrs.get("open_scope"),
                "triage_active": attrs.get("triage_active"),
                "started_accepting_at": parse_ts(attrs.get("started_accepting_at")),
            }
        if len(items) < PAGE_SIZE or not (data.get("links") or {}).get("next"):
            return
        page += 1


async def scopes(ref: str) -> AsyncIterator[dict]:
    """Structured scopes của 1 program; >10k items thì chuyển filter[id__gt].

    Program trả 403/404 → bỏ qua im lặng, sync vẫn chạy tiếp.
    """
    page = 1
    last_id: int | None = None
    while True:
        if page <= 100:
            params: dict[str, Any] = {
                "page[number]": page,
                "page[size]": PAGE_SIZE,
            }
        else:
            if last_id is None:
                return
            params = {"filter[id__gt]": last_id, "page[size]": PAGE_SIZE}
        try:
            data = await _get(
                f"/v1/hackers/programs/{ref}/structured_scopes",
                params,
                scoped=True,
            )
        except HackerOneForbidden:
            return
        items = data.get("data") or []
        if not items:
            return
        for item in items:
            try:
                last_id = int(item["id"])
            except (KeyError, TypeError, ValueError):
                pass
            attrs = item.get("attributes") or {}
            yield {
                "identifier": attrs.get("asset_identifier") or "",
                "type": attrs.get("asset_type") or "OTHER",
                "eligible_for_bounty": bool(attrs.get("eligible_for_bounty")),
                "eligible_for_submission": bool(attrs.get("eligible_for_submission")),
                "tier": None,
                "max_severity": attrs.get("max_severity"),
                "instruction": attrs.get("instruction"),
            }
        if len(items) < PAGE_SIZE:
            return
        page += 1
