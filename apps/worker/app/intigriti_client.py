"""Client Intigriti Researcher API (https://api.intigriti.com/external/researcher).

Auth: Bearer Personal Access Token (tạo từ profile settings của researcher).
Rate limit: 600 GET / 5 phút → giữ ~100 req/phút, 429 → backoff luỹ thừa.

Schema chung như h1_client (xem docstring ở đó). `ref` = program id (GUID).
Program detail (domains + rules-of-engagement) được fetch 1 lần/program và cache
trong process — cả `programs()` lẫn `scopes()` dùng chung, không gọi trùng.
"""

import asyncio
import os
import random
from typing import Any, AsyncIterator

import httpx

from .ratelimit import RateLimiter

BASE_URL = "https://api.intigriti.com/external/researcher"
PAGE_SIZE = 500  # max theo swagger
MAX_429_RETRIES = 6
POLICY_MAX_CHARS = 8000

_limiter = RateLimiter(min_interval=0.6)  # ~100 req/phút < 600/5 phút

_detail_cache: dict[str, dict] = {}


class IntigritiError(RuntimeError):
    pass


class IntigritiForbidden(IntigritiError):
    """403/404 trên MỘT program (private/invite-only) — bỏ qua, không fail cả sync."""

    pass


def _token() -> str:
    token = os.environ.get("INTIGRITI_API_TOKEN", "")
    if not token:
        raise IntigritiError("Thiếu INTIGRITI_API_TOKEN trong env của worker")
    return token


async def _get(path: str, params: dict[str, Any] | None = None) -> dict | list:
    await _limiter.wait()
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        for attempt in range(MAX_429_RETRIES):
            res = await client.get(
                path,
                params=params,
                headers={"Authorization": f"Bearer {_token()}"},
            )
            if res.status_code == 429:
                delay = min(60.0, 1.5 * (2**attempt)) + random.uniform(0, 0.5)
                await asyncio.sleep(delay)
                continue
            if res.status_code == 401:
                raise IntigritiError(
                    "Intigriti 401 Unauthorized — kiểm tra INTIGRITI_API_TOKEN trong .env"
                )
            if res.status_code in (403, 404):
                raise IntigritiForbidden(
                    f"Intigriti {path} HTTP {res.status_code} — bỏ qua program này"
                )
            if res.status_code >= 500:
                await asyncio.sleep(min(30.0, 2.0 * (attempt + 1)))
                continue
            if res.status_code != 200:
                raise IntigritiError(
                    f"Intigriti {path} HTTP {res.status_code}: {res.text[:200]}"
                )
            return res.json()
    raise IntigritiError(
        f"Intigriti {path} vẫn 429 sau {MAX_429_RETRIES} lần backoff — thử sync lại sau"
    )


async def _detail(ref: str) -> dict | None:
    """Detail 1 program (domains version + RoE); None nếu program private."""
    if ref in _detail_cache:
        return _detail_cache[ref]
    try:
        detail = await _get(f"/v1/programs/{ref}")
    except IntigritiForbidden:
        detail = None
    _detail_cache[ref] = detail or {}
    return _detail_cache[ref] or None


async def programs() -> AsyncIterator[dict]:
    offset = 0
    while True:
        data = await _get("/v1/programs", {"limit": PAGE_SIZE, "offset": offset})
        records = data.get("records") or []
        if not records:
            return
        for item in records:
            handle = item.get("handle")
            ref = item.get("id")
            if not handle or not ref:
                continue
            min_bounty = (item.get("minBounty") or {}) or {}
            max_bounty = (item.get("maxBounty") or {}) or {}
            status = (item.get("status") or {}) or {}
            detail = await _detail(ref) or {}
            roe = ((detail.get("rulesOfEngagement") or {}).get("content") or {}) or {}
            description = roe.get("description")
            yield {
                "ref": ref,
                "handle": handle,
                "name": item.get("name") or handle,
                "currency": max_bounty.get("currency"),
                "policy": (description or "")[:POLICY_MAX_CHARS] or None,
                "submission_state": (status.get("value") or "").lower() or None,
                "state": None,
                "offers_bounties": float(max_bounty.get("value") or 0) > 0,
                "min_bounty": float(min_bounty.get("value") or 0),
                "max_bounty": float(max_bounty.get("value") or 0),
                "open_scope": None,
                "triage_active": None,
                "started_accepting_at": None,
            }
        offset += PAGE_SIZE
        max_count = data.get("maxCount") or 0
        if offset >= max_count or len(records) < PAGE_SIZE:
            return


async def scopes(ref: str) -> AsyncIterator[dict]:
    """Domains của 1 program từ detail đã cache (bản version hiện tại)."""
    detail = await _detail(ref)
    if not detail:
        return
    version = (detail.get("domains") or {}) or {}
    for item in version.get("content") or []:
        dtype = (item.get("type") or {}) or {}
        tier = (item.get("tier") or {}) or {}
        tier_value = tier.get("value") or ""
        yield {
            "identifier": item.get("endpoint") or "",
            "type": (dtype.get("value") or "OTHER").upper(),
            "eligible_for_bounty": tier_value not in ("No Bounty", "Out Of Scope", ""),
            "eligible_for_submission": tier_value != "Out Of Scope",
            "tier": tier_value or None,
            "max_severity": None,
            "instruction": item.get("description"),
        }
