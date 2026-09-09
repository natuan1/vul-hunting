"""Lớp subdomain takeover end-to-end (ticket #14).

**Detection** dùng CNAME đã thu từ dnsx ở Recon giai đoạn 1 (cột
`recon_assets.cname`): `subzy` (fingerprint từ can-i-take-over-xyz, JSON qua
wrapper `subzy-run` trong tooling image) + nuclei templates `takeovers`
(`-tags takeover`). Mỗi match → 1 **Candidate** class `takeover` (dedupe
(run_id, target, class, param) như mọi Candidate).

**Verify đặc biệt**: policy của nhiều Program (vd Goldman Sachs) yêu cầu chứng
minh KIỂM SOÁT được subdomain — fingerprint match thôi thì report sẽ bị đóng
N/A và ảnh hưởng reput. Vòng verify vì thế đi tiếp:

  1. probe fingerprint trong sandbox (service còn bỏ hoang?);
  2. soạn **PoC page chứa username định danh của user** + token one-shot;
  3. deploy qua hosting khả dụng (seam `deploy` — production: GitHub Pages
     hoặc S3, cấu hình TAKEOVER_HOSTING; chạy phía WORKER như client
     interactsh ở ADR-0004 vì đây là hạ tầng của mình, không phải target —
     CHỈ bước chạm target là confirm probe qua sandbox, đúng luật ADR-0003);
  4. confirm probe trong sandbox: subdomain có phục vụ đúng PoC page không →
     **Finding (verified)** chỉ khi PoC hoạt động; deploy xong mà subdomain
     không phục vụ → **rejected** (`no_control` — fingerprint match nhưng
     không kiểm soát được).

Chưa cấu hình hosting → verify dừng ở **needs_manual** ("fingerprint match —
cần xác minh tay") kèm hướng dẫn claim + nội dung PoC page phải chứa gì.
Phần thuần (fingerprints, parser, PoC page, phân tích confirm, SigV4,
deployer) tách riêng để test; pipeline nhận `probe` và `deploy` là seam.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

import asyncpg
import httpx

from . import sandbox
from .config import settings
from .detect import (
    CANDIDATE_COLS,
    CandidateRow,
    _insert_candidates,
    parse_nuclei_jsonl,
    validate_severity,
    write_evidence,
)
from .oob import new_nonce
from .recon import unique_hosts
from .scope_validator import target_host
from .tools import (
    ToolContext,
    add_log,
    build_context,
    execute_tool,
    filter_scope,
)
from .verify import (
    ProbeBlocked,
    ProbeCallable,
    ProbeProfile,
    build_probe_script,
    parse_probe,
)

log = logging.getLogger("takeover")

# ───────────────────────────── fingerprints ─────────────────────────────


@dataclass(frozen=True)
class TakeoverFingerprint:
    """Fingerprint một service bỏ hoang claim được — dữ liệu gọn từ
    can-i-take-over-xyz/subzy: khớp theo ĐUÔI CNAME, xác nhận bằng marker
    trong body + HTTP status của trạng thái "chưa gắn"/"không tồn tại"."""

    service: str
    cname_suffixes: tuple[str, ...]  # khớp nếu CNAME == suffix hoặc endswith('.'+suffix)
    markers: tuple[str, ...]         # dấu hiệu "service bỏ hoang" trong body (bất kỳ)
    statuses: tuple[int, ...]        # HTTP status đi kèm trạng thái bỏ hoang
    claimable: bool                  # về nguyên tắc có claim được không
    hosting: str | None              # provider tự động ('github-pages' | 's3' | None = chỉ tay)
    claim_guide: str                 # hướng dẫn claim / xác minh tay (tiếng Việt)


def _fp(service, suffixes, markers, statuses, claimable, hosting, guide):
    return TakeoverFingerprint(
        service=service, cname_suffixes=suffixes, markers=markers,
        statuses=statuses, claimable=claimable, hosting=hosting, claim_guide=guide,
    )


FINGERPRINTS: tuple[TakeoverFingerprint, ...] = (
    _fp(
        "GitHub Pages", ("github.io",),
        ("There isn't a GitHub Pages site here.",), (404,),
        True, "github-pages",
        "Đăng ký GitHub account đúng tên nhãn đầu của CNAME (nếu còn trống) rồi tạo "
        "repo `<label>.github.io`, đẩy `index.html` (PoC page) + file `CNAME` chứa "
        "host nạn nhân, bật Pages.",
    ),
    _fp(
        "S3", ("s3.amazonaws.com", "s3-website-us-east-1.amazonaws.com"),
        ("NoSuchBucket", "The specified bucket does not exist"), (404,),
        True, "s3",
        "Tạo S3 bucket tên ĐÚNG phần đầu của CNAME (host nạn nhân, có dấu chấm vẫn "
        "đặt được), region khớp bản ghi, bật static website hosting, đặt `index.html` "
        "(PoC page) public-read.",
    ),
    _fp(
        "Heroku", ("herokuapp.com",),
        ("No such app",), (404,),
        True, None,
        "Đăng ký Heroku app tên đúng nhãn đầu của CNAME rồi deploy trang PoC.",
    ),
    _fp(
        "Azure", ("azurewebsites.net",),
        ("404 Web Site not found",), (404,),
        True, None,
        "Tạo Azure App Service tên đúng nhãn đầu của CNAME rồi deploy trang PoC.",
    ),
    _fp(
        "GitLab Pages", ("gitlab.io",),
        ("The page you're looking for could not be found",), (404,),
        True, None,
        "Đăng ký GitLab group/user đúng tên nhãn đầu của CNAME, tạo project "
        "`<label>.gitlab.io` với Pages job chứa PoC page.",
    ),
    _fp(
        "Bitbucket", ("bitbucket.io",),
        ("Repository not found",), (404,),
        True, None,
        "Đăng ký Bitbucket workspace/user đúng tên rồi tạo repo `<label>.bitbucket.io`.",
    ),
    _fp(
        "Surge.sh", ("surge.sh",),
        ("project not found",), (404,),
        True, None,
        "Đăng ký project surge.sh tên đúng nhãn đầu của CNAME với PoC page.",
    ),
    _fp(
        "Shopify", ("myshopify.com",),
        ("Sorry, this shop is currently unavailable",), (404,),
        True, None,
        "Đăng ký store Shopify tên đúng nhãn đầu của CNAME và đặt trang PoC.",
    ),
    _fp(
        "Read the Docs", ("readthedocs.io",),
        ("unknown domain",), (404,),
        True, None,
        "Đăng ký project Read the Docs đúng tên và trỏ custom domain, đặt PoC page.",
    ),
    _fp(
        "Webflow", ("webflow.io",),
        ("The page you are looking for doesn't exist or has been moved",), (404,),
        True, None,
        "Đăng ký Webflow site với subdomain đúng tên nhãn đầu của CNAME, đặt PoC page.",
    ),
    _fp(
        "Tumblr", ("domains.tumblr.com",),
        ("Whatever you were looking for doesn't currently exist",), (404,),
        True, None,
        "Đăng ký blog Tumblr tên đúng nhãn đầu của CNAME với PoC page.",
    ),
    _fp(
        "Pantheon", ("pantheonsite.io",),
        ("The gods are wise, but do not know of the site which you seek",), (404,),
        True, None,
        "Tạo Pantheon site với tên đúng nhãn đầu của CNAME và deploy PoC page.",
    ),
    _fp(
        "CloudFront", ("cloudfront.net",),
        ("ERROR: The request could not be satisfied",), (403, 404),
        False, None,
        "CloudFront yêu cầu kiểm soát chứng chỉ/alias của distribution — CNAME treo "
        "NHƯNG không claim được nên không cấu thành takeover; đừng report.",
    ),
    _fp(
        "Firebase Hosting", ("web.app", "firebaseapp.com"),
        ("Site not found",), (404,),
        False, None,
        "Firebase bắt buộc xác minh quyền sở hữu domain trước khi gắn — CNAME treo "
        "không claim được nên không cấu thành takeover; đừng report.",
    ),
)

# dạng suffix vùng của S3 website endpoint ngoài us-east-1 (bucket.s3-website-eu-west-1...)
_S3_WEBSITE_RE = re.compile(r"\.s3-website[-.][a-z0-9-]+\.amazonaws\.com$")


def _match_suffix(cname: str, suffixes: tuple[str, ...]) -> str | None:
    """Suffix khớp CNAME (đã bỏ chấm cuối, lowercase) — so == suffix hoặc
    endswith('.'+suffix). Trả suffix hoặc None."""
    for suffix in suffixes:
        if cname == suffix or cname.endswith("." + suffix):
            return suffix
    return None


def _match_fingerprint(cname: str | None) -> "tuple[TakeoverFingerprint, str] | None":
    """(fingerprint, suffix khớp) từ CNAME — None nếu không nhận diện được.
    Suffix khớp: đuôi CNAME trùng literal, hoặc S3 website region endpoint
    (`bucket.s3-website-<region>.amazonaws.com`). Một nguồn sự thật cho cả
    fingerprint_for_cname lẫn claim_name."""
    c = (cname or "").strip().rstrip(".").lower()
    if not c:
        return None
    for fp in FINGERPRINTS:
        suffix = _match_suffix(c, fp.cname_suffixes)
        if suffix:
            return fp, suffix
    m = _S3_WEBSITE_RE.search(c)
    if m:
        return (next(fp for fp in FINGERPRINTS if fp.service == "S3"),
                m.group(0).lstrip("."))
    return None


def fingerprint_for_cname(cname: str | None) -> TakeoverFingerprint | None:
    """Service ứng với CNAME — None nếu không nằm trong bảng fingerprint."""
    m = _match_fingerprint(cname)
    return m[0] if m else None


def claim_name(cname: str | None) -> str:
    """Tên tài nguyên cần claim từ CNAME: phần TRƯỚC suffix service — nhãn đầu
    cho GitHub Pages (`someuser`), tên bucket cho S3 (`sub.victim.com`, có dấu
    chấm). CNAME lạ → nhãn đầu (fallback)."""
    c = (cname or "").strip().rstrip(".").lower()
    m = _match_fingerprint(c)
    if m is None:
        return c.split(".", 1)[0]
    _, suffix = m
    if c == suffix:
        return c
    return c[: -(len(suffix) + 1)]


def claim_host_for(target: str, cname: str | None) -> str:
    """Hostname cần claim = CNAME đã chuẩn hoá (bỏ chấm cuối)."""
    return (cname or "").strip().rstrip(".").lower() or target_host(target)


# ───────────────────────────── parse subzy ─────────────────────────────


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_VULN_LINE_RE = re.compile(r"\[\s*VULNERABLE\s*\]\s*-\s*(\S+)\s*\[\s*([^\]]+?)\s*\]")


def parse_subzy_output(stdout: str) -> list[dict]:
    """Output subzy → các match vulnerable: [{target, service, cname,
    fingerprint, http_status}]. Ưu tiên JSON của cờ --output (wrapper
    `subzy-run` cat ra stdout; JSON array hoặc JSONL); fallback dòng
    `[ VULNERABLE ] - host [ Service ]` (đã strip ANSI). Stdout rác → []."""
    text = stdout or ""
    stripped = text.strip()
    if stripped.startswith("["):
        try:
            raw = json.loads(stripped)
            if isinstance(raw, list):
                return _normalize_subzy(raw)
        except ValueError:
            pass
    if stripped.startswith("{"):
        out: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                out.extend(_normalize_subzy([obj]))
        if out:
            return out
    # fallback: bảng/dòng stdout của subzy
    plain = _ANSI_RE.sub("", text)
    return [
        {"target": m.group(1), "service": m.group(2).strip(), "cname": [],
         "fingerprint": "", "http_status": None}
        for m in _VULN_LINE_RE.finditer(plain)
    ]


def _normalize_subzy(items: list) -> list[dict]:
    out: list[dict] = []
    for it in items:
        if not isinstance(it, dict) or not it.get("vulnerable"):
            continue
        out.append({
            "target": str(it.get("subdomain") or "").strip(),
            "service": str(it.get("service") or it.get("engine") or "").strip(),
            "cname": [str(c) for c in (it.get("cname") or [])],
            "fingerprint": str(it.get("fingerprint") or ""),
            "http_status": it.get("http_status"),
        })
    return [x for x in out if x["target"]]


# ───────────────────────────── PoC page + xác nhận ─────────────────────────────


def identifying_username() -> str:
    """Username định danh của user (PoC page phải chứa để chứng minh "mình
    kiểm soát") — HACKERONE_USERNAME trước, INTIGRITI_USERNAME sau."""
    return (settings.hackerone_username or settings.intigriti_username or "").strip()


def new_takeover_token(candidate_id: int, nonce: str) -> str:
    """Token one-shot nhúng vào PoC page — lượt verify nào serve token đó ra
    qua subdomain chính là lượt đó kiểm soát (nonce xoay mỗi lần verify)."""
    nonce = re.sub(r"[^a-z0-9]", "", (nonce or "").lower()) or secrets.token_hex(6)
    return f"vulhunt-takeover-c{int(candidate_id)}-{nonce[:24]}"


def build_poc_page(username: str, token: str, target: str, service: str) -> str:
    """PoC page chứng minh kiểm soát subdomain — chứa username định danh +
    token, kèm lời khuyên report (takeover xác nhận thiếu PoC hoạt động bị
    đóng N/A và ảnh hưởng reput). Đơn giản, tĩnh, không script."""
    return f"""<!doctype html>
<html lang="vi">
<head><meta charset="utf-8"><title>Subdomain takeover PoC — {target}</title></head>
<body>
<h1>Subdomain takeover PoC</h1>
<p>Subdomain <strong>{target}</strong> (CNAME treo trên {service}) đang được
phục vụ bởi trang PoC của <strong>{username}</strong>.</p>
<p>Token kiểm soát: <code>{token}</code></p>
<p>Lưu ý cho tổ chức: đã xác nhận với trang PoC HOẠT ĐỘNG (được phục vụ trực
tiếp qua subdomain). Report takeover xác nhận mà thiếu PoC hoạt động thường bị
đóng N/A và ảnh hưởng reput người report — đừng report nếu chưa deploy được
PoC.</p>
</body>
</html>
"""


def confirming_profile(profile: ProbeProfile, username: str, token: str) -> bool:
    """PoC page đã được phục vụ QUA SUBDOMAIN? — body phải chứa CẢ username
    định danh LẪN token của lượt verify này (token chống cache/response cũ)."""
    if profile.error or profile.status == 0:
        return False
    return bool(username) and username in profile.body and token in profile.body


def probe_url(target: str) -> str:
    """URL probe: http:// + host trần (takeover thường không có TLS ở service
    bỏ hoang; CNAME của target đã được Scope Validator chặn ở bridge)."""
    return f"http://{target_host(target)}/"


def fingerprint_present(fp: TakeoverFingerprint, profile: ProbeProfile) -> bool:
    """Probe sandbox xác nhận service còn ở trạng thái bỏ hoang (status +
    marker trong body khớp bảng fingerprint)."""
    if profile.error or profile.status == 0:
        return False
    return profile.status in fp.statuses and any(m in profile.body for m in fp.markers)


@dataclass
class TakeoverAnalysis:
    """Kết quả phân tích confirm (giống RedirectAnalysis của #12): pattern log
    (mọi pattern), tín hiệu, score 0.0–1.0 và verdict theo ngưỡng."""

    patterns: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    score: float = 0.0
    verdict: str = "rejected"
    reason: str = ""
    error: str | None = None


# PoC được phục vụ qua subdomain là bằng chứng trực tiếp của kiểm soát
SCORE_POC_SERVED = 0.95


def analyze_confirmation(
    confirm: ProbeProfile, username: str, token: str
) -> TakeoverAnalysis:
    """Confirm probe → verdict: body chứa username + token = kiểm soát thật
    (verified); không = fingerprint match nhưng KHÔNG kiểm soát được →
    rejected `no_control` (đề bài: fingerprint match thôi không report)."""
    if confirm.error or confirm.status == 0:
        err = confirm.error or f"HTTP {confirm.status}"
        return TakeoverAnalysis(
            patterns=["probe_error"], score=0.0, verdict="rejected",
            reason=f"Không đọc được response confirm từ sandbox: {err}", error=err,
        )
    if confirming_profile(confirm, username, token):
        return TakeoverAnalysis(
            patterns=["poc_served"], signals=["poc_served"],
            score=SCORE_POC_SERVED, verdict="verified",
            reason=(
                "PoC page (chứa username + token) được phục vụ trực tiếp qua "
                "subdomain — kiểm soát đã được chứng minh"
            ),
        )
    return TakeoverAnalysis(
        patterns=["no_control"], score=0.0, verdict="rejected",
        reason=(
            "Fingerprint match NHƯNG subdomain không phục vụ PoC page — không "
            "chứng minh được kiểm soát (service có thể đã hạn chế claim); "
            "report lúc này sẽ bị đóng N/A"
        ),
    )


def manual_guidance(
    fp: TakeoverFingerprint, target: str, cname: str, username: str
) -> str:
    """Hướng dẫn xác minh tay khi chưa cấu hình hosting tự động: claim gì trên
    service nào, PoC page phải chứa gì, kèm cảnh báo report thiếu PoC → N/A."""
    claim = claim_host_for(target, cname)
    name = claim_name(cname)
    return (
        f"Fingerprint của {fp.service} còn khớp trên {target} (CNAME → {claim}) — "
        f"cần chứng minh kiểm soát trước khi report. Hướng dẫn: {fp.claim_guide} "
        f"PoC page PHẢI chứa username định danh `{username}` (kèm token one-shot); "
        "report takeover xác nhận mà thiếu PoC hoạt động sẽ bị đóng N/A và ảnh "
        "hưởng reput — cấu hình TAKEOVER_HOSTING để vòng verify tự deploy + confirm."
    )


def write_takeover_evidence(run_id: int, candidate_id: int, record: dict) -> str | None:
    """Ghi evidence takeover (probe + deploy + confirm + hướng dẫn) ra volume;
    path ghi vào candidates.verify_evidence_path. IO lỗi → None (không chết)."""
    try:
        base = Path(settings.evidence_dir) / str(run_id) / "takeover"
        base.mkdir(parents=True, exist_ok=True)
        path = base / f"{candidate_id:03d}.json"
        path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        return str(path)
    except OSError as exc:
        log.warning("run %d: không ghi được takeover evidence (%s)", run_id, exc)
        return None


# ───────────────────────────── SigV4 + deployers ─────────────────────────────
# Deploy chạy phía WORKER (như client interactsh, ADR-0004): đây là hạ tầng
# hosting của mình, không phải target — không qua egress proxy của sandbox.


class TakeoverHostingError(RuntimeError):
    """Deploy/claim hosting thất bại — fingerprint match nhưng không kiểm soát
    được qua hosting khả dụng → pipeline kết luận rejected `claim_failed`."""


@dataclass
class DeployResult:
    url: str          # URL PoC (luôn là http://<host nạn nhân>/)
    provider: str
    detail: dict = field(default_factory=dict)


DeployCallable = Callable[[str, str, str], Awaitable[DeployResult]]


def sigv4_headers(
    method: str,
    host: str,
    path: str,
    body: bytes,
    region: str,
    access_key: str,
    secret_key: str,
    now: datetime | None = None,
    service: str = "s3",
    query: str = "",
) -> dict:
    """AWS SigV4 tối giản (stdlib) — đủ cho S3 PutObject/PutBucketWebsite;
    `now` truyền vào để test xác định. Trả headers x-amz-* + Authorization
    (Host do client đặt)."""
    t = now or datetime.now(timezone.utc)
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()

    canonical_headers = (
        f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    )
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = (
        f"{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n"
        f"{payload_hash}"
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )

    def _hmac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = _hmac(
        _hmac(_hmac(_hmac(f"AWS4{secret_key}".encode(), date_stamp), region), service),
        "aws4_request",
    )
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }


class GitHubPagesDeployer:
    """Deploy PoC page lên GitHub Pages (REST API) — account `owner` PHẢI khớp
    nhãn đầu của CNAME (`<label>.github.io`): lệch là không kiểm soát được →
    TakeoverHostingError. Đủ 3 việc: repo user-site, index.html + CNAME, bật
    Pages."""

    provider = "github-pages"

    def __init__(self, token: str, owner: str, http: httpx.AsyncClient | None = None):
        self._owner = (owner or "").strip().lower()
        self._http = http or httpx.AsyncClient(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    def _err(self, what: str, res: httpx.Response) -> TakeoverHostingError:
        return TakeoverHostingError(
            f"GitHub Pages ({what}): HTTP {res.status_code} {res.text[:200]}"
        )

    async def _put_file(self, repo: str, path: str, content: str, message: str) -> None:
        sha: str | None = None
        r = await self._http.get(f"/repos/{self._owner}/{repo}/contents/{path}")
        if r.status_code == 200:
            sha = (r.json() or {}).get("sha")
        elif r.status_code != 404:
            raise self._err(f"đọc {path}", r)
        data: dict = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": "main",
        }
        if sha:
            data["sha"] = sha
        r = await self._http.put(f"/repos/{self._owner}/{repo}/contents/{path}", json=data)
        if r.status_code not in (200, 201):
            raise self._err(f"đẩy {path}", r)

    async def deploy(self, claim_host: str, page_html: str, victim_host: str) -> DeployResult:
        label = claim_name(claim_host)
        if label != self._owner:
            raise TakeoverHostingError(
                f"GitHub Pages: hostname cần claim `{claim_host}` không khớp account "
                f"đã cấu hình `{self._owner}` — kiểm soát không chứng minh được qua "
                "hosting này (đúng luật: chỉ report khi PoC hoạt động)"
            )
        repo = f"{self._owner}.github.io"
        try:
            r = await self._http.get(f"/repos/{self._owner}/{repo}")
            if r.status_code == 404:
                r = await self._http.post(
                    "/user/repos",
                    json={"name": repo, "private": False, "has_issues": False,
                          "has_wiki": False, "auto_init": False},
                )
                if r.status_code not in (201, 202):
                    raise self._err("tạo repo claim", r)
            elif r.status_code != 200:
                raise self._err("kiểm tra repo", r)
            await self._put_file(repo, "index.html", page_html, "vulhunt takeover PoC")
            await self._put_file(repo, "CNAME", f"{victim_host}\n", "vulhunt takeover PoC domain")
            r = await self._http.post(
                f"/repos/{self._owner}/{repo}/pages",
                json={"source": {"branch": "main", "path": "/"}},
            )
            if r.status_code not in (201, 409):  # 409 = đã bật
                raise self._err("bật Pages", r)
        except httpx.HTTPError as exc:
            raise TakeoverHostingError(f"GitHub Pages: lỗi mạng: {exc}") from exc
        return DeployResult(
            url=f"http://{victim_host}/",
            provider=self.provider,
            detail={"owner": self._owner, "repo": repo, "claim_host": claim_host},
        )


class S3Deployer:
    """Deploy PoC page lên S3 (PutObject SigV4, httpx sync trong thread) —
    bucket tên ĐÚNG phần đầu của CNAME (= host nạn nhân, có dấu chấm).

    3 bước để confirm probe thấy PoC ở `/` bất kể victim CNAME trỏ endpoint
    nào: (1) object KEY RỖNG — REST endpoint (dispatch theo Host) phục vụ ngay
    tại `/` (best-effort — server từ chối key rỗng thì không chết); (2)
    `index.html` public-read; (3) PutBucketWebsite bật static hosting
    (IndexDocument) — website endpoint phục vụ `index.html` tại `/`."""

    provider = "s3"

    def __init__(self, access_key: str, secret_key: str, region: str,
                 http: httpx.Client | None = None):
        self._ak, self._sk, self._region = access_key, secret_key, region
        self._http = http or httpx.Client(timeout=30.0)

    def aclose(self) -> None:
        self._http.close()

    def _put(self, bucket: str, path: str, body: bytes, query: str = "",
             content_type: str = "text/html; charset=utf-8") -> httpx.Response:
        host = f"{bucket}.s3.amazonaws.com"
        headers = sigv4_headers(
            "PUT", host, path, body, self._region, self._ak, self._sk, query=query
        )
        headers["x-amz-acl"] = "public-read"
        headers["Content-Type"] = content_type
        url = f"http://{host}{path}" + (f"?{query}" if query else "")
        return self._http.put(url, content=body, headers=headers)

    def deploy_sync(self, bucket: str, page_html: str, victim_host: str) -> DeployResult:
        bucket = bucket.rstrip(".").lower()
        host = f"{bucket}.s3.amazonaws.com"
        body = page_html.encode()
        notes: dict = {"bucket": bucket, "host": host, "region": self._region}

        # (1) key rỗng — best effort
        try:
            r = self._put(bucket, "/", body)
            notes["root_object"] = (
                "ok" if r.status_code == 200 else f"HTTP {r.status_code} (bỏ qua)"
            )
        except httpx.HTTPError as exc:
            notes["root_object"] = f"lỗi mạng (bỏ qua): {exc}"

        # (2) index.html — bắt buộc
        try:
            r = self._put(bucket, "/index.html", body)
        except httpx.HTTPError as exc:
            raise TakeoverHostingError(f"S3: lỗi mạng: {exc}") from exc
        if r.status_code != 200:
            raise TakeoverHostingError(
                f"S3 (tạo bucket + index.html {bucket}): "
                f"HTTP {r.status_code} {r.text[:200]}"
            )

        # (3) website hosting — bắt buộc cho website endpoint
        config = (
            '<WebsiteConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            "<IndexDocument><Suffix>index.html</Suffix></IndexDocument>"
            "</WebsiteConfiguration>"
        ).encode()
        try:
            r = self._put(bucket, "/", config, query="website=",
                          content_type="application/xml")
        except httpx.HTTPError as exc:
            raise TakeoverHostingError(f"S3: lỗi mạng (website config): {exc}") from exc
        if r.status_code != 200:
            raise TakeoverHostingError(
                f"S3 (bật website hosting {self._bucket}): "
                f"HTTP {r.status_code} {r.text[:200]}"
            )
        return DeployResult(
            url=f"http://{victim_host}/", provider=self.provider, detail=notes
        )

    async def deploy(self, claim_host: str, page_html: str, victim_host: str) -> DeployResult:
        return await asyncio.to_thread(
            self.deploy_sync, claim_name(claim_host), page_html, victim_host
        )


def configure_hosting(fp: TakeoverFingerprint) -> tuple[DeployCallable | None, str | None]:
    """Hosting khả dụng cho fingerprint theo cấu hình hiện hành — trả
    (deploy_callable, lý_do_không_khả_dụng). Đúng một trong hai là None."""
    provider = (settings.takeover_hosting or "").strip().lower()
    if not provider:
        return None, (
            "chưa cấu hình hosting chứng minh kiểm soát (TAKEOVER_HOSTING)"
        )
    if fp.hosting is None:
        return None, (
            f"{fp.service} không claim tự động qua hosting khả dụng — chỉ xác minh tay"
        )
    if fp.hosting != provider:
        return None, (
            f"{fp.service} claim tự động qua '{fp.hosting}', không phải '{provider}'"
        )
    if provider == "github-pages":
        if not settings.github_token or not settings.github_username:
            return None, (
                "TAKEOVER_HOSTING=github-pages nhưng thiếu GITHUB_TOKEN/GITHUB_USERNAME"
            )
        deployer = GitHubPagesDeployer(settings.github_token, settings.github_username)

        async def deploy(claim_host: str, page_html: str, victim_host: str) -> DeployResult:
            try:
                return await deployer.deploy(claim_host, page_html, victim_host)
            finally:
                await deployer.aclose()

        return deploy, None
    if provider == "s3":
        if not settings.aws_access_key_id or not settings.aws_secret_access_key:
            return None, (
                "TAKEOVER_HOSTING=s3 nhưng thiếu AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY"
            )
        deployer = S3Deployer(
            settings.aws_access_key_id, settings.aws_secret_access_key,
            settings.aws_region or "us-east-1",
        )

        async def deploy(claim_host: str, page_html: str, victim_host: str) -> DeployResult:
            try:
                return await deployer.deploy(claim_host, page_html, victim_host)
            finally:
                deployer.aclose()

        return deploy, None
    return None, f"TAKEOVER_HOSTING lạ: '{provider}' (dùng github-pages hoặc s3)"


# ───────────────────────────── detection pipeline ─────────────────────────────
# Row + INSERT dùng CHÍNH shape dedupe (run_id, target, class, param) của
# detect.py — không lặp danh sách cột/SQL ở đây (thêm cột candidates chỉ sửa 1 nơi)


def _severity(value) -> str:
    """Chuẩn hoá severity từ output tool — lạ/không có thì 'high' (takeover
    xác nhận thường high; candidate còn qua vòng verify nữa)."""
    try:
        return validate_severity(value)
    except ValueError:
        return "high"


def build_nuclei_takeover_args(
    rate_limit_rps: float | None, ident: dict[str, str]
) -> list[str]:
    """Args cho nuclei CHỈ templates takeover (tag `takeover`, gồm cả template
    dns kiểu CNAME của thư mục takeovers) — throttle + header định danh như
    Detection Phase chính."""
    args = [
        "-silent", "-nc", "-j",
        "-t", settings.nuclei_templates_dir,
        "-tags", "takeover",
        "-etags", "headless",
    ]
    if rate_limit_rps and rate_limit_rps > 0:
        n = str(max(1, round(rate_limit_rps)))
        args += ["-rl", n, "-c", n]
    for name, value in (ident or {}).items():
        args += ["-H", f"{name}: {value}"]
    return args


async def run_takeover_detection(
    pool: asyncpg.Pool,
    run: asyncpg.Record | dict,
    tool_runner=None,
) -> dict:
    """Detection lớp takeover của 1 Run — dùng CNAME đã thu từ dnsx (Recon 1):
    subzy (wrapper `subzy-run` trong tooling image, JSON qua --output) + nuclei
    templates takeovers. Mỗi match vulnerable → Candidate class `takeover`
    (dedupe theo asset — match đầu tiên thắng). Tool lỗi coi như không phát
    hiện gì; target ngoài Scope bị chặn như mọi Tool Execution."""
    run_id = run["id"]
    snapshot = run["scope_snapshot"]
    if isinstance(snapshot, str):
        snapshot = json.loads(snapshot)
    ctx: ToolContext = build_context(
        run_id,
        run["rate_limit_rps"],
        run["ident_header_name"],
        run["ident_header_value"],
        snapshot,
        bool(run["allow_non_prod"]),
    )

    async with pool.acquire() as conn:
        assets = await conn.fetch(
            "SELECT host, cname FROM recon_assets "
            "WHERE run_id = $1 AND coalesce(cname, '') <> ''",
            run_id,
        )
    if not assets:
        await add_log(
            pool, run_id, "Takeover: không có host nào mang CNAME — bỏ qua lớp takeover"
        )
        return {"candidates": 0, "blocked": 0}

    hosts = unique_hosts([r["host"] for r in assets])
    allowed, blocked = await filter_scope(pool, ctx, hosts, "subzy")
    await add_log(
        pool, run_id,
        f"Takeover: {len(allowed)}/{len(hosts)} host mang CNAME trong Scope "
        f"(validator chặn {blocked}) — subzy + nuclei takeovers",
    )
    if not allowed:
        return {"candidates": 0, "blocked": blocked}
    host_input = "\n".join(allowed)

    # ── subzy: fingerprint can-i-take-over-xyz qua wrapper (JSON --output) ──
    res = await execute_tool(
        pool, ctx, "subzy-run", [], stdin=host_input, runner=tool_runner
    )
    subzy_hits = parse_subzy_output(res.stdout) if res.exit_code == 0 else []
    if res.exit_code != 0:
        await add_log(
            pool, run_id, f"subzy exit {res.exit_code} — không có match từ subzy",
            level="error",
        )

    # ── nuclei: chỉ templates takeover ──
    res2 = await execute_tool(
        pool, ctx, "nuclei",
        build_nuclei_takeover_args(run["rate_limit_rps"], ctx.ident),
        stdin=host_input, runner=tool_runner,
    )
    nuclei_findings = parse_nuclei_jsonl(res2.stdout) if res2.exit_code == 0 else []

    rows: list[CandidateRow] = []
    seen: set[str] = set()
    allowed_hosts = {target_host(h) for h in allowed}

    async def add_candidate(
        raw_target: str, source: str, service: str,
        severity: str, matcher: str, raw_finding: dict,
        recheck_scope: bool = False,
    ) -> None:
        nonlocal blocked
        if not raw_target:
            return
        target = f"http://{target_host(raw_target)}"
        if recheck_scope:  # matched-at của nuclei có thể khác host vào — phòng hờ
            ok, n = await filter_scope(pool, ctx, [target], source)
            blocked += n
            if not ok:
                return
        elif target_host(target) not in allowed_hosts:
            # hit ngoài danh sách host đã validate (stdout lạ / stdout trôi) — bỏ
            return
        if target in seen:
            return
        seen.add(target)
        rows.append(CandidateRow(
            run_id=run_id,
            target=target,
            cls="takeover",
            param="",
            template_id=f"takeover/{source}" if source == "subzy" else str(
                raw_finding.get("template-id") or f"takeover/{source}"
            ),
            title=service or str(raw_finding.get("info", {}).get("name") or "Takeover"),
            severity=_severity(severity),
            matcher_name=matcher,
            status="new",
            evidence_path=write_evidence(run_id, len(rows) + 1, {
                "template-id": f"takeover/{source}", **raw_finding,
            }),
        ))

    for hit in subzy_hits:
        # target subzy chính là host vào đã validate — không cần recheck
        await add_candidate(
            hit["target"], "subzy", hit["service"], "high",
            hit["fingerprint"] or "fingerprint",
            {"template-id": "takeover/subzy", **hit},
        )
    for finding in nuclei_findings:
        info = finding.get("info") or {}
        await add_candidate(
            str(finding.get("matched-at") or finding.get("host") or ""),
            "nuclei", str(info.get("name") or ""),
            str(info.get("severity") or "high"),
            str(finding.get("matcher-name") or ""),
            finding,
            recheck_scope=True,
        )

    await _insert_candidates(pool, rows)
    await add_log(
        pool, run_id,
        f"Takeover: {len(rows)} Candidate từ subzy ({len(subzy_hits)} match) + "
        f"nuclei ({len(nuclei_findings)} match) — đã dedupe, chờ vòng xác minh "
        "(fingerprint match chưa đủ — phải chứng minh kiểm soát)",
    )
    return {"candidates": len(rows), "blocked": blocked}


# ───────────────────────────── verification pipeline ─────────────────────────────


_SET_STATUS_SQL = (
    f"UPDATE candidates SET status = $2 WHERE id = $1 RETURNING {CANDIDATE_COLS}"
)
# needs_manual KHÔNG phải verdict — xoá sạch score/reject cũ (nếu có) để UI
# không hiện confidence của lần verify khác
_NEEDS_MANUAL_SQL = (
    f"UPDATE candidates SET status = $2, confidence = NULL, "
    f"confidence_threshold = NULL, reject_reason = NULL, verify_evidence_path = $3, "
    f"verify_session_id = $4, baseline_session_id = $5 "
    f"WHERE id = $1 RETURNING {CANDIDATE_COLS}"
)
_VERDICT_SQL = (
    f"UPDATE candidates SET status = $2, confidence = $3, confidence_threshold = $4, "
    f"reject_reason = $5, verify_evidence_path = $6, verify_session_id = $7, "
    f"baseline_session_id = $8 WHERE id = $1 RETURNING {CANDIDATE_COLS}"
)


def _unread_profile(reason: str) -> ProbeProfile:
    return ProbeProfile(
        status=0, headers={}, content_type="", body_length=0, body="", error=reason
    )


async def run_takeover_verification(
    pool: asyncpg.Pool,
    candidate: dict,
    probe: ProbeCallable | None = None,
    deploy: DeployCallable | None = None,
    threshold: float | None = None,
    wait_s: float | None = None,
    poll_s: float | None = None,
) -> dict:
    """Trọn vòng verify 1 Candidate class `takeover` (#14):

      fingerprint probe (sandbox) → hosting khả dụng? → soạn PoC page chứa
      username định danh + token one-shot → deploy → confirm probe (sandbox,
      poll trong cửa sổ wait) → PoC được phục vụ QUA SUBDOMAIN = kiểm soát
      chứng minh → Finding (verified); ngược lại rejected / needs_manual.

    Contract lỗi giống mọi vòng verify: target bị chặn scope → ProbeBlocked
    (trả lifecycle về cũ); lỗi môi trường sandbox → RuntimeError. Deploy lỗi
    là DỮ LIỆU verify (không kiểm soát được) → rejected `claim_failed`, không
    bao giờ verdict oan thành verified.
    """
    candidate_id = candidate["id"]
    run_id = candidate["run_id"]
    threshold = float(
        settings.verify_confidence_threshold if threshold is None else threshold
    )
    wait_s = float(settings.takeover_verify_wait_s if wait_s is None else wait_s)
    poll_s = float(settings.takeover_verify_poll_s if poll_s is None else poll_s)
    target = candidate["target"]
    host = target_host(target)
    username = identifying_username()
    prev_status = candidate.get("status") or "new"

    async def _update(sql: str, *params) -> dict | None:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(sql, *params)
        return dict(row) if row else None

    def _summary(**kw) -> dict:
        deploy_detail = kw.get("deploy_detail")
        return {
            "candidate_id": candidate_id,
            "run_id": run_id,
            "verdict": kw.get("verdict", "rejected"),
            "score": round(float(kw.get("score", 0.0)), 4),
            "threshold": threshold,
            "reason": kw.get("reason", ""),
            "signals": kw.get("signals", []),
            "patterns": kw.get("patterns", []),
            "cname": cname,
            "service": fp.service if fp else None,
            "claim_host": claim,
            "poc_url": kw.get("poc_url") or (deploy_detail or {}).get("url"),
            "token": kw.get("token"),
            "username": username,
            "deploy": deploy_detail,
            "guidance": kw.get("guidance"),
            "evidence_path": evidence_path,
            "baseline_session_id": base_sid,
            "verify_session_id": confirm_sid,
        }

    async def _finish_local(
        verdict: str, patterns: list[str], reason: str,
        guidance: str | None = None, score: float = 0.0,
        fp_profile: ProbeProfile | None = None,
    ) -> dict:
        """Kết thúc KHÔNG qua probe/deploy (thiếu username, không cname…) —
        verdict 'needs_manual' update SQL riêng, còn lại là rejected."""
        nonlocal evidence_path
        evidence_path = write_takeover_evidence(run_id, candidate_id, _evidence_record(
            verdict=verdict, patterns=patterns, signals=[], reason=reason,
            score=score, guidance=guidance, fp_profile=fp_profile,
        ))
        if verdict == "needs_manual":
            await _update_needs_manual(confirm_sid=None, baseline_sid=None)
        else:
            await _update_verdict(verdict, score=score, reason=reason,
                                  confirm_sid=None, baseline_sid=None)
        await add_log(
            pool, run_id,
            f"Verify takeover Candidate #{candidate_id}: {verdict} · "
            f"patterns: {', '.join(patterns) or '—'}"
            + (f" · evidence: {evidence_path}" if evidence_path else ""),
        )
        return _summary(
            verdict=verdict, score=score, reason=reason, patterns=patterns,
            guidance=guidance,
        )

    async def _update_needs_manual(confirm_sid: int | None, baseline_sid: int | None) -> None:
        await _update(_NEEDS_MANUAL_SQL, candidate_id, "needs_manual",
                      evidence_path, confirm_sid, baseline_sid)

    async def _update_verdict(verdict: str, score: float, reason: str,
                              confirm_sid: int | None, baseline_sid: int | None) -> None:
        await _update(
            _VERDICT_SQL, candidate_id, verdict, score, threshold,
            reason if verdict == "rejected" else None,
            evidence_path, confirm_sid, baseline_sid,
        )

    # placeholder — cname/fp/claim gán sau khi đọc DB, dùng trong _summary
    cname: str | None = None
    fp: "TakeoverFingerprint | None" = None
    claim: str | None = None
    evidence_path: str | None = None
    base_sid: int | None = None
    confirm_sid: int | None = None

    def _evidence_record(
        *, verdict: str, patterns: list[str] | None = None,
        signals: list[str] | None = None, reason: str = "",
        score: float = 0.0, guidance: str | None = None,
        fp_profile: ProbeProfile | None = None,
        confirm_profile: ProbeProfile | None = None,
        poc: dict | None = None, deploy_detail: dict | None = None,
    ) -> dict:
        patterns, signals = patterns or [], signals or []
        return {
            "schema": "vulhunt.takeover-evidence/1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "candidate_id": candidate_id,
            "run_id": run_id,
            "class": candidate.get("class"),
            "target": target,
            "cname": cname,
            "threshold": threshold,
            "fingerprint": None if fp is None else {
                "service": fp.service,
                "markers": list(fp.markers),
                "statuses": list(fp.statuses),
                "claim_host": claim,
                "probe": fp_profile.to_dict() if fp_profile else None,
                "session_id": base_sid,
            },
            "poc": poc,
            "deploy": deploy_detail,
            "confirm": confirm_profile.to_dict() if confirm_profile else None,
            "baseline_session_id": base_sid,
            "verify_session_id": confirm_sid,
            "guidance": guidance,
            "analysis": {
                "signals": signals,
                "patterns": patterns,  # pattern log (kể cả khi rejected)
                "score": score,
                "verdict": verdict,
                "reason": reason,
                "wait_s": wait_s,
                "poll_s": poll_s,
            },
        }

    # ── username định danh: PoC page phải chứa — thiếu thì dừng ngay ──
    if not username:
        return await _finish_local(
            "needs_manual", ["missing_username"],
            "Chưa cấu hình username platform (HACKERONE_USERNAME/INTIGRITI_USERNAME) "
            "— PoC page chứng minh kiểm soát phải chứa username định danh của bạn",
            guidance="Điền HACKERONE_USERNAME (hoặc INTIGRITI_USERNAME) vào .env rồi verify lại.",
        )

    # ── CNAME từ Recon 1 ──
    async with pool.acquire() as conn:
        rec = await conn.fetchrow(
            "SELECT host, cname FROM recon_assets WHERE run_id = $1 AND host = $2",
            run_id, host,
        )
    cname = (rec["cname"] if rec else None) or None
    if not cname:
        return await _finish_local(
            "rejected", ["no_cname"],
            f"Không tìm thấy CNAME của {host} trong recon_assets của Run — "
            "detection lớp takeover chỉ chạy trên host mang CNAME",
        )

    fp = fingerprint_for_cname(cname)
    if fp is None:
        return await _finish_local(
            "needs_manual", ["unknown_service"],
            f"CNAME {cname} không nằm trong bảng fingerprint — không tự xác minh "
            "được service; xem evidence detection để biết fingerprint subzy báo",
            guidance=(
                f"Tự kiểm tra {probe_url(target)}: đọc fingerprint trong evidence "
                "Detection Phase, tra can-i-take-over-xyz, claim theo service rồi "
                "deploy PoC page chứa username `"
                f"{username}` trước khi report."
            ),
        )
    claim = claim_host_for(target, cname)

    if probe is None:
        run = await sandbox.resolve_run(pool, run_id)
        if run is None:
            raise ValueError("không có Run nào — không thể xác minh qua sandbox")

        async def probe(script: str, target_: str, _run: asyncpg.Record = run) -> dict:
            return await sandbox.run_verify_session(pool, _run, script, target_)

    await _update(_SET_STATUS_SQL, candidate_id, "verifying")

    async def _run_probe(script: str) -> dict:
        res = await probe(script, target)
        if res.get("status") == "blocked":
            await _update(_SET_STATUS_SQL, candidate_id, prev_status)
            raise ProbeBlocked(res.get("reason") or "target bị chặn tại bridge")
        if res.get("status") == "error":
            await _update(_SET_STATUS_SQL, candidate_id, prev_status)
            raise RuntimeError(
                f"lỗi môi trường sandbox: {res.get('reason') or res.get('stderr', '')}"
            )
        return res

    async def _finish_full(**kw) -> dict:
        nonlocal evidence_path
        evidence_path = write_takeover_evidence(run_id, candidate_id, _evidence_record(**kw))
        verdict = kw["verdict"]
        if verdict == "needs_manual":
            await _update_needs_manual(confirm_sid=confirm_sid, baseline_sid=base_sid)
        else:
            await _update_verdict(
                verdict, score=kw.get("score", 0.0),
                reason=kw.get("reason") or "",
                confirm_sid=confirm_sid, baseline_sid=base_sid,
            )
        await add_log(
            pool, run_id,
            f"Verify takeover Candidate #{candidate_id}: {verdict} "
            f"({fp.service}, CNAME {cname})"
            f" · patterns: {', '.join(kw.get('patterns') or []) or '—'}"
            + (f" · evidence: {evidence_path}" if evidence_path else ""),
        )
        return _summary(
            verdict=verdict, score=kw.get("score", 0.0), reason=kw.get("reason", ""),
            signals=kw.get("signals") or [], patterns=kw.get("patterns") or [],
            poc_url=kw.get("poc_url"), token=kw.get("token"),
            deploy_detail=kw.get("deploy_detail"), guidance=kw.get("guidance"),
        )

    # ── 1. fingerprint probe trong sandbox: service còn bỏ hoang? ──
    fp_res = await _run_probe(build_probe_script(probe_url(target)))
    base_sid = fp_res.get("session_id")
    fp_profile = parse_probe(fp_res.get("stdout") or "")
    if fp_profile is None or not fingerprint_present(fp, fp_profile):
        detail = (
            f"HTTP {fp_profile.status}, body không mang marker nào của {fp.service}"
            if fp_profile else "không đọc được profile response từ sandbox"
        )
        return await _finish_full(
            verdict="rejected", patterns=["fingerprint_gone"], score=0.0,
            reason=(
                f"Fingerprint {fp.service} không còn khớp trên {host} ({detail}) — "
                "service có thể đã được gắn lại; không phải takeover"
            ),
            fp_profile=fp_profile,
        )

    # ── 2. hosting khả dụng? — chưa có thì dừng ở needs_manual (#14) ──
    deploy_fn = deploy
    unavailable: str | None = None
    if deploy_fn is None:
        deploy_fn, unavailable = configure_hosting(fp)
    if deploy_fn is None:
        guidance = manual_guidance(fp, target, cname, username)
        if unavailable:
            guidance = f"Lý do chưa tự động xác minh được: {unavailable}. " + guidance
        return await _finish_full(
            verdict="needs_manual", patterns=["manual_verification_required"],
            score=0.0, reason=guidance, guidance=guidance,
            fp_profile=fp_profile,
        )

    # ── 3. soạn PoC page (username + token one-shot) → deploy ──
    token = new_takeover_token(candidate_id, new_nonce())
    page = build_poc_page(username, token, target, fp.service)
    try:
        deploy_result = await deploy_fn(claim, page, host)
    except TakeoverHostingError as exc:
        return await _finish_full(
            verdict="rejected", patterns=["claim_failed"], score=0.0,
            reason=(
                f"Fingerprint match NHƯNG không claim/kiểm soát được qua hosting "
                f"khả dụng: {exc} — không có PoC hoạt động thì không report"
            ),
            fp_profile=fp_profile,
            poc={"username": username, "token": token, "page": page},
        )
    except Exception as exc:  # deployer lạ — vẫn là "không kiểm soát được"
        return await _finish_full(
            verdict="rejected", patterns=["claim_failed"], score=0.0,
            reason=(
                f"Deploy PoC lỗi không lường trước: {exc} — coi như không "
                "kiểm soát được, KHÔNG verdict oan"
            ),
            fp_profile=fp_profile,
            poc={"username": username, "token": token, "page": page},
        )
    deploy_detail = {
        "provider": deploy_result.provider,
        "url": deploy_result.url,
        "detail": deploy_result.detail,
    }

    # ── 4. confirm probe: subdomain có phục vụ đúng PoC page không? ──
    confirm_profile: ProbeProfile | None = None
    confirm_res: dict | None = None
    end = time.monotonic() + wait_s
    while True:
        confirm_res = await _run_probe(build_probe_script(probe_url(target)))
        confirm_sid = confirm_res.get("session_id")
        confirm_profile = parse_probe(confirm_res.get("stdout") or "")
        if confirm_profile is not None and confirming_profile(
            confirm_profile, username, token
        ):
            break
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(poll_s, remaining) if poll_s > 0 else 0.01)
    if confirm_profile is None:
        confirm_profile = _unread_profile(
            f"stdout confirm không đọc được: {(confirm_res or {}).get('stdout', '')[:200]}"
        )

    analysis = analyze_confirmation(confirm_profile, username, token)
    return await _finish_full(
        verdict=analysis.verdict,
        patterns=analysis.patterns,
        signals=analysis.signals,
        score=analysis.score,
        reason=analysis.reason,
        fp_profile=fp_profile,
        confirm_profile=confirm_profile,
        poc={"username": username, "token": token, "page": page},
        deploy_detail=deploy_detail,
    )
