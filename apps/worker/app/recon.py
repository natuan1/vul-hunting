"""Recon Phase — chuỗi cứng 2 giai đoạn:

Giai đoạn 1 (ticket #8): subfinder → amass → [Scope Validator] → dnsx → naabu → httpx
Giai đoạn 2 (ticket #9): katana (crawl live host) → gau/waymore (URL lịch sử)
                         → gf-slice (phân loại URL theo class lỗ hổng)

- discovery (subfinder/amass) là passive: chỉ được chạy trên domain gốc lấy từ
  Scope snapshot của Run — root được validate trước khi chạy;
- MỌI host phát hiện được phải qua ToolContext.validate() trước khi bước nào
  đó chạm tới (dnsx resolve, naabu quét cổng, httpx gửi HTTP) — host ngoài
  scope bị audit + loại ngay từ đầu, không có request nào đi ra;
- CNAME (dnsx) lưu cột riêng trên recon_assets — nuôi lớp subdomain takeover
  (ticket #14);
- subdomain xuất hiện trên recon_assets ngay sau bước lọc, live host cập nhật
  sau httpx — UI đếm tăng dần trong lúc Run chạy;
- giai đoạn 2 chỉ chạm tới live host đã qua validator (katana crawl, throttle
  theo rate limit của Run); gau/waymore là passive archive (không gửi traffic
  tới target) nhưng URL tìm được vẫn lọc qua Scope Validator trước khi lên
  bảng recon_urls — URL + params + nhãn class từ gf, nguồn mục tiêu của
  Detection Phase.
"""

import json
import logging
import re
from collections import namedtuple
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import asyncpg

from .config import settings
from .scope_validator import target_host
from .tools import (
    TargetBlockedError,
    ToolContext,
    add_log,
    build_context,
    execute_tool,
    filter_scope,
    jsonl_lines,
)

log = logging.getLogger("recon")

# hostname chỉ gồm [a-z0-9._-] (cho phép * vì output tool có thể chứa wildcard) —
# dòng khác (vd preamble 'Session Scope'/'FQDN:' của amass) không phải host
_HOSTNAME_RE = re.compile(r"^[a-z0-9._*-]+$")

# dòng URL hợp lệ cho output của katana/gau/waymore (1 URL/dòng)
_URL_LINE_RE = re.compile(r"^https?://\S+$", re.IGNORECASE)


DISCOVERY_TOOLS = ("subfinder", "amass")
PROBE_TOOLS = ("dnsx", "naabu", "httpx")
RECON_CHAIN = DISCOVERY_TOOLS + PROBE_TOOLS

# giai đoạn 2 (ticket #9): katana crawl live host, gau/waymore thu URL lịch sử
# (Wayback + Common Crawl + OTX), gf-slice phân loại URL theo pattern ~/.gf
ARCHIVE_TOOLS = ("gau", "waymore")
GF_SLICE_TOOL = "gf-slice"  # wrapper trong tooling image: dùng chính engine gf

# độ sâu crawl mặc định của katana — điều độ, tôn trọng rate limit của Run
_KATANA_DEPTH = 3

# amass v5 ghi kết quả vào FILE chứ không stdout — mount volume recon_data vào
# container để harvest file JSON/txt sau khi chạy; thiếu volume thì chỉ đọc stdout
_AMASS_OUT_MOUNT = "/out"


def _discovery_args(tool: str, root: str, run_id: int) -> tuple[list[str], list[str] | None]:
    """(args, docker_args) cho từng tool discovery trên 1 domain gốc."""
    if tool == "subfinder":
        return ["-d", root, "-json", "-silent"], None
    if tool == "amass":
        args = ["enum", "-passive", "-d", root, "-nocolor"]
        if settings.recon_volume:
            # -u 0:0: container chạy user thường, volume thuộc worker (root)
            return (
                args + ["-oA", f"{_AMASS_OUT_MOUNT}/amass-{run_id}-{root}"],
                ["-v", f"{settings.recon_volume}:{_AMASS_OUT_MOUNT}", "-u", "0:0"],
            )
        return args, None
    raise ValueError(f"tool discovery không hỗ trợ: {tool}")


def _harvest_amass_files(run_id: int, root: str) -> list[str]:
    """Đọc file output do amass ghi vào volume (nếu có) — trả về host tìm thấy."""
    base = Path(settings.artifacts_dir) / str(run_id)
    hosts: list[str] = []
    for path in sorted(base.glob(f"amass-{run_id}-{root}.*")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if text.lstrip()[:1] in ("[", "{"):
            try:
                data = json.loads(text)
                items = data if isinstance(data, list) else [data]
                for obj in items:
                    if isinstance(obj, dict):
                        name = obj.get("name") or obj.get("host")
                        if name:
                            hosts.append(str(name))
            except ValueError:
                continue
        else:
            hosts.extend(parse_host_lines(text))
    return unique_hosts(hosts)


# ───────────────────────────── seam thuần (có test) ─────────────────────────────


def recon_roots(snapshot: list[dict]) -> list[str]:
    """Domain gốc để enumerate: base của wildcard + host của asset URL tường minh.

    Thứ tự theo snapshot (wildcard trước — snapshot ORDER BY eligible_for_bounty
    DESC), trùng nhau chỉ lấy một lần. Asset không phải host (app store, OTHER) bỏ.
    """
    roots: list[str] = []
    for asset in snapshot:
        if (asset.get("asset_type") or "") not in ("URL", "WILDCARD"):
            continue
        host = target_host(asset.get("asset_identifier") or "")
        if not host:
            continue
        if host.startswith("*."):
            host = host[2:]
        if host and host not in roots:
            roots.append(host)
    return roots


def explicit_hosts(snapshot: list[dict]) -> list[str]:
    """Host asset tường minh (không wildcard) — được đưa thẳng vào danh sách
    probe (chúng đã trong Scope), ngoài việc làm root cho discovery."""
    hosts: list[str] = []
    for asset in snapshot:
        if (asset.get("asset_type") or "") not in ("URL",):
            continue
        host = target_host(asset.get("asset_identifier") or "")
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def unique_hosts(hosts: list[str]) -> list[str]:
    """Chuẩn hoá + dedupe, giữ thứ tự xuất hiện đầu tiên."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in hosts:
        host = target_host(raw)
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def parse_host_lines(stdout: str) -> list[str]:
    """Output dạng thẳng (1 host/dòng) hoặc JSON per-line {"host": ...}."""
    hosts: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            for obj in jsonl_lines(line):
                host = obj.get("host")
                if host:
                    hosts.append(str(host))
        elif _HOSTNAME_RE.match(line.lower()):
            hosts.append(line)
    return hosts


def parse_dnsx_json(stdout: str) -> dict[str, dict]:
    """dnsx -json → {host: {"a": [ip], "cname": "chuỗi hoặc None"}}.

    Chuỗi CNAME (hiếm) giữ nguyên thứ tự nối bằng dấu phẩy — đủ dữ liệu cho
    lớp subdomain takeover sau này.
    """
    out: dict[str, dict] = {}
    for obj in jsonl_lines(stdout):
        host = obj.get("host")
        if not host:
            continue
        cname = obj.get("cname") or None
        out[str(host)] = {
            "a": [str(ip) for ip in (obj.get("a") or [])],
            "cname": ",".join(str(c) for c in cname) if isinstance(cname, list) else cname,
        }
    return out


def parse_naabu_json(stdout: str) -> dict[str, list[int]]:
    """naabu -json → {host: [port]}"""
    ports: dict[str, list[int]] = {}
    for obj in jsonl_lines(stdout):
        host = obj.get("host")
        port = obj.get("port")
        if not host or not port:
            continue
        bucket = ports.setdefault(str(host), [])
        if int(port) not in bucket:
            bucket.append(int(port))
    for bucket in ports.values():
        bucket.sort()
    return ports


def parse_httpx_json(stdout: str) -> list[dict]:
    """httpx -json → [{host, url, status_code, title}]"""
    out: list[dict] = []
    for obj in jsonl_lines(stdout):
        host = obj.get("host")
        if not host:
            continue
        out.append(
            {
                "host": str(host),
                "url": obj.get("url"),
                "status_code": obj.get("status_code"),
                "title": obj.get("title"),
            }
        )
    return out


def build_httpx_targets(hosts: list[str], ports: dict[str, list[int]]) -> list[str]:
    """Target cho httpx: host:port với mỗi cổng naabu tìm được; host nào không
    có cổng nào thì đưa host trần (httpx tự thử 80/443)."""
    targets: list[str] = []
    for host in hosts:
        open_ports = ports.get(host) or []
        if open_ports:
            targets.extend(f"{host}:{p}" for p in open_ports)
        else:
            targets.append(host)
    return targets


# ─────────── seam thuần giai đoạn 2 — URL + params + class (ticket #9) ───────────

_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_url(raw: str) -> str | None:
    """Chuẩn hoá URL thành chìa khoá dedupe crawled ↔ lịch sử: scheme + host
    lowercase, bỏ fragment, bỏ port mặc định (http:80/https:443), path rỗng
    thành '/', query sắp xếp lại theo tên param (cùng bộ param với thứ tự
    khác nhau — hay gặp giữa crawled và lịch sử — ra cùng một URL). Trả None
    nếu không phải http(s) URL hợp lệ (dòng rác của tool)."""
    t = (raw or "").strip()
    if not t:
        return None
    try:
        parts = urlsplit(t)
        port = parts.port
        query = urlencode(
            sorted(parse_qsl(parts.query, keep_blank_values=True)),
            quote_via=quote,
            safe="/",
        )
    except ValueError:
        return None
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        return None
    netloc = parts.hostname
    if port is not None and port != _DEFAULT_PORTS[parts.scheme]:
        netloc = f"{netloc}:{port}"
    if parts.username:
        cred = parts.username
        if parts.password:
            cred += f":{parts.password}"
        netloc = f"{cred}@{netloc}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/", query, ""))


def url_param_names(url: str) -> list[str]:
    """Tên param trong query string — unique + sorted cho cột params."""
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return []
    return sorted({name for name, _ in pairs})


def parse_url_lines(stdout: str) -> list[str]:
    """Output dạng URL thẳng (1 URL/dòng) của katana/gau/waymore — bỏ dòng rác,
    giữ thứ tự, dedupe dòng trùng (chuẩn hoá sâu hơn do merge lo)."""
    out: list[str] = []
    seen: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not _URL_LINE_RE.match(line):
            continue
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def parse_gf_slice_json(stdout: str) -> dict[str, list[str]]:
    """Output JSONL của gf-slice → {url: [class]}."""
    out: dict[str, list[str]] = {}
    for obj in jsonl_lines(stdout):
        url = obj.get("url")
        if not url:
            continue
        classes = obj.get("classes") or []
        out[str(url)] = [str(c) for c in classes]
    return out


def build_katana_args(rate_limit_rps: float | None, ident: dict[str, str]) -> list[str]:
    """Args cho katana: depth cố định, throttle theo rate limit của Run
    (-rate-limit/-concurrency là int — làm tròn như httpx -rl) + header định danh."""
    args = ["-silent", "-no-color", "-d", str(_KATANA_DEPTH)]
    if rate_limit_rps and rate_limit_rps > 0:
        n = str(max(1, round(rate_limit_rps)))
        args += ["-rate-limit", n, "-concurrency", n]
    for name, value in ident.items():
        args += ["-H", f"{name}: {value}"]
    return args


def build_archive_args(tool: str, root: str) -> list[str]:
    """Args thu URL lịch sử theo domain gốc (gồm subdomain)."""
    if tool == "gau":
        return ["--subs", root]
    if tool == "waymore":
        # -mode U: chỉ lấy URL (không tải response); --stream: in URL ra stdout
        return ["-i", root, "-mode", "U", "--stream"]
    raise ValueError(f"tool thu URL lịch sử không hỗ trợ: {tool}")


def archive_docker_args() -> list[str] | None:
    """Docker env cho container archive: OTX_API_KEY nếu có (waymore đọc key
    từ env; gau dùng OTX endpoint công khai nên không cần)."""
    if settings.otx_api_key:
        return ["-e", f"OTX_API_KEY={settings.otx_api_key}"]
    return None


# ───────────────────────────── pipeline (async) ─────────────────────────────


async def _upsert_asset(pool, run_id: int, host: str, sources: list[str]) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO recon_assets (run_id, host, sources)
            VALUES ($1, $2, $3)
            ON CONFLICT (run_id, host) DO UPDATE SET
                sources = (SELECT array_agg(DISTINCT s)
                           FROM unnest(recon_assets.sources || EXCLUDED.sources) AS s)
            """,
            run_id,
            host,
            sources,
        )


_UPSERT_URLS_SQL = """
INSERT INTO recon_urls (run_id, url, host, params, sources, classes)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (run_id, url) DO UPDATE SET
    sources = (SELECT array_agg(DISTINCT s)
               FROM unnest(recon_urls.sources || EXCLUDED.sources) AS s),
    classes = (SELECT array_agg(DISTINCT c)
               FROM unnest(recon_urls.classes || EXCLUDED.classes) AS c)
"""


class UrlRow(namedtuple("UrlRow", "run_id url host params sources classes")):
    """1 row recon_urls — NamedTuple để đọc theo tên, không theo index."""


async def _upsert_urls(pool, rows: list[UrlRow]) -> None:
    """Ghi URL + params + nhãn class vào recon_urls (1 batch executemany).
    Chìa khoá dedupe là (run_id, url đã chuẩn hoá) — re-run/cùng URL từ nguồn
    khác chỉ GỘP thêm sources/classes, không sinh row mới."""
    if not rows:
        return
    async with pool.acquire() as conn:
        await conn.executemany(_UPSERT_URLS_SQL, rows)


async def run_url_phase(
    pool: asyncpg.Pool,
    ctx: ToolContext,
    rate_limit_rps: float | None,
    live_records: list[dict],
    roots: list[str],
    tool_runner=None,
) -> dict:
    """Giai đoạn 2 của Recon Phase (ticket #9):

      katana (crawl live host) → gau/waymore (URL lịch sử theo domain gốc)
      → gf-slice (phân loại theo pattern ~/.gf) → bảng recon_urls

    - Seed của katana là URL httpx đã xác nhận live; katana được throttle theo
      rate limit của Run (flag riêng + RateLimiter chung ở execute_tool);
      katana lỗi (exit ≠ 0) coi như tool không phát hiện gì — seed không bị
      gán nguồn katana (đúng provenance, như convention của giai đoạn 1);
    - gau/waymore là passive archive — không gửi traffic tới target, nhưng URL
      tìm được vẫn phải qua Scope Validator (theo host) trước khi lên DB;
    - cùng 1 URL từ nhiều nguồn → 1 row, sources/classes gộp (dedupe).
    Trả {urls, urls_classed, blocked} để log cuối Run.
    """
    run_id = ctx.run_id
    merged: dict[str, set[str]] = {}
    blocked = 0

    async def scope_ok(raw_urls: list[str], tool: str) -> list[str]:
        """Lọc URL qua Scope Validator (theo host — mỗi host duy nhất 1 lần,
        qua tools.filter_scope), trả về URL đã chuẩn hoá + dedupe thuộc Scope."""
        nonlocal blocked
        urls: list[str] = []
        seen: set[str] = set()
        for raw in raw_urls:
            url = normalize_url(raw)
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
        allowed, n = await filter_scope(pool, ctx, urls, tool)
        blocked += n
        return allowed

    def merge(urls: list[str], source: str) -> None:
        for url in urls:
            merged.setdefault(url, set()).add(source)

    # ── katana: crawl các live host (seed = URL httpx đã xác nhận) ──
    seeds = [rec.get("url") or f"https://{rec['host']}" for rec in live_records]
    ok_seeds = await scope_ok(seeds, "katana")
    if ok_seeds:
        res = await execute_tool(
            pool, ctx, "katana", build_katana_args(rate_limit_rps, ctx.ident),
            stdin="\n".join(sorted(ok_seeds)), runner=tool_runner,
        )
        if res.exit_code == 0:
            crawled_raw = parse_url_lines(res.stdout)
            merge(ok_seeds + await scope_ok(crawled_raw, "katana"), "katana")
        else:
            crawled_raw = []
        await add_log(
            pool, run_id, f"Crawl: katana {len(crawled_raw)} URL từ {len(ok_seeds)} live host"
        )

    # ── gau/waymore: URL lịch sử (Wayback / Common Crawl / OTX) — passive ──
    for tool in ARCHIVE_TOOLS:
        for root in roots:
            # cửa ắt như discovery: root từ snapshot, passive trên không gian
            # wildcard đã khai báo — base wildcard được phép
            await ctx.validate(pool, root, tool=tool, allow_wildcard_base=True)
            docker_args = archive_docker_args() if tool == "waymore" else None
            res = await execute_tool(
                pool, ctx, tool, build_archive_args(tool, root),
                runner=tool_runner, docker_args=docker_args,
            )
            found_raw = parse_url_lines(res.stdout) if res.exit_code == 0 else []
            merge(await scope_ok(found_raw, tool), tool)
            await add_log(
                pool, run_id, f"URL lịch sử: {tool} {len(found_raw)} URL trên {root}"
            )

    if not merged:
        return {"urls": 0, "urls_classed": 0, "blocked": blocked}

    # ── gf-slice: gắn nhãn class theo pattern ~/.gf (xss, ssrf, redirect, …) ──
    url_list = sorted(merged)
    res = await execute_tool(
        pool, ctx, GF_SLICE_TOOL, [], stdin="\n".join(url_list), runner=tool_runner,
    )
    classes_map = parse_gf_slice_json(res.stdout) if res.exit_code == 0 else {}
    rows = [
        UrlRow(
            run_id=run_id,
            url=url,
            host=target_host(url),
            params=url_param_names(url),
            sources=sorted(merged[url]),
            classes=sorted(classes_map.get(url, [])),
        )
        for url in url_list
    ]
    await _upsert_urls(pool, rows)
    classed = sum(1 for r in rows if r.classes)
    await add_log(
        pool, run_id,
        f"URLs: {len(rows)} URL vào recon_urls (đã dedupe crawled + lịch sử) · "
        f"{classed} URL có nhãn class từ gf — nguồn cho Detection Phase",
    )
    return {"urls": len(rows), "urls_classed": classed, "blocked": blocked}


async def run_recon_phase(
    pool: asyncpg.Pool,
    run: asyncpg.Record | dict,
    tool_runner=None,
) -> dict:
    """Chạy chuỗi recon cho 1 Run. `run` cần id, program_name, rate_limit_rps,
    ident_header_name/value, scope_snapshot, allow_non_prod. Trả summary đếm
    ({subdomains, live_hosts, blocked, urls, urls_classed}) để log cuối Run.

    Tool lỗi (exit ≠ 0) không làm chết chuỗi — các bước sau vẫn chạy với những
    gì đã có; chỉ lỗi môi trường (docker) ném lên cho jobqueue retry.
    """
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

    roots = recon_roots(snapshot)
    seeds = [h for h in explicit_hosts(snapshot)]
    await add_log(
        pool,
        run_id,
        f"Recon Phase: chuỗi {' → '.join(RECON_CHAIN)} · "
        f"{len(roots)} domain gốc ({', '.join(roots) if roots else 'không có host asset trong Scope'})",
    )
    if not roots:
        await add_log(pool, run_id, "Scope không có Asset dạng host — bỏ qua Recon Phase.")
        return {"subdomains": 0, "live_hosts": 0, "blocked": 0, "urls": 0, "urls_classed": 0}

    # ── discovery: subfinder → amass (passive, per root) ──
    found: dict[str, set[str]] = {}
    for tool in DISCOVERY_TOOLS:
        for root in roots:
            # cửa ắt: root lấy từ snapshot, nhưng vẫn qua validator (fail-closed,
            # có audit) — base wildcard được phép vì passive discovery
            await ctx.validate(pool, root, tool=tool, allow_wildcard_base=True)
            args, docker_args = _discovery_args(tool, root, run_id)
            result = await execute_tool(
                pool, ctx, tool, args, runner=tool_runner, docker_args=docker_args
            )
            if result.exit_code != 0:
                continue  # tool lỗi — coi như không phát hiện gì từ tool này
            discovered = parse_host_lines(result.stdout)
            if tool == "amass" and settings.recon_volume:
                # amass v5 ghi kết quả vào file trên volume, stdout chỉ có
                # preamble — harvest file và GỘP thêm vào những gì stdout có
                discovered = unique_hosts(discovered + _harvest_amass_files(run_id, root))
            for host in discovered:
                found.setdefault(host, set()).add(tool)

    # ── Scope Validator: MỌI host phát hiện được phải qua cửa ắt này ──
    allowed: list[str] = []
    blocked = 0
    for host in unique_hosts(seeds + list(found)):
        try:
            await ctx.validate(pool, host, tool="dnsx/naabu/httpx")
        except TargetBlockedError as exc:
            blocked += 1
            found.pop(host, None)
            await add_log(pool, run_id, f"BLOCKED: {exc}", level="error")
            continue
        allowed.append(host)

    sources_map = {h: sorted(found.get(h, {"scope"})) for h in allowed}
    for host, sources in sources_map.items():
        await _upsert_asset(pool, run_id, host, sources)
    await add_log(
        pool,
        run_id,
        f"Discovery: {len(allowed)} subdomain trong Scope (validator chặn {blocked} "
        f"target ngoài Scope) — đã ghi recon_assets",
    )

    if not allowed:
        return {
            "subdomains": 0,
            "live_hosts": 0,
            "blocked": blocked,
            "urls": 0,
            "urls_classed": 0,
        }

    # ── dnsx: resolve A/CNAME trên host ĐÃ validate ──
    res = await execute_tool(
        pool, ctx, "dnsx", ["-a", "-cname", "-json", "-silent"], stdin="\n".join(allowed),
        runner=tool_runner,
    )
    records = parse_dnsx_json(res.stdout) if res.exit_code == 0 else {}
    for host, rec in records.items():
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE recon_assets SET ip = $3, cname = $4 WHERE run_id = $1 AND host = $2",
                run_id,
                host,
                rec["a"],
                rec["cname"],
            )
    cname_count = sum(1 for r in records.values() if r["cname"])
    await add_log(
        pool,
        run_id,
        f"DNS: resolve {len(records)}/{len(allowed)} host · {cname_count} CNAME (lưu phục vụ takeover)",
    )

    # ── naabu: quét cổng trên host ĐÃ validate (rate-limit ở mức packet/s) ──
    naabu_args = ["-top-ports", "100", "-json", "-silent"]
    if ctx.limiter is not None and run["rate_limit_rps"]:
        naabu_args += ["-rate", str(max(1, round(run["rate_limit_rps"])))]
    res = await execute_tool(
        pool, ctx, "naabu", naabu_args,
        stdin="\n".join(allowed), runner=tool_runner,
    )
    ports_map = parse_naabu_json(res.stdout) if res.exit_code == 0 else {}
    for host, ports in ports_map.items():
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE recon_assets SET ports = $3 WHERE run_id = $1 AND host = $2",
                run_id,
                host,
                ports,
            )
    await add_log(pool, run_id, f"Cổng mở: {sum(len(p) for p in ports_map.values())} trên "
                                f"{len(ports_map)} host")

    # ── httpx: probe HTTP — target lại được validate từng cái một ──
    targets = build_httpx_targets(allowed, ports_map)
    valid_targets: list[str] = []
    for target in targets:
        try:
            await ctx.validate(pool, target, tool="httpx")
        except TargetBlockedError as exc:  # phòng hờ — host đã qua lọc ở trên
            await add_log(pool, run_id, f"BLOCKED: {exc}", level="error")
            blocked += 1
            continue
        valid_targets.append(target)
    httpx_args = ["-json", "-silent", "-status-code", "-title", "-no-color"]
    if ctx.limiter is not None and run["rate_limit_rps"]:
        # httpx -rl là int — rate thấp hơn 1 rps vẫn chặn ở mức 1 (coarse gate
        # đã có RateLimiter của Run phía trước)
        httpx_args += ["-rl", str(max(1, round(run["rate_limit_rps"])))]
    for hname, hvalue in ctx.ident.items():
        httpx_args += ["-H", f"{hname}: {hvalue}"]
    res = await execute_tool(
        pool, ctx, "httpx", httpx_args, stdin="\n".join(valid_targets), runner=tool_runner
    )
    live_records = parse_httpx_json(res.stdout) if res.exit_code == 0 else []
    live_hosts: set[str] = set()
    for rec in live_records:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE recon_assets SET is_live = TRUE, http_url = $3, "
                "http_status = $4, http_title = $5 WHERE run_id = $1 AND host = $2",
                run_id,
                rec["host"],
                rec["url"],
                rec["status_code"],
                rec["title"],
            )
        live_hosts.add(rec["host"])
    await add_log(
        pool, run_id,
        f"Live host: {len(live_hosts)}/{len(valid_targets)} target có HTTP",
    )

    # ── giai đoạn 2: katana crawl + gau/waymore lịch sử + gf slicing (ticket #9) ──
    url_summary = await run_url_phase(
        pool, ctx, run["rate_limit_rps"], live_records, roots, tool_runner=tool_runner
    )
    blocked += url_summary["blocked"]

    return {
        "subdomains": len(allowed),
        "live_hosts": len(live_hosts),
        "blocked": blocked,
        "urls": url_summary["urls"],
        "urls_classed": url_summary["urls_classed"],
    }


_COUNTS_SQL = """
SELECT count(*) AS subdomains,
       count(*) FILTER (WHERE is_live) AS live_hosts,
       coalesce(sum(array_length(ports, 1)), 0) AS open_ports,
       (SELECT count(*) FROM recon_urls WHERE run_id = $1) AS urls,
       (SELECT count(*) FROM recon_urls
        WHERE run_id = $1 AND array_length(classes, 1) > 0) AS urls_classed,
       (SELECT count(*) FROM candidates WHERE run_id = $1) AS candidates
FROM recon_assets WHERE run_id = $1
"""

_COUNTS_EMPTY = {
    "subdomains": 0,
    "live_hosts": 0,
    "open_ports": 0,
    "urls": 0,
    "urls_classed": 0,
    "candidates": 0,
}


async def counts_for(pool: asyncpg.Pool, run_id: int) -> dict:
    """Bộ đếm recon của Run (một nguồn sự thật — dùng chung cho API list/detail)."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(_COUNTS_SQL, run_id)
    return dict(row) if row else dict(_COUNTS_EMPTY)


async def list_assets(pool: asyncpg.Pool, run_id: int, limit: int = 500) -> dict:
    """Kết quả recon của Run + bộ đếm cho UI (subdomain/live host tăng dần)."""
    async with pool.acquire() as conn:
        items = [
            dict(r)
            for r in await conn.fetch(
                """
                SELECT host, sources, cname, ip, ports, is_live,
                       http_url, http_status, http_title, first_seen
                FROM recon_assets WHERE run_id = $1
                ORDER BY is_live DESC, http_status DESC NULLS LAST, host
                LIMIT $2
                """,
                run_id,
                limit,
            )
        ]
    return {"counts": await counts_for(pool, run_id), "items": items}


async def list_urls(
    pool: asyncpg.Pool, run_id: int, limit: int = 500, classed: bool | None = None
) -> dict:
    """Bảng URLs + params + nhãn class của Run (ticket #9) — nguồn mục tiêu
    của Detection Phase. Truy theo Run; theo Program xem `list_program_urls`."""
    async with pool.acquire() as conn:
        where = "WHERE run_id = $1"
        if classed:
            where += " AND array_length(classes, 1) > 0"
        items = [
            dict(r)
            for r in await conn.fetch(
                f"""
                SELECT url, host, params, sources, classes, first_seen
                FROM recon_urls {where}
                ORDER BY array_length(classes, 1) DESC NULLS LAST,
                         array_length(params, 1) DESC, url
                LIMIT $2
                """,
                run_id,
                limit,
            )
        ]
    return {"counts": await counts_for(pool, run_id), "items": items}


async def list_program_urls(
    pool: asyncpg.Pool, program_id: int, limit: int = 500
) -> dict:
    """URL của TẤT CẢ Run thuộc một Program — truy vấn theo Program
    (acceptance criterion của ticket #9: 'truy được theo Program/Run')."""
    async with pool.acquire() as conn:
        items = [
            dict(r)
            for r in await conn.fetch(
                """
                SELECT u.url, u.host, u.params, u.sources, u.classes,
                       u.run_id, u.first_seen
                FROM recon_urls u
                JOIN runs r ON r.id = u.run_id
                WHERE r.program_id = $1
                ORDER BY u.first_seen DESC, u.url
                LIMIT $2
                """,
                program_id,
                limit,
            )
        ]
    return {"items": items}
