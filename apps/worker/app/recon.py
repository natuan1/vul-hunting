"""Recon Phase giai đoạn 1 (ticket #8) — chuỗi cứng:

    subfinder → amass → [Scope Validator] → dnsx (-a -cname) → naabu → httpx (-json)

- discovery (subfinder/amass) là passive: chỉ được chạy trên domain gốc lấy từ
  Scope snapshot của Run — root được validate trước khi chạy;
- MỌI host phát hiện được phải qua ToolContext.validate() trước khi bước nào
  đó chạm tới (dnsx resolve, naabu quét cổng, httpx gửi HTTP) — host ngoài
  scope bị audit + loại ngay từ đầu, không có request nào đi ra;
- CNAME (dnsx) lưu cột riêng trên recon_assets — nuôi lớp subdomain takeover
  (ticket #14);
- subdomain xuất hiện trên recon_assets ngay sau bước lọc, live host cập nhật
  sau httpx — UI đếm tăng dần trong lúc Run chạy.
"""

import json
import logging
import re
from pathlib import Path

import asyncpg

from .config import settings
from .scope_validator import target_host
from .tools import (
    TargetBlockedError,
    ToolContext,
    add_log,
    build_context,
    execute_tool,
)

log = logging.getLogger("recon")

# hostname chỉ gồm [a-z0-9._-] (cho phép * vì output tool có thể chứa wildcard) —
# dòng khác (vd preamble 'Session Scope'/'FQDN:' của amass) không phải host
_HOSTNAME_RE = re.compile(r"^[a-z0-9._*-]+$")


def _jsonl_lines(stdout: str) -> list[dict]:
    """Trích các dòng JSON hợp lệ (mỗi dòng 1 object) từ stdout của tool."""
    out: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out

DISCOVERY_TOOLS = ("subfinder", "amass")
PROBE_TOOLS = ("dnsx", "naabu", "httpx")
RECON_CHAIN = DISCOVERY_TOOLS + PROBE_TOOLS

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
            for obj in _jsonl_lines(line):
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
    for obj in _jsonl_lines(stdout):
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
    for obj in _jsonl_lines(stdout):
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
    for obj in _jsonl_lines(stdout):
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


async def run_recon_phase(
    pool: asyncpg.Pool,
    run: asyncpg.Record | dict,
    tool_runner=None,
) -> dict:
    """Chạy chuỗi recon cho 1 Run. `run` cần id, program_name, rate_limit_rps,
    ident_header_name/value, scope_snapshot, allow_non_prod. Trả summary đếm
    ({subdomains, live_hosts, blocked}) để log cuối Run.

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
        return {"subdomains": 0, "live_hosts": 0, "blocked": 0}

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
        return {"subdomains": 0, "live_hosts": 0, "blocked": blocked}

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

    return {
        "subdomains": len(allowed),
        "live_hosts": len(live_hosts),
        "blocked": blocked,
    }


_COUNTS_SQL = """
SELECT count(*) AS subdomains,
       count(*) FILTER (WHERE is_live) AS live_hosts,
       coalesce(sum(array_length(ports, 1)), 0) AS open_ports
FROM recon_assets WHERE run_id = $1
"""

_COUNTS_EMPTY = {"subdomains": 0, "live_hosts": 0, "open_ports": 0}


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
