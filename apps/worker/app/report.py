"""Sinh report draft theo mẫu platform (ticket #18) — nộp TAY, không auto-submit.

Finding (status `verified`) → draft report theo mẫu HackerOne (## Summary /
## Steps to Reproduce / ## Impact / ## Supporting Material/References) hoặc
Intigriti (### Description / ### Steps to Reproduce / ### Impact / ### Proof
of Concept) — title, severity, steps, impact và PoC/evidence (curl, response
diff so baseline, callback OOB, PoC page takeover) nhúng đúng chỗ. Nội dung
build THUẦN từ evidence đã có trên volume + Candidate — không gọi mạng.

Preview sửa xong lưu nháp (JSONB `report_drafts` theo platform). User tự nộp
trên platform xong → `mark_reported` đặt status `reported` + link + ngày nộp
+ ghi chú tự do. TRIPWIRE: module này KHÔNG import HTTP client nào — không có
bất kỳ đường code nào tự POST report lên platform (auto-submit là v2, phải
hỏi user và kiểm tra quyền API tạo report trước).
"""

import json
import logging
import re
from datetime import datetime, timezone

import asyncpg

from .detect import CANDIDATE_COLS, read_evidence

log = logging.getLogger("report")

# 2 platform có mẫu report riêng (ticket #18) — auto-submit platform khác là v2
PLATFORMS = ("hackerone", "intigriti")

# chỉ Finding (verified) — và những cái đã nộp — mới làm việc với report
_REPORTABLE = ("verified", "reported")

_SEVERITIES_PLATFORM = ("low", "medium", "high", "critical")


class ReportError(ValueError):
    """Candidate không đủ điều kiện sinh/sửa report, hoặc platform lạ."""


# ───────────────────────────── seam thuần (có test) ─────────────────────────────


def severity_for_platform(severity: str | None, platform: str) -> str:
    """Severity vocab của platform: 'info' không tồn tại trên H1/Intigriti →
    map về low; lạ → low (thận trọng, không phóng đại mức độ)."""
    if platform not in PLATFORMS:
        raise ReportError(f"platform phải là một trong {', '.join(PLATFORMS)}")
    s = (severity or "").strip().lower()
    return s if s in _SEVERITIES_PLATFORM else "low"


def build_curl(url: str) -> str:
    """curl command tái lập được PoC — URL bọc quote đơn (escape ' bên trong)."""
    safe = str(url or "").replace("'", "'\\''")
    return f"curl -i -s '{safe}'"


def _clip(text: str, cap: int = 1500) -> str:
    return text[:cap]


def _as_str_list(value) -> list[str]:
    """Chuẩn hoá cname sang list chuỗi — evidence takeover ghi cname dạng
    CHUỖI (recon_assets.cname là TEXT) nhưng schema cũ/subzy parse trả list;
    chuỗi phải là 1 phần tử, KHÔNG mảnh ra từng ký tự."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v).strip()]
    return [str(value)]


def _profile_fields(profile: dict | None) -> dict:
    """Trường cần cho report từ 1 profile probe (baseline hoặc PoC)."""
    if not isinstance(profile, dict):
        return {}
    headers = profile.get("headers") or {}
    return {
        "url": profile.get("url"),
        "status": profile.get("status"),
        "location": str(headers.get("location") or ""),
        "body_length": profile.get("body_length"),
        "body": str(profile.get("body") or ""),
        "error": profile.get("error"),
    }


def extract_bundle(detection: dict | None, verify: dict | None, oob: dict | None) -> dict:
    """Chuẩn hoá 3 evidence (Detection / vòng xác minh / OOB) thành bundle phẳng
    cho build_draft — không phụ thuộc schema riêng của từng vòng verify."""
    bundle: dict = {
        "poc_url": None,
        "baseline_url": None,
        "poc_status": None,
        "baseline_status": None,
        "poc_location": "",
        "baseline_location": "",
        "poc_body": "",
        "payload": "",
        "signals": [],
        "patterns": [],
        "score": None,
        "reason": "",
        "detail": None,
        "callbacks": [],
        "oob_domain": None,
        "takeover": None,
        "curl": None,
        "detection_request": None,
        "detection_response": None,
    }

    if isinstance(detection, dict):
        # evidence nuclei thô: raw request/response là bằng chứng phát hiện
        req = str(detection.get("request") or "").strip()
        res = str(detection.get("response") or "").strip()
        bundle["detection_request"] = _clip(req) if req else None
        bundle["detection_response"] = _clip(res) if res else None

    if isinstance(verify, dict):
        analysis = verify.get("analysis") or {}
        bundle["payload"] = str(verify.get("payload") or "")
        bundle["signals"] = [str(s) for s in (analysis.get("signals") or [])]
        bundle["patterns"] = [str(p) for p in (analysis.get("patterns") or [])]
        bundle["score"] = analysis.get("score")
        bundle["reason"] = str(analysis.get("reason") or "")
        bundle["detail"] = analysis.get("detail")
        if str(verify.get("schema") or "") == "vulhunt.takeover-evidence/1":
            fp = verify.get("fingerprint") or {}
            deploy = verify.get("deploy") or {}
            confirm = verify.get("confirm") or {}
            poc_url = deploy.get("url") or None
            bundle["takeover"] = {
                "target": verify.get("target"),
                "cname": _as_str_list(verify.get("cname")),
                "service": fp.get("service"),
                "claim_host": fp.get("claim_host"),
                "poc_url": poc_url,
                "confirm_status": confirm.get("status"),
                "confirm_url": confirm.get("url"),
            }
            bundle["poc_url"] = poc_url or confirm.get("url")
            if bundle["poc_url"]:
                bundle["curl"] = build_curl(bundle["poc_url"])
        else:
            base = _profile_fields(verify.get("baseline"))
            poc = _profile_fields(verify.get("poc"))
            bundle["baseline_url"] = base.get("url")
            bundle["poc_url"] = poc.get("url")
            bundle["baseline_status"] = base.get("status")
            bundle["poc_status"] = poc.get("status")
            bundle["baseline_location"] = base.get("location") or ""
            bundle["poc_location"] = poc.get("location") or ""
            bundle["poc_body"] = _clip(poc.get("body") or "", 800)
            if bundle["poc_url"]:
                bundle["curl"] = build_curl(bundle["poc_url"])

    if isinstance(oob, dict):
        analysis = oob.get("analysis") or {}
        bundle["payload"] = bundle["payload"] or str(oob.get("payload") or "")
        bundle["oob_domain"] = (oob.get("registration") or {}).get("domain")
        bundle["callbacks"] = list(oob.get("callbacks") or [])
        bundle["signals"] = bundle["signals"] or [str(s) for s in (analysis.get("signals") or [])]
        if bundle["score"] is None:
            bundle["score"] = analysis.get("score")
        # cờ human review (batch C #17) đi theo Finding vào report — deserialization
        if oob.get("human_review_required"):
            bundle["human_review_required"] = True
            bundle["human_review_note"] = str(oob.get("human_review_note") or "")

    # payload OOB là PoC URL (blind) khi chưa có PoC HTTP nào
    if not bundle["poc_url"] and bundle["payload"].startswith("http"):
        bundle["poc_url"] = bundle["payload"]
        bundle["curl"] = bundle["curl"] or build_curl(bundle["payload"])
    return bundle


# label + mô tả + impact theo class — report viết TIẾNG ANH (ngôn ngữ platform)
_CLASS_META = {
    "redirect": (
        "Open Redirect",
        "The application redirects users to a URL built from user-controlled "
        "input without sufficient validation.",
        "An attacker can craft links on a trusted domain that redirect victims "
        "to phishing pages, or abuse the redirect to leak OAuth tokens and "
        "password-reset links.",
    ),
    "ssrf": (
        "Server-Side Request Forgery (SSRF)",
        "The server fetches a user-controlled URL, allowing requests towards "
        "internal or attacker-controlled destinations.",
        "An attacker can make the server issue requests to internal services, "
        "cloud metadata endpoints, or exfiltrate data out-of-band.",
    ),
    "takeover": (
        "Subdomain Takeover",
        "A subdomain points (CNAME) to an external service that is no longer "
        "claimed, so the subdomain serves attacker-controlled content.",
        "An attacker can host arbitrary content on a legitimate subdomain of "
        "the program, enabling phishing, cookie theft on scoped cookies, and "
        "reputation damage.",
    ),
    "cors": (
        "Cross-Origin Resource Sharing (CORS) Misconfiguration",
        "The application reflects an arbitrary Origin and allows credentials "
        "in CORS responses.",
        "Any website can read authenticated responses of the victim via "
        "JavaScript, disclosing sensitive data cross-origin.",
    ),
    "dirlist": (
        "Directory Listing",
        "A web directory exposes its file listing instead of denying access.",
        "Attackers can discover hidden files, backups and source code, which "
        "may lead to further vulnerabilities.",
    ),
    "graphql": (
        "GraphQL Introspection Enabled",
        "The public GraphQL endpoint discloses its full schema through "
        "introspection queries.",
        "The complete API schema (types, fields, mutations) is exposed, which "
        "lowers the bar for finding and abusing sensitive operations.",
    ),
    "crlf": (
        "CRLF / HTTP Response Header Injection",
        "User input is reflected into HTTP response headers without escaping "
        "CR/LF sequences.",
        "An attacker can split or poison responses (cache poisoning, session "
        "fixation, cross-site scripting via injected headers).",
    ),
    "ssti": (
        "Server-Side Template Injection (SSTI)",
        "User input is evaluated inside a server-side template engine.",
        "Depending on the engine, an attacker can escalate to information "
        "disclosure or remote code execution on the server.",
    ),
    "headers": (
        "Missing Security Headers",
        "The application does not set recommended security response headers.",
        "Missing headers (CSP, X-Frame-Options, HSTS, ...) increase exposure "
        "to clickjacking, downgrade and injection attacks.",
    ),
    "disclosure": (
        "Information Disclosure",
        "The application exposes sensitive technical information that should "
        "not be public (debug endpoints, configuration, stack traces).",
        "Disclosed internals help attackers map the application and chain "
        "further attacks.",
    ),
    "xss": (
        "Cross-Site Scripting (XSS)",
        "User-controlled input is incorporated into the application without "
        "proper output encoding; the out-of-band callback confirms the "
        "submitted payload is processed (blind XSS).",
        "An attacker can execute arbitrary JavaScript in the context of the "
        "victim's session — for blind XSS typically an administrator — "
        "hijacking accounts or performing actions on their behalf.",
    ),
    "xxe": (
        "XML External Entity (XXE)",
        "The server parses user-controlled XML with external entity "
        "resolution enabled; an out-of-band callback confirms the external "
        "entity is resolved.",
        "An attacker can read local files, reach internal services through "
        "entity URLs, or exfiltrate data out-of-band via crafted XML "
        "documents.",
    ),
    "deserialization": (
        "Insecure Deserialization",
        "The application deserializes user-controlled data; a benign "
        "DNS ping-back payload (URLDNS) confirms deserialization occurs — "
        "no execution gadget was submitted.",
        "Deserialization of untrusted input commonly enables remote code "
        "execution, but this report only demonstrates a benign ping-back; "
        "impact must be confirmed by manual analysis before claiming higher "
        "severity.",
    ),
    "sqli": (
        "SQL Injection",
        "User-controlled input is concatenated into a SQL query without "
        "parameterisation.",
        "An attacker can read or modify database contents, potentially "
        "leading to full data compromise.",
    ),
    "secret": (
        "Exposed Secret / API Key",
        "A valid credential (verified against its provider) is served publicly "
        "at a program-controlled URL. The key is redacted throughout this "
        "report — only a short prefix is shown.",
        "Anyone can retrieve the exposed key and access the associated "
        "third-party account or service as the program (data exposure, "
        "resource abuse, account takeover).",
    ),
    "lfi": (
        "Local File Inclusion (LFI)",
        "User-controlled input is used in a file path on the server without "
        "validation.",
        "An attacker can read arbitrary files on the host (source code, "
        "credentials) and potentially execute code.",
    ),
    "rce": (
        "Remote Code Execution (RCE)",
        "User-controlled input reaches a code execution sink on the server.",
        "An attacker can run arbitrary commands on the server, fully "
        "compromising the application and its data.",
    ),
    "idor": (
        "Insecure Direct Object Reference (IDOR)",
        "The application serves objects by identifier without verifying the "
        "caller's authorisation.",
        "An attacker can access or modify other users' data by changing "
        "object identifiers.",
    ),
}

_GENERIC_IMPACT = (
    "Depending on the application context, this issue can be abused to "
    "compromise the confidentiality or integrity of the program's assets."
)


def _class_meta(cls: str) -> tuple[str, str, str]:
    label, desc, impact = _CLASS_META.get(cls, (cls, None, None))
    if desc is None:
        desc = (
            f"The application is affected by a `{cls}` issue detected by the "
            "automated scan and confirmed during verification."
        )
    if impact is None:
        impact = _GENERIC_IMPACT
    return label, desc, impact


_HOST_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]+)")


def _host_of(url: str) -> str:
    m = _HOST_RE.match(url or "")
    return m.group(1) if m else (url or "")


def _summary_text(candidate: dict, bundle: dict, description: str) -> str:
    parts = [description]
    target = candidate.get("target") or ""
    if target:
        parts.append(f"Affected endpoint: `{target}`")
    param = candidate.get("param") or ""
    if param:
        parts.append(f"The value of the `{param}` query parameter is used without validation.")
    template = candidate.get("title") or candidate.get("template_id")
    if template:
        parts.append(f"Detected via `{template}`.")
    score = bundle.get("score")
    if score is not None:
        parts.append(
            f"Confirmed inside an isolated verification sandbox against a benign "
            f"baseline capture (confidence {float(score):.2f})."
        )
    return " ".join(parts)


def _steps_text(candidate: dict, bundle: dict) -> str:
    lines: list[str] = []

    def add(step: str) -> None:
        lines.append(f"{len(lines) + 1}. {step}")

    takeover = bundle.get("takeover")
    if isinstance(takeover, dict):
        cnames = ", ".join(f"`{c}`" for c in takeover.get("cname") or [])
        target = takeover.get("target") or candidate.get("target")
        if cnames:
            add(f"Resolve `{target}` — it is a CNAME to {cnames}.")
        add(f"The destination service is unclaimed (fingerprint match: `{takeover.get('service')}`).")
        if takeover.get("claim_host"):
            add(f"Register/claim the resource on `{takeover['claim_host']}`.")
        if takeover.get("poc_url"):
            add(f"Deploy an identification PoC page at `{takeover['poc_url']}`.")
        if takeover.get("confirm_url") or takeover.get("confirm_status"):
            add(
                f"Request `{target}` again — the PoC page is served through the "
                f"vulnerable subdomain (HTTP {takeover.get('confirm_status')})."
            )
        return "\n".join(lines)

    callbacks = bundle.get("callbacks") or []
    payload = bundle.get("payload") or ""
    if callbacks:
        if payload:
            add(
                f"Trigger the vulnerable functionality with the out-of-band payload "
                f"`{payload}`."
            )
        else:
            add("Trigger the vulnerable functionality with an out-of-band payload.")
        add(
            "Observe an interaction from the target towards the payload domain "
            f"`{bundle.get('oob_domain')}` (DNS/HTTP callback)."
        )
        for cb in callbacks[:3]:
            add(
                f"Callback received: {cb.get('protocol')} from `{cb.get('source')}` "
                f"at {cb.get('occurred_at')}."
            )
        return "\n".join(lines)

    if bundle.get("poc_url"):
        if bundle.get("baseline_url"):
            add(
                f"Open the benign URL and note the normal response "
                f"(HTTP {bundle.get('baseline_status')}): `{bundle['baseline_url']}`"
            )
        param = candidate.get("param") or "vulnerable"
        add(
            f"Open the PoC URL with the payload injected into the `{param}` "
            f"parameter: `{bundle['poc_url']}`"
        )
        signals = bundle.get("signals") or []
        poc_status = bundle.get("poc_status")
        if "location_redirect" in signals:
            add(
                f"Observe HTTP {poc_status} with `Location: {bundle.get('poc_location')}` — "
                f"the request is redirected to attacker-controlled `{payload}`."
            )
        elif "meta_refresh" in signals or "js_redirect" in signals:
            add(
                "Observe the response executes a client-side redirect "
                "(meta refresh / JavaScript) towards the payload."
            )
        elif "oob_callback" in signals:
            add("Observe an out-of-band callback proving server-side fetch of the payload.")
        else:
            add("Observe the response differs from the baseline in an exploitable way.")
        return "\n".join(lines)

    # fallback: chỉ có Candidate + matcher của tool detect
    add(f"Open `{candidate.get('target')}` in a browser or HTTP client.")
    add(
        f"Reproduce the detection ({candidate.get('template_id')} / matcher "
        f"`{candidate.get('matcher_name')}`) and observe the issue."
    )
    return "\n".join(lines)


def _evidence_text(candidate: dict, bundle: dict) -> str:
    blocks: list[str] = []

    curl = bundle.get("curl")
    if curl:
        blocks.append(f"Reproduce the PoC request:\n\n```bash\n{curl}\n```")

    takeover = bundle.get("takeover")
    if isinstance(takeover, dict):
        rows = ["**Takeover evidence:**"]
        if takeover.get("cname"):
            rows.append(f"- CNAME: {', '.join(f'`{c}`' for c in takeover['cname'])}")
        if takeover.get("service"):
            rows.append(f"- Fingerprinted service: `{takeover['service']}`")
        if takeover.get("claim_host"):
            rows.append(f"- Claim host: `{takeover['claim_host']}`")
        if takeover.get("poc_url"):
            rows.append(f"- PoC page (attacker-controlled): `{takeover['poc_url']}`")
        if takeover.get("confirm_url") or takeover.get("confirm_status"):
            rows.append(
                f"- Confirm probe: HTTP {takeover.get('confirm_status')} at "
                f"`{takeover.get('confirm_url')}` — PoC served via subdomain"
            )
        blocks.append("\n".join(rows))

    if bundle.get("poc_status") is not None or bundle.get("baseline_status") is not None:
        rows = ["**Response diff (baseline vs PoC):**"]
        rows.append(f"- Baseline: HTTP {bundle.get('baseline_status')}"
                    + (f", `Location: {bundle['baseline_location']}`" if bundle.get("baseline_location") else ""))
        rows.append(f"- PoC: HTTP {bundle.get('poc_status')}"
                    + (f", `Location: {bundle['poc_location']}`" if bundle.get("poc_location") else ""))
        if bundle.get("payload"):
            rows.append(f"- Payload: `{bundle['payload']}`")
        blocks.append("\n".join(rows))
        if bundle.get("poc_body"):
            blocks.append(
                "PoC response body (excerpt):\n\n```http\n"
                f"{bundle['poc_body']}\n```"
            )

    detail = bundle.get("detail")
    if isinstance(detail, dict):
        missing = detail.get("missing")
        if missing:
            blocks.append(
                "**Missing headers:**\n" + "\n".join(f"- `{h}`" for h in missing)
            )
        markers = detail.get("markers")
        if isinstance(markers, dict):
            strong = markers.get("strong") or []
            if strong:
                blocks.append("**Confirmed markers:**\n" + "\n".join(f"- `{m}`" for m in strong))
        elif isinstance(markers, list) and markers:
            blocks.append("**Confirmed markers:**\n" + "\n".join(f"- `{m}`" for m in markers))

    callbacks = bundle.get("callbacks") or []
    if callbacks:
        rows = ["**Out-of-band callbacks:**"]
        for cb in callbacks[:5]:
            rows.append(
                f"- {cb.get('protocol')} from `{cb.get('source')}` at {cb.get('occurred_at')}"
            )
        blocks.append("\n".join(rows))

    if bundle.get("detection_request"):
        blocks.append(
            "Raw request captured during detection:\n\n```http\n"
            f"{bundle['detection_request']}\n```"
        )
    if bundle.get("detection_response"):
        blocks.append(
            "Raw response captured during detection:\n\n```http\n"
            f"{bundle['detection_response']}\n```"
        )

    return "\n\n".join(blocks) or "(no automated evidence attached — see verify evidence viewer)"


_HEADINGS = {
    "hackerone": {
        "summary": "## Summary",
        "steps": "## Steps to Reproduce",
        "impact": "## Impact",
        "evidence": "## Supporting Material/References",
    },
    "intigriti": {
        "summary": "### Description",
        "steps": "### Steps to Reproduce",
        "impact": "### Impact",
        "evidence": "### Proof of Concept",
    },
}


def format_markdown(sections: dict, platform: str) -> str:
    """Nội dung sections → markdown trọn bản theo MẪU platform (heading H1
    dạng `##`, Intigriti dạng `###` + Description/Proof of Concept)."""
    if platform not in PLATFORMS:
        raise ReportError(f"platform phải là một trong {', '.join(PLATFORMS)}")
    h = _HEADINGS[platform]
    parts = [
        f"# {sections['title']}",
        f"**Severity:** {sections['severity']}",
        f"{h['summary']}\n{sections['summary']}",
        f"{h['steps']}\n{sections['steps_to_reproduce']}",
        f"{h['impact']}\n{sections['impact']}",
        f"{h['evidence']}\n{sections['evidence']}",
    ]
    return "\n\n".join(parts)


def build_draft(candidate: dict, bundle: dict, platform: str) -> dict:
    """Draft report của 1 Finding theo mẫu platform: sections riêng lẻ (cho
    preview sửa + copy từng phần) + markdown trọn bản."""
    if platform not in PLATFORMS:
        raise ReportError(f"platform phải là một trong {', '.join(PLATFORMS)}")
    label, description, impact = _class_meta(candidate.get("class") or "misc")
    host = _host_of(candidate.get("target") or bundle.get("poc_url") or "")
    param = candidate.get("param") or ""
    title = f"{label} in `{param}` parameter on {host}" if param else f"{label} on {host}"
    sections = {
        "title": title,
        "severity": severity_for_platform(candidate.get("severity"), platform),
        "summary": _summary_text(candidate, bundle, description),
        "steps_to_reproduce": _steps_text(candidate, bundle),
        "impact": impact,
        "evidence": _evidence_text(candidate, bundle),
    }
    if bundle.get("human_review_required"):
        # deserialization (batch C #17): Finding luôn kèm cảnh báo human review
        sections["impact"] += (
            " **Note:** the verification payload only demonstrates a benign "
            "ping-back — impact must be confirmed by manual review before "
            "reporting or claiming higher severity."
        )
    return {
        "platform": platform,
        "sections": sections,
        "markdown": format_markdown(sections, platform),
    }


# ───────────────────────────── pipeline (async) ─────────────────────────────


_SELECT_REPORT_CANDIDATE_SQL = """
SELECT c.*, pl.slug AS program_platform
FROM candidates c
JOIN runs r ON r.id = c.run_id
JOIN programs p ON p.id = r.program_id
JOIN platforms pl ON pl.id = p.platform_id
WHERE c.id = $1
"""


async def _fetch_candidate(pool: asyncpg.Pool, candidate_id: int) -> dict | None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(_SELECT_REPORT_CANDIDATE_SQL, candidate_id)
    return dict(row) if row else None


def _parse_drafts(raw) -> dict:
    """report_drafts là JSONB — asyncpg trả str nếu chưa có codec; nhận cả 2."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _resolve_platform(platform: str | None, program_platform: str | None) -> str:
    p = (platform or program_platform or "").strip().lower()
    if p not in PLATFORMS:
        raise ReportError(f"platform phải là một trong {', '.join(PLATFORMS)}")
    return p


def _require_reportable(candidate: dict) -> None:
    status = candidate.get("status")
    if status not in _REPORTABLE:
        raise ReportError(
            f"Chỉ Finding đã xác minh (verified) mới sinh được report — "
            f"Candidate này đang ở trạng thái '{status}'"
        )


async def _load_evidence(pool: asyncpg.Pool, candidate_id: int, path_column: str) -> dict | None:
    """Đọc + parse 1 file evidence của Candidate (path-jail dùng chung với
    viewer); file thiếu/hỏng → None (report vẫn sinh từ phần còn lại)."""
    raw = await read_evidence(pool, candidate_id, path_column=path_column)
    if not raw:
        return None
    try:
        return json.loads(raw["content"])
    except ValueError:
        log.warning("evidence %s không parse được JSON — bỏ qua", raw.get("path"))
        return None


async def load_bundle(pool: asyncpg.Pool, candidate: dict) -> dict:
    """Bundle evidence của Candidate từ 3 nguồn: Detection, vòng xác minh, OOB."""
    detection = await _load_evidence(pool, candidate["id"], "evidence_path")
    verify = await _load_evidence(pool, candidate["id"], "verify_evidence_path")
    oob = await _load_evidence(pool, candidate["id"], "oob_evidence_path")
    return extract_bundle(detection, verify, oob)


def _report_payload(
    candidate: dict, platform: str, program_platform: str | None,
    source: str, sections: dict, markdown: str,
) -> dict:
    return {
        "candidate_id": candidate["id"],
        "platform": platform,
        "program_platform": program_platform,
        "source": source,
        "sections": sections,
        "markdown": markdown,
        "status": candidate.get("status"),
        "report_url": candidate.get("report_url"),
        "report_notes": candidate.get("report_notes"),
        "reported_at": candidate.get("reported_at"),
    }


async def get_report(
    pool: asyncpg.Pool, candidate_id: int,
    platform: str | None = None, refresh: bool = False,
) -> dict | None:
    """Draft report của Finding: mặc định theo platform của Program, ưu tiên
    bản nháp đã lưu (refresh=True → sinh lại từ evidence). GET không tự lưu —
    lưu nháp là hành động PUT của user. Candidate không tồn tại → None."""
    candidate = await _fetch_candidate(pool, candidate_id)
    if candidate is None:
        return None
    program_platform = candidate.pop("program_platform", None)
    platform = _resolve_platform(platform, program_platform)
    _require_reportable(candidate)
    saved = _parse_drafts(candidate.get("report_drafts")).get(platform)
    if saved and not refresh:
        return _report_payload(
            candidate, platform, program_platform, "saved",
            saved.get("sections") or {}, saved.get("markdown") or "",
        )
    bundle = await load_bundle(pool, candidate)
    draft = build_draft(candidate, bundle, platform)
    return _report_payload(
        candidate, platform, program_platform, "generated",
        draft["sections"], draft["markdown"],
    )


async def save_report_draft(
    pool: asyncpg.Pool, candidate_id: int, platform: str, sections: dict,
) -> dict | None:
    """Lưu nháp report (nội dung user đã sửa trên Preview) vào
    `report_drafts` JSONB theo platform — lưu trễ để preview lại sau.
    Worker là NGUỒN SỰ THẬT của markdown: compose lại từ sections tại đây
    (client chỉ copy/preview tức thì, không quyết định nội dung lưu)."""
    platform = _resolve_platform(platform, None)
    candidate = await _fetch_candidate(pool, candidate_id)
    if candidate is None:
        return None
    _require_reportable(candidate)
    section_keys = ("title", "severity", "summary", "steps_to_reproduce",
                    "impact", "evidence")
    safe = {k: str((sections or {}).get(k, "")) for k in section_keys}
    draft = {
        "platform": platform,
        "sections": safe,
        "markdown": format_markdown(safe, platform),
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    payload = json.dumps({platform: draft}, ensure_ascii=False)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"UPDATE candidates "
            f"SET report_drafts = COALESCE(report_drafts, '{{}}'::jsonb) || $2::jsonb "
            f"WHERE id = $1 RETURNING {CANDIDATE_COLS}",
            candidate_id, payload,
        )
    return dict(row) if row else None


async def mark_reported(
    pool: asyncpg.Pool, candidate_id: int,
    report_url: str | None = None, report_notes: str | None = None,
) -> dict | None:
    """User đã TỰ nộp report trên platform → đánh dấu `reported` + link + ngày
    nộp (now()) + ghi chú tự do. KHÔNG có request nào gửi đi platform ở đây —
    auto-submit là v2. Trạng thái không hợp lệ → ReportError."""
    candidate = await _fetch_candidate(pool, candidate_id)
    if candidate is None:
        return None
    _require_reportable(candidate)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"UPDATE candidates "
            f"SET status = 'reported', reported_at = now(), "
            f"    report_url = COALESCE($2, report_url), "
            f"    report_notes = COALESCE($3, report_notes) "
            f"WHERE id = $1 RETURNING {CANDIDATE_COLS}",
            candidate_id, (report_url or None), (report_notes or None),
        )
    return dict(row) if row else None
