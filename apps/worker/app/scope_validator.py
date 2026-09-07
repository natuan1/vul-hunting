"""Scope Validator (ticket #7) — chặn cứng mọi target không thuộc Scope.

Đây là cửa ắt BẮT BUỘC cho mọi ticket gửi traffic thật phía sau: tool execution
phải gọi `check_target()` (trực tiếp hoặc qua `ToolContext.validate()` trong
runner) trước khi chạm tới target. Đối chiếu với Scope snapshot của Run đang
chạy (chụp từ DB lúc tạo Run), hỗ trợ wildcard `*.domain` (bao cả subdomain
sâu), flag subdomain non-production để loại khỏi auto-testing (config được).

Module này cố tình KHÔNG đụng DB — logic đối chiếu thuần để test được; phần
ghi audit log nằm ở `audit.py`.
"""

from dataclasses import dataclass

# Asset type là host thật (URL/WILDCARD) — các loại khác (app store, OTHER)
# không phải bề mặt network nên không match theo host
_HOST_TYPES = {"URL", "WILDCARD"}

# Nhãn môi trường non-production — khớp ở BẤT KỲ nhãn nào của host:
# dev.1password.com lẫn api.dev.1password.com đều bị flag. Chặn nhầm thì
# thấy rõ trong audit log; lọt thì thành traffic ngoài ý muốn.
NON_PROD_LABELS = frozenset(
    {"dev", "staging", "uat", "qa", "sandbox", "test", "preview"}
)


@dataclass
class ScopeDecision:
    decision: str  # 'allowed' | 'blocked_out_of_scope' | 'blocked_non_prod'
    reason: str  # tiếng Việt cho audit log + log stream

    @property
    def allowed(self) -> bool:
        """Dẫn xuất từ decision — một nguồn sự thật duy nhất."""
        return self.decision == "allowed"


def target_host(raw: str) -> str:
    """Chuẩn hoá target về host: bỏ scheme/port/đường dẫn, trim, lowercase."""
    t = (raw or "").strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    t = t.split(":", 1)[0]
    return t.rstrip(".")


def _asset_host(identifier: str) -> str | None:
    """Host của 1 Asset; trả None nếu Asset không phải host (vd GOOGLE_PLAY_APP)."""
    host = target_host(identifier)
    return host or None


def check_target(
    raw_target: str,
    snapshot: list[dict],
    allow_non_prod: bool = False,
    allow_wildcard_base: bool = False,
) -> ScopeDecision:
    """Đối chiếu target với Scope snapshot của Run.

    Thứ tự: match tường minh (exact) → match wildcard → flag non-prod
    (chỉ khi match qua wildcard — asset tường minh trong scope thì đương nhiên
    được phép, kể cả mang nhãn non-prod). Ngoài tất cả → chặn.

    `allow_wildcard_base`: cho phép đúng BASE của wildcard (vd example.com của
    *.example.com) — chỉ dùng cho passive discovery (subfinder/amass tra cứu
    dữ liệu công khai về không gian subdomain mà wildcard đã khai báo), KHÔNG
    dùng cho probe chủ động (naabu/httpx vẫn phải bám asset tường minh).

    Hạn chế ghi nhận: Asset URL có đường dẫn (vd https://example.com/api)
    hiện match theo HOST — ràng buộc path sẽ xử lý khi có tool thật
    (stub hiện tại chỉ làm việc ở mức host).
    """
    host = target_host(raw_target)

    explicit: set[str] = set()
    wildcards: list[str] = []
    for asset in snapshot:
        if (asset.get("asset_type") or "") not in _HOST_TYPES:
            continue
        ident = _asset_host(asset.get("asset_identifier") or "")
        if ident is None:
            continue
        if ident.startswith("*."):
            wildcards.append(ident[2:])
        else:
            explicit.add(ident)

    if host in explicit:
        return ScopeDecision("allowed", f"trong Scope (Asset tường minh {host})")

    wildcard_hit: str | None = None
    for base in wildcards:
        # wildcard chỉ bao SUBDOMAIN (kể cả sâu) — apex phải được khai báo tường minh
        if host.endswith("." + base):
            wildcard_hit = base
            break
    if wildcard_hit is not None:
        hit = next((lb for lb in host.split(".") if lb in NON_PROD_LABELS), None)
        if hit is not None and not allow_non_prod:
            return ScopeDecision(
                "blocked_non_prod",
                f"{host} match wildcard *.{wildcard_hit} nhưng mang nhãn "
                f"non-production ({hit}.) — mặc định không auto-test",
            )
        return ScopeDecision("allowed", f"trong Scope (match wildcard *.{wildcard_hit})")

    if host in wildcards and allow_wildcard_base:
        return ScopeDecision(
            "allowed",
            f"root của wildcard *.{host} — passive discovery trên không gian "
            f"subdomain đã khai báo",
        )

    return ScopeDecision(
        "blocked_out_of_scope", f"{host} không thuộc Scope của Run"
    )
