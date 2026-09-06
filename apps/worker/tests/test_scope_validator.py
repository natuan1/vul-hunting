"""Test Scope Validator (ticket #7) — logic đối chiếu thuần, không DB.

Chạy trong container worker:
    docker compose exec worker python -m pytest tests -q
"""

import pytest

from app.scope_validator import NON_PROD_LABELS, ScopeDecision, check_target, target_host

SCOPE = [
    {"asset_identifier": "agilebits.com", "asset_type": "URL"},
    {"asset_identifier": "*.1password.com", "asset_type": "WILDCARD"},
    {"asset_identifier": "https://api.agilebits.com", "asset_type": "URL"},
    {"asset_identifier": "dev.agilebits.com", "asset_type": "URL"},  # non-prod nhưng NẰM TRONG scope tường minh
    {"asset_identifier": "com.example.app", "asset_type": "GOOGLE_PLAY_APP"},  # không phải host
]

ALLOWED = "allowed"
BLOCKED_SCOPE = "blocked_out_of_scope"
BLOCKED_NON_PROD = "blocked_non_prod"


def dec(target: str, allow_non_prod: bool = False) -> ScopeDecision:
    return check_target(target, SCOPE, allow_non_prod=allow_non_prod)


# ── chuẩn hoá target ──


@pytest.mark.parametrize(
    "raw,host",
    [
        ("agilebits.com", "agilebits.com"),
        ("  AgileBits.COM  ", "agilebits.com"),  # trim + lowercase
        ("https://api.agilebits.com/x?y=1", "api.agilebits.com"),
        ("http://API.agilebits.com:8443", "api.agilebits.com"),
        ("*.1password.com.", "*.1password.com"),  # dot cuối
    ],
)
def test_target_host_chuẩn_hoá(raw, host):
    assert target_host(raw) == host


# ── allowed ──


def test_exact_match_được_cho_phép():
    assert dec("agilebits.com").decision == ALLOWED
    assert "tường minh" in dec("agilebits.com").reason


def test_wildcard_match_subdomain_và_subdomain_sâu():
    assert dec("app.1password.com").decision == ALLOWED
    assert dec("a.b.c.1password.com").decision == ALLOWED


def test_url_asset_match_theo_host():
    assert dec("api.agilebits.com").decision == ALLOWED


def test_chữ_hoa_vẫn_match():
    assert dec("APP.1PASSWORD.COM").decision == ALLOWED


# ── blocked: ngoài scope ──


def test_ngoài_scope_bị_chặn():
    assert dec("out-of-scope.invalid").decision == BLOCKED_SCOPE


def test_apex_không_tự_match_wildcard():
    # *.1password.com không bao hàm apex 1password.com
    assert dec("1password.com").decision == BLOCKED_SCOPE


def test_đổi_hậu_tố_không_lọt():
    assert dec("evil-1password.com").decision == BLOCKED_SCOPE
    assert dec("1password.com.evil.io").decision == BLOCKED_SCOPE
    assert dec("not1password.com").decision == BLOCKED_SCOPE


def test_asset_không_phải_host_không_match_được():
    assert dec("com.example.app").decision == BLOCKED_SCOPE


# ── non-production ──


def test_non_prod_dưới_wildcard_bị_flag():
    d = dec("dev.1password.com")
    assert d.decision == BLOCKED_NON_PROD
    assert d.allowed is False


def test_non_prod_được_phép_khi_config():
    assert dec("dev.1password.com", allow_non_prod=True).decision == ALLOWED


def test_non_prod_tường_minh_trong_scope_vẫn_được():
    # dev.agilebits.com là asset tường minh — không bị flag
    assert dec("dev.agilebits.com").decision == ALLOWED


@pytest.mark.parametrize("label", sorted(NON_PROD_LABELS))
def test_đủ_7_nhãn_non_prod(label):
    d = check_target(f"{label}.1password.com", SCOPE)
    assert d.decision == BLOCKED_NON_PROD


def test_nhãn_non_prod_ở_giữa_cũng_bị_flag():
    # non-prod khớp BẤT KỲ nhãn nào — api.dev.* vẫn là môi trường dev
    d = check_target("api.dev.1password.com", SCOPE)
    assert d.decision == BLOCKED_NON_PROD
    assert d.allowed is False
