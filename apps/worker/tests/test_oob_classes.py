"""Test pure seam của catalog batch C (ticket #17) — 4 lớp OOB (blind XSS,
SSRF, XXE, deserialization): payload builder nhúng token interactsh, guard
payload gây cost (Code of Conduct Intigriti — không SMS/API tốn phí), cờ
human review + severity thận trọng cho deserialization, và map_class nhận
thêm 2 lớp mới.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_oob_classes.py -q
"""

import base64

import pytest

from app.detect import map_class
from app.oob import (
    DESERIALIZATION_SEVERITY_CAP,
    OOB_VERIFY_CLASSES,
    blind_xss_payload,
    cap_deser_severity,
    deserialization_payload,
    find_costly_payload_pattern,
    oob_payload,
    ssrf_payload,
    xxe_payload,
)

TOKEN = "c7ybndrfg8ejkmc"
DOMAIN = "abcdefghijklmnopqrst1234567890abc.oast.pro"
HOST = f"{TOKEN}.{DOMAIN}"


# ── 4 lớp OOB đều trong danh sách verify ──


def test_oob_verify_classes_gồm_4_lớp_batch_c():
    assert OOB_VERIFY_CLASSES == ("ssrf", "xss", "xxe", "deserialization")


# ── payload builder: token interactsh nhúng đúng cách từng lớp ──


def test_payload_ssrf_dạng_url():
    """SSRF: payload hệ thống — URL trỏ thẳng tới domain interactsh."""
    p = ssrf_payload(TOKEN, DOMAIN)
    assert p == f"http://{HOST}"


def test_payload_blind_xss_script_tag_kiểu_dalfox():
    """Blind XSS: payload kiểu dalfox — tag script protocol-relative; trình
    duyệt (admin viewer) fetch script → HTTP callback về interactsh."""
    p = blind_xss_payload(TOKEN, DOMAIN)
    assert p == f'"><script src=//{HOST}></script>'


def test_payload_xxe_external_entity():
    """XXE: DOCTYPE khai báo external entity SYSTEM trỏ tới interactsh —
    server parse XML → resolve entity → HTTP callback."""
    p = xxe_payload(TOKEN, DOMAIN)
    assert p.startswith("<?xml version=")
    assert f'<!DOCTYPE' in p
    assert f'<!ENTITY' in p and f'SYSTEM "http://{HOST}' in p
    assert "&" in p and ";" in p  # entity được tham chiếu trong document


def test_payload_deserialization_ping_back_an_toàn():
    """Deserialization: stream Java dạng URLDNS — CHỈ ping-back DNS/HTTP,
    KHÔNG gadget thực thi. Base64 giải ra magic stream `aced0005`, chứa host
    interactsh, và KHÔNG chứa tên class gadget nào."""
    p = deserialization_payload(TOKEN, DOMAIN)
    raw = base64.b64decode(p, validate=True)
    assert raw[:4] == b"\xac\xed\x00\x05"  # magic Java serialization
    assert HOST.encode() in raw
    # cấu trúc chỉ gồm HashMap + java.net.URL + String — không gadget RCE
    assert b"java.util.HashMap" in raw
    assert b"java.net.URL" in raw
    low = raw.lower()
    for gadget in (
        "commons", "invokertransformer", "templatesimpl", "runtime",
        "processbuilder", "transformedchain", "annotationinvocationhandler",
        "rmi", "jndi", "ldap", "rmiregistry",
    ):
        assert gadget.encode() not in low, f"payload chứa gadget cấm: {gadget}"


def test_payload_deserialization_token_khác_payload_khác():
    a = deserialization_payload("c1ybndrfg8ejkmc", DOMAIN)
    b = deserialization_payload("c2ybndrfg8ejkmc", DOMAIN)
    assert a != b
    # token của từng payload nằm trong stream của CHÍNH payload đó
    assert b"c1ybndrfg8ejkmc" in base64.b64decode(a)
    assert b"c2ybndrfg8ejkmc" in base64.b64decode(b)
    assert b"c1ybndrfg8ejkmc" not in base64.b64decode(b)


def test_oob_payload_dispatch_theo_class():
    assert oob_payload("ssrf", TOKEN, DOMAIN) == ssrf_payload(TOKEN, DOMAIN)
    assert oob_payload("xss", TOKEN, DOMAIN) == blind_xss_payload(TOKEN, DOMAIN)
    assert oob_payload("xxe", TOKEN, DOMAIN) == xxe_payload(TOKEN, DOMAIN)
    assert oob_payload("deserialization", TOKEN, DOMAIN) == deserialization_payload(
        TOKEN, DOMAIN
    )
    with pytest.raises(ValueError):
        oob_payload("redirect", TOKEN, DOMAIN)


# ── guard payload gây cost (Intigriti CoC: không SMS/API tốn phí) ──


def test_find_costly_payload_pattern_phát_hiện_sms_và_api_tốn_phí():
    for payload in (
        'sms:+84901234567?body=hi',
        "tel:+84901234567",
        "https://api.twilio.com/2010-04-01/Accounts/x/Messages.json",
        "https://rest.nexmo.com/sms/json",
        "https://messaging.vonage.com/1/messages",
        "https://api.messagebird.com/v1/messages",
        "https://api.plivo.com/v1/Account/x/Message/",
    ):
        assert find_costly_payload_pattern(payload) is not None, payload


def test_find_costly_payload_pattern_payload_an_toàn_thì_none():
    assert find_costly_payload_pattern(ssrf_payload(TOKEN, DOMAIN)) is None
    assert find_costly_payload_pattern(blind_xss_payload(TOKEN, DOMAIN)) is None
    assert find_costly_payload_pattern(xxe_payload(TOKEN, DOMAIN)) is None
    assert find_costly_payload_pattern(deserialization_payload(TOKEN, DOMAIN)) is None
    assert find_costly_payload_pattern("") is None


# ── deserialization: severity thận trọng (chỉ chứng minh ping-back) ──


def test_deser_severity_cap_là_medium():
    assert DESERIALIZATION_SEVERITY_CAP == "medium"
    assert cap_deser_severity("critical") == "medium"
    assert cap_deser_severity("high") == "medium"
    assert cap_deser_severity("medium") == "medium"
    assert cap_deser_severity("low") == "low"
    assert cap_deser_severity("lạ") == "medium"


# ── detection: map_class nhận thêm lớp batch C ──


def test_map_class_batch_c_xxe_và_deserialization():
    assert map_class(["xxe", "injection"]) == "xxe"
    assert map_class(["deserialization"]) == "deserialization"
    assert map_class(["deser"]) == "deserialization"  # alias tag nuclei
    # template-id chính xác hơn tag
    assert map_class(["injection"], template_id="blind-xss-when-parsed") == "xss"
    assert map_class(["cve"], template_id="java-deserialization-jndi") == (
        "deserialization"
    )
    assert map_class([], template_id="xxe-parameter-injection") == "xxe"
    # class cũ không đổi hành vi
    assert map_class(["xss", "reflected"]) == "xss"
    assert map_class(["ssrf"]) == "ssrf"
