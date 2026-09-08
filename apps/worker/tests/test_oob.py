"""Test Interactsh OOB client (ticket #13) — phần seam thuần.

Sinh token/domain payload, map callback → Candidate theo token, chuẩn hoá
interaction, giải mã poll response (RSA-OAEP-SHA256 + AES-CTR, đúng giao thức
interactsh), expiry của registration, ghi evidence OOB.

Chạy trong container worker:
    docker compose run --rm worker python -m pytest tests/test_oob.py -q
"""

import base64
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from app import config
from app.oob import (
    ZBASE32_ALPHABET,
    candidate_id_from_token,
    candidate_token,
    decrypt_interactions,
    extract_label,
    generate_rsa_keypair,
    is_active,
    new_correlation_id,
    new_nonce,
    new_secret_key,
    parse_interaction,
    parse_servers,
    payload_domain,
    write_oob_evidence,
)

# ── sinh token / correlation-id / nonce: DNS-safe, đúng độ dài chuẩn ──


def test_correlation_id_20_ký_tự_dns_safe():
    cid = new_correlation_id()
    assert len(cid) == 20
    assert all(ch in ZBASE32_ALPHABET for ch in cid)
    assert cid == cid.lower()


def test_nonce_13_ký_tự_và_không_lặp():
    nonces = {new_nonce() for _ in range(50)}
    assert len(nonces) == 50
    assert all(len(n) == 13 for n in nonces)


def test_secret_key_dạng_uuid():
    s = new_secret_key()
    assert len(s) == 36 and s.count("-") == 4  # uuid4 chuẩn của client Go


def test_payload_domain_nối_correlation_id_nonce_và_host():
    assert (
        payload_domain("abcdefghijklmnopqrst", "oast.pro", "1234567890abc")
        == "abcdefghijklmnopqrst1234567890abc.oast.pro"
    )


# ── token per-Candidate + map callback → candidate ──


def test_candidate_token_chứa_candidate_id_và_nonce():
    token = candidate_token(42, "ybndrfg8ejkmc")
    assert token == "c42nybndrfg8ejkmc"
    assert candidate_id_from_token(token) == 42


def test_candidate_id_from_token_không_khớp_trả_none():
    assert candidate_id_from_token("c42nybndrfg8ejkmc") == 42
    assert candidate_id_from_token("abcdefghijklmnopqrst1234567890abc") is None
    assert candidate_id_from_token("xx42nybndrfg8ejkmc") is None
    assert candidate_id_from_token("") is None


def test_extract_label_lấy_nhãn_trái_nhất_lowercase():
    assert extract_label("c42nybndrfg8ejkmc") == "c42nybndrfg8ejkmc"
    assert extract_label("c42nybndrfg8ejkmc.sub") == "c42nybndrfg8ejkmc"
    assert extract_label("") == ""
    assert extract_label(None) == ""


# ── parse_servers: danh sách server public, shuffle nhưng vẫn đủ bộ ──


def test_parse_servers_bỏ_scheme_và_shuffle_đủ_bộ():
    servers = parse_servers("https://oast.pro,oast.live,http://oast.site")
    assert sorted(servers) == ["oast.live", "oast.pro", "oast.site"]
    assert parse_servers("") == []


# ── RSA keypair đúng định dạng giao thức ──


def test_generate_rsa_keypair_public_b64_giải_mã_được_pem():
    private_pem, public_b64 = generate_rsa_keypair()
    assert b"PRIVATE KEY" in private_pem.encode()
    pem = base64.b64decode(public_b64)
    assert b"PUBLIC KEY" in pem  # PEM SubjectPublicKeyInfo — server Go parse OK


# ── decrypt poll response: đúng cơ chế server mã hoá ──


def _encrypt_like_server(aes_key: bytes, iv: bytes, plaintext: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).encryptor()
    return base64.b64encode(iv + encryptor.update(plaintext) + encryptor.finalize()).decode()


def test_decrypt_interactions_round_trip_rsa_oaep_aes_ctr():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    private_pem, public_b64 = generate_rsa_keypair()
    public_key = serialization.load_pem_public_key(
        base64.b64decode(public_b64)
    )
    aes_key = os.urandom(32)
    aes_key_b64 = base64.b64encode(
        public_key.encrypt(aes_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None,
        ))
    ).decode()
    interaction = {"protocol": "dns", "full-id": "abc", "remote-address": "1.2.3.4"}
    item = _encrypt_like_server(
        aes_key, os.urandom(16),
        (json.dumps(interaction) + "\n").encode(),
    )
    out = decrypt_interactions(private_pem, aes_key_b64, [item])
    assert out == [interaction]


def test_decrypt_interactions_lỗi_giải_má_raise_valueerror():
    private_pem, _ = generate_rsa_keypair()
    with pytest.raises(ValueError):
        decrypt_interactions(private_pem, "không-phải-base64!!", ["x"])


# ── parse_interaction: chuẩn hoá đúng 4 trường ticket yêu cầu ──


def test_parse_interaction_chuẩn_hoá_source_protocol_timestamp():
    raw = {
        "protocol": "http",
        "unique-id": "c7nabc",
        "full-id": "c7nabc",
        "remote-address": "93.184.216.34:41234",
        "timestamp": "2026-09-08T01:02:03.123456789Z",
        "raw-request": "GET / HTTP/1.1",
    }
    rec = parse_interaction(raw)
    assert rec["protocol"] == "http"
    assert rec["source"] == "93.184.216.34:41234"
    assert rec["unique_id"] == "c7nabc"
    assert rec["full_id"] == "c7nabc"
    assert rec["occurred_at"] == datetime(
        2026, 9, 8, 1, 2, 3, 123456, tzinfo=timezone.utc
    )
    assert rec["raw_interaction"] == raw  # raw interaction giữ nguyên


def test_parse_interaction_thiếu_trường_vẫn_an_toàn():
    rec = parse_interaction({"protocol": "dns"})
    assert rec["source"] == ""
    assert rec["occurred_at"] is None
    assert rec["raw_interaction"] == {"protocol": "dns"}


# ── is_active: callback cache sống đủ lâu cho verify dài, hết hạn rõ ràng ──


NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)


def test_is_active_theo_status_và_hạn():
    fresh = {"status": "active", "expires_at": NOW + timedelta(hours=1)}
    assert is_active(fresh, NOW)
    assert not is_active({**fresh, "expires_at": NOW}, NOW)
    assert not is_active({**fresh, "status": "closed"}, NOW)
    assert not is_active({**fresh, "status": "expired"}, NOW)


# ── write_oob_evidence: file JSON trên volume ──


def test_write_oob_evidence_ghi_file_giữa_run_và_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", str(tmp_path / "evidence"))
    record = {"schema": "vulhunt.oob-evidence/1", "callbacks": [{"protocol": "dns"}]}
    path = write_oob_evidence(7, 42, record)
    assert path is not None and os.path.exists(path)
    assert f"{tmp_path}/evidence/7/oob/042.json" == path
    content = json.loads(open(path, encoding="utf-8").read())
    assert content["callbacks"][0]["protocol"] == "dns"


def test_write_oob_evidence_io_lỗi_trả_none_không_chết(monkeypatch):
    monkeypatch.setattr(config.settings, "evidence_dir", "/proc/không-ghi-được/x")
    assert write_oob_evidence(7, 1, {"callbacks": []}) is None
