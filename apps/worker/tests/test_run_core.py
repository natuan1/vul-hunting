"""Test các seam thuần của Run core (ticket #6).

Chạy trong container worker:
    docker compose exec worker python -m pytest tests -q
"""

from app import config
from app.jobqueue import _backoff
from app.runs import default_ident


def test_backoff_tăng_luỹ_thừa_và_chặn_trần():
    assert _backoff(1) == 5.0
    assert _backoff(2) == 10.0
    assert _backoff(3) == 20.0
    assert _backoff(10) == 300.0  # chặn trần 5 phút


def test_default_ident_hackerone_dùng_username_env(monkeypatch):
    monkeypatch.setattr(config.settings, "hackerone_username", "tuantest")
    assert default_ident("hackerone") == ("X-Bug-Bounty", "HackerOne-tuantest")


def test_default_ident_intigriti_không_có_username_trả_none(monkeypatch):
    monkeypatch.setattr(config.settings, "intigriti_username", "")
    assert default_ident("intigriti") is None


def test_default_ident_platform_lạ_trả_none():
    assert default_ident("yeswehack") is None
