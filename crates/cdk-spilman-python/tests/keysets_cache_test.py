import sys
from pathlib import Path


EXAMPLE_DIR = Path(__file__).resolve().parents[3] / "examples" / "python-ascii-art"
sys.path.insert(0, str(EXAMPLE_DIR))

import server as ascii_server  # noqa: E402


def reset_keyset_cache():
    ascii_server.keyset_cache.clear()


def test_refresh_retains_inactive(monkeypatch):
    reset_keyset_cache()
    mint_url = "http://mint.test"
    ascii_server.keyset_cache[(mint_url, "A")] = {
        "info_json": "infoA",
        "active": True,
        "unit": "sat",
    }

    entries = [
        {"id": "A", "unit": "sat", "active": False, "info_json": "infoA"},
        {"id": "B", "unit": "sat", "active": True, "info_json": "infoB"},
    ]

    monkeypatch.setattr(ascii_server, "fetch_all_keysets_from_mint", lambda _url: entries)

    ascii_server.refresh_all_keysets(mint_url)

    assert ascii_server.keyset_cache[(mint_url, "A")]["active"] is False
    assert (mint_url, "B") in ascii_server.keyset_cache


def test_refresh_does_not_drop_missing(monkeypatch):
    reset_keyset_cache()
    mint_url = "http://mint.test"
    ascii_server.keyset_cache[(mint_url, "A")] = {
        "info_json": "infoA",
        "active": True,
        "unit": "sat",
    }

    entries = [
        {"id": "B", "unit": "sat", "active": True, "info_json": "infoB"},
    ]

    monkeypatch.setattr(ascii_server, "fetch_all_keysets_from_mint", lambda _url: entries)

    ascii_server.refresh_all_keysets(mint_url)

    assert (mint_url, "A") in ascii_server.keyset_cache
    assert (mint_url, "B") in ascii_server.keyset_cache
