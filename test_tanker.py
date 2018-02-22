import tanker
from tanker import Tanker

import pytest

TRUSTCHAIN_URL = "https://dev-api.tanker.io"
TRUSTCHAIN_ID = "EBwzNy5/hFgxqSSgN4FPdm2PrEaGMhHXr8g6v05U1Zg="
TRUSTCHAIN_PRIVATE_KEY = "t8SvaSQ6E/6w41bKNQThkzCZKU9lqDjoz9M0syrJuglB4J/bDaQTpOXNeYiOtoX6ToTaifmlbkp5FyqQtpFElw=="  # noqa


def test_init_tanker_ok(tmpdir):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        db_storage_path=str(tmpdir)
    )
    assert tanker.version == "1.4.0"
    assert tanker.trustchain_url == TRUSTCHAIN_URL


def test_init_tanker_invalid_url(tmpdir):
    with pytest.raises(tanker.Error) as e:
        Tanker(
            trustchain_url=TRUSTCHAIN_URL,
            trustchain_id="invalid bad 64",
            trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
            db_storage_path=str(tmpdir)
        )
    assert "parse error" in e.value.args[0]


def test_open(tmpdir):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        db_storage_path=str(tmpdir)
    )
    token = tanker.make_user_token("python-test-1", "s3cr3t")
    tanker.open(token)
