import tanker
from tanker import Tanker

import path
from faker import Faker

import pytest


TRUSTCHAIN_URL = "https://dev-api.tanker.io"
TRUSTCHAIN_ID = "Lj93QRsF4aadPoT/abm/ZUS1YqC5StX+B326stEeiT8="
TRUSTCHAIN_PRIVATE_KEY = "TZEIID4mTQta0xtLSNzh/mejX1SOjLb4l8tLCbORHpk29v9yEMS7uk0s9GlbPtuqn5+morIna1Op2F8Y6uTl2Q=="  # noqa

ALICE_ID = "mcbriderobin@walter-cochran.org"
ALICE_TOKEN = "eyJkZWxlZ2F0aW9uX3NpZ25hdHVyZSI6IlllSU9PWkFxQ3BwRHBXOHl2bVV6VDQ3UXNvZEFjZUV2R2VZQXIycDBWVFBnYmxDWEpyeGxBTVpjRGVKbkVoZDRDRmJPZVJaRXBYMmlQWVBpSFdvR0RBPT0iLCJlcGhlbWVyYWxfcHJpdmF0ZV9zaWduYXR1cmVfa2V5IjoiYXRXenAwaFRsdXEvUXE0VEZneUw3SWlibjcxM3ZvUGpoMU1DWVZjaG9SRkhWTFdha3pKaWwrbXF3RVdJdFVYNTJTU0l1VTJ0MGJoR3NFcmhzTG1GZUE9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6IlIxUzFtcE15WXBmcHFzQkZpTFZGK2Rra2lMbE5yZEc0UnJCSzRiQzVoWGc9IiwidXNlcl9pZCI6Ik4vNlI3WC9ReGJ0amNaVWRJNm5UNFA0cFZ3Z3Z6ZWtiMi9jMjF5VjAzdzQ9IiwidXNlcl9zZWNyZXQiOiJoTnZ4Wmg0aklQWHQ4N3N4TmtETE5nRHVGN0FMMEd4dU5yM29LbnhWcjF3PSJ9"  # noqa


BOB_ID = "juanwhite@hotmail.com"
BOB_TOKEN = "eyJkZWxlZ2F0aW9uX3NpZ25hdHVyZSI6IlFXekpiTFUrLzdyZ2lvd2ZpcjRhRm81QnNCa2ZNYTFMU3pkQkVFWjFRcnZNUGNFYnpDVFpST0ExWWNzRHFNNGFpQmxXcHZrZmFBNS93aHpsbG1URUFnPT0iLCJlcGhlbWVyYWxfcHJpdmF0ZV9zaWduYXR1cmVfa2V5IjoiRmNDWFQyZzg0bGdrVmp4eWlCZTNDSDU3SnVldTdqcTkwWWQrUE9CSGFqTDdJc0t0Q251Uk1PSDhpZExXN1p2eEk1Nmd3MXF6Ym1FckMzQzdCOVYvc0E9PSIsImVwaGVtZXJhbF9wdWJsaWNfc2lnbmF0dXJlX2tleSI6Iit5TENyUXA3a1REaC9JblMxdTJiOFNPZW9NTmFzMjVoS3d0d3V3ZlZmN0E9IiwidXNlcl9pZCI6Ikk2UXQ5dVpaMk1SaWFtOHBrb2NXOG9MNkxCRUpCK3pkWjh0ajREWG02WE09IiwidXNlcl9zZWNyZXQiOiJDMzIySHNFOERRRCtueUlubUpBU3MvakpWNi9ERUZ2Ym8xdnlmN1M3MmtvPSJ9"  # noqa


@pytest.fixture()
def tmp_path(tmpdir):
    return path.Path(str(tmpdir))


def test_init_tanker_ok(tmp_path):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        db_storage_path=tmp_path
    )
    assert tanker.version == "1.4.0"
    assert tanker.trustchain_url == TRUSTCHAIN_URL


def test_init_tanker_invalid_url(tmp_path):
    with pytest.raises(tanker.Error) as e:
        Tanker(
            trustchain_url=TRUSTCHAIN_URL,
            trustchain_id="invalid bad 64",
            trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
            db_storage_path=tmp_path
        )
    assert "parse error" in e.value.args[0]


def test_open_new_account(tmp_path):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        db_storage_path=tmp_path,
    )
    fake = Faker()
    user_name = fake.email()
    print("Creating account for", user_name)
    token = tanker.generate_user_token(user_name)
    tanker.open(token)
    tanker.close()


def test_encrypt_decrypt(tmp_path):
    fake = Faker()
    alice_id = fake.email()
    alice_path = tmp_path.joinpath("alice")
    alice_path.mkdir_p()
    alice_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        db_storage_path=alice_path
    )
    alice_token = alice_tanker.generate_user_token(alice_id)
    alice_tanker.open(alice_token)
    message = b"I love you"
    encrypted_data = alice_tanker.encrypt(message)
    clear_data = alice_tanker.decrypted(encrypted_data)
    assert clear_data == message


def test_share(tmp_path):
    fake = Faker()
    alice_id = fake.email()
    alice_path = tmp_path.joinpath("alice")
    alice_path.mkdir_p()
    alice_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        db_storage_path=alice_path
    )
    alice_token = alice_tanker.generate_user_token(alice_id)
    alice_tanker.open(alice_token)
    bob_path = tmp_path.joinpath("bob")
    bob_path.mkdir_p()
    bob_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        db_storage_path=bob_path
    )
    bob_id = fake.email()
    bob_token = bob_tanker.generate_user_token(bob_id)
    bob_tanker.open(bob_token)
    message = b"I love you"
    encrypted = alice_tanker.encrypt(message, share_with=[bob_id])
    assert encrypted


if __name__ == "__main__":
    test_open_new_account("/tmp/test")
