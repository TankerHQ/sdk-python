import time
import threading

from tanker import Tanker, Status as TankerStatus, Error as TankerError, get_answer

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
        writable_path=tmp_path
    )
    assert tanker.version == "1.4.0"
    assert tanker.trustchain_url == TRUSTCHAIN_URL


def test_init_tanker_invalid_url(tmp_path):
    with pytest.raises(TankerError) as e:
        Tanker(
            trustchain_url=TRUSTCHAIN_URL,
            trustchain_id="invalid bad 64",
            trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
            writable_path=tmp_path
        )
    assert "parse error" in e.value.args[0]


def test_open_new_account(tmp_path):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path=tmp_path,
    )
    fake = Faker()
    user_id = fake.email()
    print("Creating account for", user_id)
    token = tanker.generate_user_token(user_id)
    tanker.open(user_id, token)
    assert tanker.status == TankerStatus.OPEN
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
        writable_path=alice_path
    )
    alice_token = alice_tanker.generate_user_token(alice_id)
    alice_tanker.open(alice_id, alice_token)
    message = b"I love you"
    encrypted_data = alice_tanker.encrypt(message)
    time.sleep(5)
    clear_data = alice_tanker.decrypt(encrypted_data)
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
        writable_path=alice_path
    )
    alice_token = alice_tanker.generate_user_token(alice_id)
    alice_tanker.open(alice_id, alice_token)
    bob_path = tmp_path.joinpath("bob")
    bob_path.mkdir_p()
    bob_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path=bob_path
    )
    bob_id = fake.email()
    bob_token = bob_tanker.generate_user_token(bob_id)
    bob_tanker.open(bob_id, bob_token)
    message = b"I love you"
    encrypted = alice_tanker.encrypt(message, share_with=[bob_id])
    decrypted = bob_tanker.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.skip("Need proper async stuff")
def test_add_device(tmp_path):
    fake = Faker()
    alice_id = fake.email()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path=laptop_path
    )
    alice_token = laptop_tanker.generate_user_token(alice_id)
    laptop_tanker.open(alice_id, alice_token)
    time.sleep(5)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()

    phone_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path=phone_path,
    )

    def on_waiting_for_validation(code):
        print("waiting for validation with code", code)
        print("accepting phone on laptop ...")
        laptop_tanker.accept_device(code)
        print("done accepting phone on laptop")

    phone_tanker.on_waiting_for_validation = on_waiting_for_validation

    class PhoneOpenThread(threading.Thread):
        def __init__(self):
            super().__init__(name="phone.open() thread")

        def run(self):
            phone_tanker.open(alice_id, alice_token)

    phone_open_thread = PhoneOpenThread()
    print("starting phone_tanker.open() in a thread ...")
    phone_open_thread.start()
    print("sleeping 5 sec")
    time.sleep(5)
    phone_open_thread.join()
    print("done")


@pytest.mark.asyncio
async def test_anwser():
    res = await get_answer()
    assert res == 42


@pytest.mark.asyncio
async def test_async_open(tmp_path):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path=tmp_path,
    )
    fake = Faker()
    user_id = fake.email()
    print("Creating account for", user_id)
    token = tanker.generate_user_token(user_id)
    await tanker.async_open(user_id, token)
    assert tanker.status == TankerStatus.OPEN

if __name__ == "__main__":
    test_open_new_account("/tmp/test")
