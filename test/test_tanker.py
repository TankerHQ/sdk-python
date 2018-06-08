import asyncio
from tankersdk.core import Tanker, Status as TankerStatus, Error as TankerError

import path
from faker import Faker

import pytest


TRUSTCHAIN_URL = "https://dev-api.tanker.io"
TRUSTCHAIN_ID = "P8Gxs6M4v6tORNbETX9SDdqLzi43v0sJEwcP1DmcDrc="
TRUSTCHAIN_PRIVATE_KEY = "A3FXwUu3hvtjJbBWbIn9GlG8w+MfW9xO/laJs3XoqbwOLbBC7vlpWh1bc8rmN0uwiMtzVTsiJQkS9ZHbHHE5ig=="  # noqa


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
    assert tanker.version == "1.7.0-alpha4"
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


@pytest.mark.asyncio
async def test_init_tanker_invalid_path():
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path="/path/to/no-such"
    )
    fake = Faker()
    user_id = fake.email()
    token = tanker.generate_user_token(user_id)
    with pytest.raises(TankerError) as e:
        await tanker.open(user_id, token)
    print(e.value)


@pytest.mark.asyncio
async def test_open_new_account(tmp_path):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path=tmp_path,
    )
    fake = Faker()
    user_id = fake.email()
    token = tanker.generate_user_token(user_id)
    await tanker.open(user_id, token)
    assert tanker.status == TankerStatus.OPEN
    tanker.close()


@pytest.mark.asyncio
async def test_open_bad_token(tmp_path):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path=tmp_path,
    )
    fake = Faker()
    user_id = fake.email()
    with pytest.raises(TankerError) as e:
        await tanker.open(user_id, "bad token")
    assert "base64" in str(e.value)


@pytest.mark.asyncio
async def test_encrypt_decrypt(tmp_path):
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
    await alice_tanker.open(alice_id, alice_token)
    message = b"I love you"
    encrypted_data = await alice_tanker.encrypt(message)
    clear_data = await alice_tanker.decrypt(encrypted_data)
    assert clear_data == message


@pytest.mark.asyncio
async def test_share(tmp_path):
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
    await alice_tanker.open(alice_id, alice_token)
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
    await bob_tanker.open(bob_id, bob_token)
    message = b"I love you"
    encrypted = await alice_tanker.encrypt(message, share_with=[bob_id])
    decrypted = await bob_tanker.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_add_device(tmp_path):
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
    await laptop_tanker.open(alice_id, alice_token)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()

    phone_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path=phone_path,
    )

    loop = asyncio.get_event_loop()

    def on_waiting_for_validation(code):
        print("waiting for validation with code", code)
        print("accepting phone on laptop ...")

        async def cb():
            try:
                await laptop_tanker.accept_device(code)
            except Exception as e:
                pytest.fail("accept failed: %s" % e)

        asyncio.run_coroutine_threadsafe(cb(), loop)

    phone_tanker.on_waiting_for_validation = on_waiting_for_validation

    await phone_tanker.open(alice_id, alice_token)
    assert phone_tanker.status == TankerStatus.OPEN


if __name__ == "__main__":
    test_open_new_account("/tmp/test")
