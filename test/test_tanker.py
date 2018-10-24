import asyncio
from tankersdk.core import Admin, Tanker, Status as TankerStatus, Error as TankerError

import path
from faker import Faker

import pytest


TRUSTCHAIN_URL = "https://dev-api.tanker.io"
ID_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +\
           "eyJpc3MiOiJodHRwczovL3Rhbmtlci1kYXNoYm9hcmQuZXUuYXV0aDAuY29tLyIsInN1YiI6" +\
           "ImF1dGgwfDVhODMxOGZhM2FmZjczMTAxMzI0YWM2YSIsImF1ZCI6ImxlY0liTzVDNk5TTGdR" +\
           "cHo4ZVVFRVpPMUpXbFB4ZUtKIiwiaWF0IjoxNTExNDUyMDIxLCJleHAiOjI1MzM3MDc2NDgw" +\
           "MCwibm9uY2UiOiJCQWItek9lckp1d3E1U29hY0JhNUgycUlIWkZxSUZjNCJ9." +\
           "zqVbGFssprvF40LZOtWcBp7onWEAdModBwu-jJO2q5M"


@pytest.fixture()
def tmp_path(tmpdir):
    return path.Path(str(tmpdir))


@pytest.fixture(scope="session")
def trustchain():
    admin = Admin(
        url=TRUSTCHAIN_URL,
        token=ID_TOKEN,
    )
    name = "python_bindings"
    admin.create_trustchain(name)
    yield admin
    admin.delete_trustchain()


def test_create_trustchain():
    name = "python_bindings"
    admin = Admin(
        url=TRUSTCHAIN_URL,
        token=ID_TOKEN,
    )
    admin.create_trustchain(name)
    assert admin.trustchain_name == name
    admin.delete_trustchain()


def test_init_tanker_ok(tmp_path, trustchain):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=trustchain.trustchain_id,
        trustchain_private_key=trustchain.trustchain_private_key,
        writable_path=tmp_path
    )
    assert tanker.version
    assert tanker.trustchain_url == TRUSTCHAIN_URL


def test_init_tanker_invalid_id(tmp_path, trustchain):
    with pytest.raises(TankerError) as e:
        Tanker(
            trustchain_url=TRUSTCHAIN_URL,
            trustchain_id="invalid bad 64",
            trustchain_private_key=trustchain.trustchain_private_key,
            writable_path=tmp_path
        )
    assert "parse error" in e.value.args[0]


@pytest.mark.asyncio
async def test_init_tanker_invalid_path(trustchain):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=trustchain.trustchain_id,
        trustchain_private_key=trustchain.trustchain_private_key,
        writable_path="/path/to/no-such"
    )
    fake = Faker()
    user_id = fake.email()
    token = tanker.generate_user_token(user_id)
    with pytest.raises(TankerError) as e:
        await tanker.open(user_id, token)
    print(e.value)


@pytest.mark.asyncio
async def test_open_new_account(tmp_path, trustchain):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=trustchain.trustchain_id,
        trustchain_private_key=trustchain.trustchain_private_key,
        writable_path=tmp_path,
    )
    fake = Faker()
    user_id = fake.email()
    token = tanker.generate_user_token(user_id)
    await tanker.open(user_id, token)
    assert tanker.status == TankerStatus.OPEN
    await tanker.close()


@pytest.mark.asyncio
async def test_open_bad_token(tmp_path, trustchain):
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=trustchain.trustchain_id,
        trustchain_private_key=trustchain.trustchain_private_key,
        writable_path=tmp_path,
    )
    fake = Faker()
    user_id = fake.email()
    with pytest.raises(TankerError) as e:
        await tanker.open(user_id, "bad token")
    assert "base64" in str(e.value)
    await tanker.close()


@pytest.mark.asyncio
async def test_encrypt_decrypt(tmp_path, trustchain):
    fake = Faker()
    alice_id = fake.email()
    alice_path = tmp_path.joinpath("alice")
    alice_path.mkdir_p()
    alice_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=trustchain.trustchain_id,
        trustchain_private_key=trustchain.trustchain_private_key,
        writable_path=alice_path
    )
    alice_token = alice_tanker.generate_user_token(alice_id)
    await alice_tanker.open(alice_id, alice_token)
    message = b"I love you"
    encrypted_data = await alice_tanker.encrypt(message)
    clear_data = await alice_tanker.decrypt(encrypted_data)
    assert clear_data == message
    await alice_tanker.close()


@pytest.mark.asyncio
async def test_share(tmp_path, trustchain):
    fake = Faker()
    alice_id = fake.email()
    alice_path = tmp_path.joinpath("alice")
    alice_path.mkdir_p()
    alice_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=trustchain.trustchain_id,
        trustchain_private_key=trustchain.trustchain_private_key,
        writable_path=alice_path
    )
    alice_token = alice_tanker.generate_user_token(alice_id)
    await alice_tanker.open(alice_id, alice_token)
    bob_path = tmp_path.joinpath("bob")
    bob_path.mkdir_p()
    bob_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=trustchain.trustchain_id,
        trustchain_private_key=trustchain.trustchain_private_key,
        writable_path=bob_path
    )
    bob_id = fake.email()
    bob_token = bob_tanker.generate_user_token(bob_id)
    await bob_tanker.open(bob_id, bob_token)
    message = b"I love you"
    encrypted = await alice_tanker.encrypt(message, share_with=[bob_id])
    decrypted = await bob_tanker.decrypt(encrypted)
    assert decrypted == message
    await alice_tanker.close()
    await bob_tanker.close()


@pytest.mark.asyncio
async def test_add_device(tmp_path, trustchain):
    fake = Faker()
    alice_id = fake.email()
    password = "plop"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=trustchain.trustchain_id,
        trustchain_private_key=trustchain.trustchain_private_key,
        writable_path=laptop_path,
    )
    alice_token = laptop_tanker.generate_user_token(alice_id)
    await laptop_tanker.open(alice_id, alice_token)
    await laptop_tanker.setup_unlock(password)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()

    phone_tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=trustchain.trustchain_id,
        trustchain_private_key=trustchain.trustchain_private_key,
        writable_path=phone_path,
    )

    loop = asyncio.get_event_loop()

    def on_unlock_required():
        async def cb():
            try:
                await phone_tanker.unlock_current_device_with_password(password)
            except Exception as e:
                pytest.fail("unlock failed: %s" % e)

        asyncio.run_coroutine_threadsafe(cb(), loop)

    phone_tanker.on_unlock_required = on_unlock_required

    await phone_tanker.open(alice_id, alice_token)
    assert phone_tanker.status == TankerStatus.OPEN
    await laptop_tanker.close()
    await phone_tanker.close()
