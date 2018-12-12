import asyncio
from tankersdk.core import Admin, Tanker, Status as TankerStatus, Error as TankerError

import path
from faker import Faker

import pytest


TRUSTCHAIN_URL = "https://dev-api.tanker.io"
ID_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJpc3MiOiJodHRwczovL3Rhbmtlci1kYXNoYm9hcmQuZXUuYXV0aDAuY29tLyIsInN1YiI6"
    "ImF1dGgwfDVhODMxOGZhM2FmZjczMTAxMzI0YWM2YSIsImF1ZCI6ImxlY0liTzVDNk5TTGdR"
    "cHo4ZVVFRVpPMUpXbFB4ZUtKIiwiaWF0IjoxNTExNDUyMDIxLCJleHAiOjI1MzM3MDc2NDgw"
    "MCwibm9uY2UiOiJCQWItek9lckp1d3E1U29hY0JhNUgycUlIWkZxSUZjNCJ9."
    "zqVbGFssprvF40LZOtWcBp7onWEAdModBwu-jJO2q5M"
)


def create_tanker(trustchain_id, *, writable_path):
    return Tanker(
        trustchain_id,
        trustchain_url=TRUSTCHAIN_URL,
        sdk_type="test",
        writable_path=writable_path,
    )


@pytest.fixture()
def tmp_path(tmpdir):
    return path.Path(str(tmpdir))


@pytest.fixture(scope="session")
def trustchain():
    admin = Admin(url=TRUSTCHAIN_URL, token=ID_TOKEN)
    name = "python_bindings"
    trustchain = admin.create_trustchain(name)
    yield trustchain
    admin.delete_trustchain(trustchain.id)


def test_create_trustchain():
    name = "python_bindings"
    admin = Admin(url=TRUSTCHAIN_URL, token=ID_TOKEN)
    trustchain = admin.create_trustchain(name)
    assert trustchain.name == name
    admin.delete_trustchain(trustchain.id)


def test_init_tanker_ok(tmp_path, trustchain):
    tanker = create_tanker(trustchain_id=trustchain.id, writable_path=tmp_path)
    assert tanker.version
    assert tanker.trustchain_url == TRUSTCHAIN_URL


def test_init_tanker_invalid_id(tmp_path):
    with pytest.raises(TankerError) as e:
        create_tanker(trustchain_id="invalid bad 64", writable_path=tmp_path)
    assert "parse error" in e.value.args[0]


@pytest.mark.asyncio
async def test_init_tanker_invalid_path(trustchain):
    tanker = create_tanker(
        trustchain_id=trustchain.id, writable_path="/path/to/no-such"
    )
    fake = Faker()
    user_id = fake.email()
    token = tanker.generate_user_token(trustchain.private_key, user_id)
    with pytest.raises(TankerError) as e:
        await tanker.open(user_id, token)
    print(e.value)


@pytest.mark.asyncio
async def test_open_new_account(tmp_path, trustchain):
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    fake = Faker()
    user_id = fake.email()
    token = tanker.generate_user_token(trustchain.private_key, user_id)
    await tanker.open(user_id, token)
    assert tanker.status == TankerStatus.OPEN
    await tanker.close()


@pytest.mark.asyncio
async def test_open_bad_token(tmp_path, trustchain):
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    fake = Faker()
    user_id = fake.email()
    with pytest.raises(TankerError) as e:
        await tanker.open(user_id, "bad token")
    assert "base64" in str(e.value)
    await tanker.close()


async def create_user_session(tmp_path, trustchain):
    fake = Faker()
    user_id = fake.email()
    user_path = tmp_path.joinpath("user")
    user_path.mkdir_p()
    tanker = create_tanker(trustchain.id, writable_path=user_path)
    user_token = tanker.generate_user_token(trustchain.private_key, user_id)
    await tanker.open(user_id, user_token)
    return user_id, tanker


@pytest.mark.asyncio
async def test_encrypt_decrypt(tmp_path, trustchain):
    _, alice_session = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted_data = await alice_session.encrypt(message)
    clear_data = await alice_session.decrypt(encrypted_data)
    assert clear_data == message
    await alice_session.close()


@pytest.mark.asyncio
async def test_share_during_encrypt(tmp_path, trustchain):
    _, alice_session = await create_user_session(tmp_path, trustchain)
    bob_id, bob_session = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted = await alice_session.encrypt(message, share_with_users=[bob_id])
    decrypted = await bob_session.decrypt(encrypted)
    assert decrypted == message
    await alice_session.close()
    await bob_session.close()


@pytest.mark.asyncio
async def test_postponed_share(tmp_path, trustchain):
    _, alice_session = await create_user_session(tmp_path, trustchain)
    bob_id, bob_session = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted = await alice_session.encrypt(message)
    resource_id = alice_session.get_resource_id(encrypted)
    await alice_session.share([resource_id], users=[bob_id])

    decrypted = await bob_session.decrypt(encrypted)
    assert decrypted == message
    await alice_session.close()
    await bob_session.close()


async def check_share_to_group_works(
    alice_session, group_id, bob_session, charlie_session
):
    message = b"Hi, guys"
    encrypted = await alice_session.encrypt(message, share_with_groups=[group_id])

    decrypted = await charlie_session.decrypt(encrypted)
    assert decrypted == message

    decrypted = await bob_session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_create_group(tmp_path, trustchain):
    _, alice_session = await create_user_session(tmp_path, trustchain)
    bob_id, bob_session = await create_user_session(tmp_path, trustchain)
    charlie_id, charlie_session = await create_user_session(tmp_path, trustchain)

    group_id = await alice_session.create_group([bob_id, charlie_id])
    await check_share_to_group_works(
        alice_session, group_id, bob_session, charlie_session
    )


@pytest.mark.asyncio
async def test_update_group(tmp_path, trustchain):
    alice_id, alice_session = await create_user_session(tmp_path, trustchain)
    bob_id, bob_session = await create_user_session(tmp_path, trustchain)
    charlie_id, charlie_session = await create_user_session(tmp_path, trustchain)

    group_id = await alice_session.create_group([alice_id, bob_id])
    await alice_session.update_group_members(group_id, add=[charlie_id])

    await check_share_to_group_works(
        alice_session, group_id, bob_session, charlie_session
    )


@pytest.mark.asyncio
async def test_add_device(tmp_path, trustchain):
    fake = Faker()
    alice_id = fake.email()
    password = "plop"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    alice_token = laptop_tanker.generate_user_token(trustchain.private_key, alice_id)
    await laptop_tanker.open(alice_id, alice_token)
    await laptop_tanker.register_unlock(password=password)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()

    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)

    loop = asyncio.get_event_loop()

    def on_unlock_required():
        async def cb():
            try:
                await phone_tanker.unlock(password=password)
            except Exception as e:
                pytest.fail("unlock failed: %s" % e)

        asyncio.run_coroutine_threadsafe(cb(), loop)

    phone_tanker.on_unlock_required = on_unlock_required

    await phone_tanker.open(alice_id, alice_token)
    assert phone_tanker.status == TankerStatus.OPEN
    await laptop_tanker.close()
    await phone_tanker.close()
