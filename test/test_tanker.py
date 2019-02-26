from typing import Dict, Iterator, Tuple, cast
import asyncio
import os
import json

from path import Path
from faker import Faker

import tankersdk
from tankersdk import Admin, Tanker, Status as TankerStatus, Error as TankerError
from tankersdk.admin import Trustchain

import pytest


def assert_env(name: str) -> str:
    value = os.environ.get(name)
    assert value, f"{name} should be set before running tests"
    return value


def read_test_config() -> Dict[str, str]:
    config_path = assert_env("TANKER_CONFIG_FILEPATH")
    config_name = assert_env("TANKER_CONFIG_NAME")
    config = json.loads(Path(config_path).text())
    assert config_name in config, f"unknown TANKER_CONFIG_NAME: {config_name}"
    return cast(Dict[str, str], config[config_name])


TEST_CONFIG = read_test_config()


def create_tanker(trustchain_id: str, *, writable_path: str) -> Tanker:
    return Tanker(
        trustchain_id,
        trustchain_url=TEST_CONFIG["url"],
        sdk_type="sdk-python-test",
        writable_path=writable_path,
    )


@pytest.fixture()
def tmp_path(tmpdir: str) -> Path:
    return Path(str(tmpdir))


@pytest.fixture(scope="session")
def trustchain() -> Iterator[Trustchain]:
    admin = Admin(url=TEST_CONFIG["url"], token=TEST_CONFIG["idToken"])
    name = "python_bindings"
    trustchain = admin.create_trustchain(name)
    yield trustchain
    admin.delete_trustchain(trustchain.id)


def test_native_version() -> None:
    native_version = tankersdk.native_version()
    assert(native_version)


def test_create_trustchain() -> None:
    name = "python_bindings"
    admin = Admin(url=TEST_CONFIG["url"], token=TEST_CONFIG["idToken"])
    trustchain = admin.create_trustchain(name)
    assert trustchain.name == name
    admin.delete_trustchain(trustchain.id)


def test_init_tanker_ok(tmp_path: Path, trustchain: Trustchain) -> None:
    tanker = create_tanker(trustchain_id=trustchain.id, writable_path=tmp_path)
    assert tanker.trustchain_url == TEST_CONFIG["url"]


def test_init_tanker_invalid_id(tmp_path: Path) -> None:
    with pytest.raises(TankerError) as e:
        create_tanker(trustchain_id="invalid bad 64", writable_path=tmp_path)
    assert "parse error" in e.value.args[0]


@pytest.mark.asyncio
async def test_init_tanker_invalid_path(trustchain: Trustchain) -> None:
    tanker = create_tanker(
        trustchain_id=trustchain.id, writable_path="/path/to/no-such"
    )
    fake = Faker()
    user_id = fake.email()
    identity = tanker.create_identity(trustchain.private_key, user_id)
    with pytest.raises(TankerError):
        await tanker.sign_up(identity)


@pytest.mark.asyncio
async def test_tanker_sdk_version(tmp_path: Path, trustchain: Trustchain) -> None:
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    sdk_version = tanker.sdk_version
    assert sdk_version


@pytest.mark.asyncio
async def test_sign_up_new_account(tmp_path: Path, trustchain: Trustchain) -> None:
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    fake = Faker()
    user_id = fake.email()
    identity = tanker.create_identity(trustchain.private_key, user_id)
    await tanker.sign_up(identity)
    assert tanker.status == TankerStatus.OPEN
    device_id = await tanker.device_id()
    assert device_id
    await tanker.sign_out()


@pytest.mark.asyncio
async def test_sign_up_bad_identity(tmp_path: Path, trustchain: Trustchain) -> None:
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    with pytest.raises(TankerError) as e:
        await tanker.sign_up("bad identity")
    assert "base64" in str(e.value)
    await tanker.sign_out()


@pytest.mark.asyncio
async def test_sign_in_bad_identity(tmp_path: Path, trustchain: Trustchain) -> None:
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    with pytest.raises(TankerError) as e:
        await tanker.sign_in("bad identity")
    assert "base64" in str(e.value)
    await tanker.sign_out()


@pytest.mark.asyncio
async def test_sign_back_in(tmp_path: Path, trustchain: Trustchain) -> None:
    fake = Faker()
    user_id = fake.email()
    user_path = tmp_path.joinpath("user")
    user_path.mkdir_p()
    tanker = create_tanker(trustchain.id, writable_path=user_path)
    identity = tanker.create_identity(trustchain.private_key, user_id)
    await tanker.sign_up(identity)
    await tanker.sign_out()
    await tanker.sign_in(identity)
    await tanker.sign_out()


async def create_user_session(
    tmp_path: Path, trustchain: Trustchain
) -> Tuple[str, Tanker]:
    fake = Faker()
    user_id = fake.email()
    user_path = tmp_path.joinpath("user")
    user_path.mkdir_p()
    tanker = create_tanker(trustchain.id, writable_path=user_path)
    identity = tanker.create_identity(trustchain.private_key, user_id)
    await tanker.sign_up(identity)
    return user_id, tanker


@pytest.mark.asyncio
async def test_encrypt_decrypt(tmp_path: Path, trustchain: Trustchain) -> None:
    _, alice_session = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted_data = await alice_session.encrypt(message)
    clear_data = await alice_session.decrypt(encrypted_data)
    assert clear_data == message
    await alice_session.sign_out()


@pytest.mark.asyncio
async def test_share_during_encrypt(tmp_path: Path, trustchain: Trustchain) -> None:
    _, alice_session = await create_user_session(tmp_path, trustchain)
    bob_id, bob_session = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted = await alice_session.encrypt(message, share_with_users=[bob_id])
    decrypted = await bob_session.decrypt(encrypted)
    assert decrypted == message
    await alice_session.sign_out()
    await bob_session.sign_out()


@pytest.mark.asyncio
async def test_postponed_share(tmp_path: Path, trustchain: Trustchain) -> None:
    _, alice_session = await create_user_session(tmp_path, trustchain)
    bob_id, bob_session = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted = await alice_session.encrypt(message)
    resource_id = alice_session.get_resource_id(encrypted)
    await alice_session.share([resource_id], users=[bob_id])

    decrypted = await bob_session.decrypt(encrypted)
    assert decrypted == message
    await alice_session.sign_out()
    await bob_session.sign_out()


async def check_share_to_group_works(
    alice_session: Tanker, group_id: str, bob_session: Tanker, charlie_session: Tanker
) -> None:
    message = b"Hi, guys"
    encrypted = await alice_session.encrypt(message, share_with_groups=[group_id])

    decrypted = await charlie_session.decrypt(encrypted)
    assert decrypted == message

    decrypted = await bob_session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_create_group(tmp_path: Path, trustchain: Trustchain) -> None:
    _, alice_session = await create_user_session(tmp_path, trustchain)
    bob_id, bob_session = await create_user_session(tmp_path, trustchain)
    charlie_id, charlie_session = await create_user_session(tmp_path, trustchain)

    group_id = await alice_session.create_group([bob_id, charlie_id])
    await check_share_to_group_works(
        alice_session, group_id, bob_session, charlie_session
    )


@pytest.mark.asyncio
async def test_update_group(tmp_path: Path, trustchain: Trustchain) -> None:
    alice_id, alice_session = await create_user_session(tmp_path, trustchain)
    bob_id, bob_session = await create_user_session(tmp_path, trustchain)
    charlie_id, charlie_session = await create_user_session(tmp_path, trustchain)

    group_id = await alice_session.create_group([alice_id, bob_id])
    await alice_session.update_group_members(group_id, add=[charlie_id])

    await check_share_to_group_works(
        alice_session, group_id, bob_session, charlie_session
    )


async def create_two_devices(
    tmp_path: Path, trustchain: Trustchain
) -> Tuple[Tanker, Tanker]:
    fake = Faker()
    password = "plop"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    alice_identity = laptop_tanker.create_identity(trustchain.private_key, fake.email())
    await laptop_tanker.sign_up(alice_identity, password=password)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()

    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)

    await phone_tanker.sign_in(alice_identity, password=password)
    return laptop_tanker, phone_tanker


@pytest.mark.asyncio
async def test_add_device(tmp_path: Path, trustchain: Trustchain) -> None:
    laptop, phone = await create_two_devices(tmp_path, trustchain)
    assert phone.status == TankerStatus.OPEN
    await laptop.sign_out()
    await phone.sign_out()


@pytest.mark.asyncio
async def test_revoke_device(tmp_path: Path, trustchain: Trustchain) -> None:
    laptop, phone = await create_two_devices(tmp_path, trustchain)
    laptop_id = await laptop.device_id()
    laptop_revoked = asyncio.Event()
    loop = asyncio.get_event_loop()

    def on_revoked() -> None:
        async def cb() -> None:
            laptop_revoked.set()

        asyncio.run_coroutine_threadsafe(cb(), loop)

    laptop.on_revoked = on_revoked
    await phone.revoke_device(laptop_id)
    await asyncio.wait_for(laptop_revoked.wait(), timeout=1)
    assert laptop.status == TankerStatus.CLOSED
