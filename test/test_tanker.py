import asyncio
from collections import namedtuple
import os
import json

from path import Path
from faker import Faker
from typing import cast, Dict, Iterator, Tuple

import tankersdk
from tankersdk import Admin, Tanker, Error as TankerError, ErrorCode
from tankersdk.admin import Trustchain
import tankersdk_identity

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
def admin() -> Iterator[Admin]:
    yield Admin(url=TEST_CONFIG["url"], token=TEST_CONFIG["idToken"])


@pytest.fixture(scope="session")
def trustchain(admin: Admin) -> Iterator[Trustchain]:
    name = "python_bindings"
    trustchain = admin.create_trustchain(name)
    yield trustchain
    admin.delete_trustchain(trustchain.id)


def test_native_version() -> None:
    native_version = tankersdk.native_version()
    assert native_version


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
    with pytest.raises(TankerError) as error:
        create_tanker(trustchain_id="invalid bad 64", writable_path=tmp_path)
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_init_tanker_invalid_path(trustchain: Trustchain) -> None:
    tanker = create_tanker(
        trustchain_id=trustchain.id, writable_path="/path/to/no-such"
    )
    fake = Faker()
    user_id = fake.email()
    identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, user_id
    )
    with pytest.raises(TankerError) as error:
        await tanker.sign_up(identity)
    assert error.value.code == ErrorCode.INTERNAL_ERROR


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
    identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, user_id
    )
    await tanker.sign_up(identity)
    assert tanker.is_open
    device_id = await tanker.device_id()
    assert device_id
    await tanker.sign_out()


@pytest.mark.asyncio
async def test_sign_up_bad_identity(tmp_path: Path, trustchain: Trustchain) -> None:
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    with pytest.raises(TankerError) as error:
        await tanker.sign_up("bad identity")
    assert error.value.code == ErrorCode.INVALID_ARGUMENT
    await tanker.sign_out()


@pytest.mark.asyncio
async def test_sign_in_bad_identity(tmp_path: Path, trustchain: Trustchain) -> None:
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    with pytest.raises(TankerError) as error:
        await tanker.sign_in("bad identity")
    assert error.value.code == ErrorCode.INVALID_ARGUMENT
    await tanker.sign_out()


@pytest.mark.asyncio
async def test_sign_back_in(tmp_path: Path, trustchain: Trustchain) -> None:
    fake = Faker()
    user_id = fake.email()
    user_path = tmp_path.joinpath("user")
    user_path.mkdir_p()
    tanker = create_tanker(trustchain.id, writable_path=user_path)
    identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, user_id
    )
    await tanker.sign_up(identity)
    assert tanker.is_open
    await tanker.sign_out()
    assert not tanker.is_open
    assert await tanker.sign_in(identity) == tankersdk.SignInResult.OK
    assert tanker.is_open
    await tanker.sign_out()
    assert not tanker.is_open


async def create_user_session(
    tmp_path: Path, trustchain: Trustchain
) -> Tuple[str, Tanker]:
    fake = Faker()
    user_id = fake.email()
    user_path = tmp_path.joinpath("user")
    user_path.mkdir_p()
    tanker = create_tanker(trustchain.id, writable_path=user_path)
    identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, user_id
    )
    await tanker.sign_up(identity)
    return identity, tanker


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
    bob_identity, bob_session = await create_user_session(tmp_path, trustchain)
    bob_pub_id = tankersdk_identity.get_public_identity(bob_identity)
    message = b"I love you"
    encrypted = await alice_session.encrypt(message, share_with_users=[bob_pub_id])
    decrypted = await bob_session.decrypt(encrypted)
    assert decrypted == message
    await alice_session.sign_out()
    await bob_session.sign_out()


@pytest.mark.asyncio
async def test_postponed_share(tmp_path: Path, trustchain: Trustchain) -> None:
    _, alice_session = await create_user_session(tmp_path, trustchain)
    bob_identity, bob_session = await create_user_session(tmp_path, trustchain)
    bob_pub_id = tankersdk_identity.get_public_identity(bob_identity)
    message = b"I love you"
    encrypted = await alice_session.encrypt(message)
    resource_id = alice_session.get_resource_id(encrypted)
    await alice_session.share([resource_id], users=[bob_pub_id])

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
    bob_identity, bob_session = await create_user_session(tmp_path, trustchain)
    bob_pub_id = tankersdk_identity.get_public_identity(bob_identity)
    charlie_identity, charlie_session = await create_user_session(tmp_path, trustchain)
    charlie_pub_id = tankersdk_identity.get_public_identity(charlie_identity)

    group_id = await alice_session.create_group([bob_pub_id, charlie_pub_id])
    await check_share_to_group_works(
        alice_session, group_id, bob_session, charlie_session
    )


@pytest.mark.asyncio
async def test_update_group(tmp_path: Path, trustchain: Trustchain) -> None:
    alice_identity, alice_session = await create_user_session(tmp_path, trustchain)
    alice_pub_id = tankersdk_identity.get_public_identity(alice_identity)
    bob_identity, bob_session = await create_user_session(tmp_path, trustchain)
    bob_pub_id = tankersdk_identity.get_public_identity(bob_identity)
    charlie_identity, charlie_session = await create_user_session(tmp_path, trustchain)
    charlie_pub_id = tankersdk_identity.get_public_identity(charlie_identity)

    group_id = await alice_session.create_group([alice_pub_id, bob_pub_id])
    await alice_session.update_group_members(group_id, add=[charlie_pub_id])

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
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, fake.email()
    )
    await laptop_tanker.sign_up(alice_identity, password=password)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()

    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)

    await phone_tanker.sign_in(alice_identity, password=password)
    return laptop_tanker, phone_tanker


@pytest.mark.asyncio
async def test_add_device(tmp_path: Path, trustchain: Trustchain) -> None:
    laptop, phone = await create_two_devices(tmp_path, trustchain)
    assert phone.is_open
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
    assert not laptop.is_open


@pytest.mark.asyncio
async def test_no_password(tmp_path: Path, trustchain: Trustchain) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, fake.email()
    )
    await laptop_tanker.sign_up(alice_identity, password="plop")

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()

    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)

    res = await phone_tanker.sign_in(alice_identity)
    assert res == tankersdk.SignInResult.IDENTITY_VERIFICATION_NEEDED
    assert not phone_tanker.is_open


@pytest.mark.asyncio
async def test_unlock_key(tmp_path: Path, trustchain: Trustchain) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, fake.email()
    )
    await laptop_tanker.sign_up(alice_identity)
    unlock_key = await laptop_tanker.generate_and_register_unlock_key()
    assert unlock_key

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)
    await phone_tanker.sign_in(alice_identity, unlock_key=unlock_key)
    assert phone_tanker.is_open
    await laptop_tanker.sign_out()
    await phone_tanker.sign_out()


@pytest.mark.asyncio
async def test_invalid_unlock_key(tmp_path: Path, trustchain: Trustchain) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, fake.email()
    )
    await laptop_tanker.sign_up(alice_identity)
    unlock_key = await laptop_tanker.generate_and_register_unlock_key()
    assert unlock_key

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)
    with pytest.raises(TankerError) as error:
        await phone_tanker.sign_in(alice_identity, unlock_key="plop")
    assert error.value.code == ErrorCode.INVALID_UNLOCK_KEY
    assert not phone_tanker.is_open
    with pytest.raises(TankerError) as error:
        await phone_tanker.sign_in(alice_identity, unlock_key="")
    assert error.value.code == ErrorCode.INVALID_UNLOCK_KEY
    assert not phone_tanker.is_open
    await laptop_tanker.sign_out()


@pytest.mark.asyncio
async def test_unlock_email(tmp_path: Path, trustchain: Trustchain, admin: Admin) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    email = fake.email()
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, email
    )
    await laptop_tanker.sign_up(alice_identity, email=email)
    verif_code = admin.get_verification_code(trustchain.id, email)
    assert len(verif_code) == 8

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)

    await phone_tanker.sign_in(alice_identity, verification_code=verif_code)
    assert phone_tanker.is_open
    await laptop_tanker.sign_out()
    await phone_tanker.sign_out()


@pytest.mark.asyncio
async def test_bad_verif_code(tmp_path: Path, trustchain: Trustchain) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    email = fake.email()
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, email
    )
    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)
    await laptop_tanker.sign_up(alice_identity, email=email)
    with pytest.raises(TankerError) as error:
        await phone_tanker.sign_in(alice_identity, verification_code="12345678")
    assert error.value.code == ErrorCode.INVALID_VERIFICATION_CODE
    assert not phone_tanker.is_open
    with pytest.raises(TankerError) as error:
        await phone_tanker.sign_in(alice_identity, verification_code="azerty")
    assert error.value.code == ErrorCode.INVALID_VERIFICATION_CODE
    assert not phone_tanker.is_open
    with pytest.raises(TankerError) as error:
        await phone_tanker.sign_in(alice_identity, verification_code="")
    assert error.value.code == ErrorCode.INVALID_VERIFICATION_CODE
    assert not phone_tanker.is_open
    await laptop_tanker.sign_out()


@pytest.mark.asyncio
async def test_decrypt_unclaimed_resource(
        tmp_path: Path, trustchain: Trustchain, admin: Admin) -> None:
    fake = Faker()
    bob_email = fake.email()
    bob_provisional_identity = tankersdk_identity.create_provisional_identity(
        trustchain.id, bob_email)
    _, alice_session = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted = await alice_session.encrypt(message, share_with_users=[bob_provisional_identity])
    _, bob_session = await create_user_session(tmp_path, trustchain)
    with pytest.raises(TankerError) as error:
        await bob_session.decrypt(encrypted)
    assert error.value.code == ErrorCode.RESOURCE_KEY_NOT_FOUND


User = namedtuple("User", ["session", "identity", "provisional_identity", "email"])


async def share_and_claim(
    tmp_path: Path, trustchain: Trustchain, admin: Admin
) -> Tuple[User, bytes, bytes]:
    fake = Faker()
    bob_email = fake.email()
    bob_provisional_identity = tankersdk_identity.create_provisional_identity(
        trustchain.id, bob_email)
    _, alice_session = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted = await alice_session.encrypt(message, share_with_users=[bob_provisional_identity])
    bob_identity, bob_session = await create_user_session(tmp_path, trustchain)
    verif_code = admin.get_verification_code(trustchain.id, bob_email)
    await bob_session.claim_provisional_identity(bob_provisional_identity, verif_code)
    bob = User(
        session=bob_session,
        identity=bob_identity,
        provisional_identity=bob_provisional_identity,
        email=bob_email,
    )
    return bob, encrypted, message


@pytest.mark.asyncio
async def test_claim_identity(tmp_path: Path, trustchain: Trustchain, admin: Admin) -> None:
    bob, encrypted, message = await share_and_claim(tmp_path, trustchain, admin)
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_claim_identity_after_sign_out_sign_in(
        tmp_path: Path, trustchain: Trustchain, admin: Admin
) -> None:
    bob, encrypted, message = await share_and_claim(tmp_path, trustchain, admin)
    await bob.session.sign_out()
    await bob.session.sign_in(bob.identity)
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_already_claimed_identity(
        tmp_path: Path, trustchain: Trustchain, admin: Admin
) -> None:
    bob, _, _ = await share_and_claim(tmp_path, trustchain, admin)
    verif_code = admin.get_verification_code(trustchain.id, bob.email)
    with pytest.raises(TankerError) as error:
        await bob.session.claim_provisional_identity(bob.provisional_identity, verif_code)
    assert error.value.code == ErrorCode.SERVER_ERROR


@pytest.mark.asyncio
async def test_claim_with_incorrect_code(tmp_path: Path, trustchain: Trustchain) -> None:
    fake = Faker()
    bob_email = fake.email()
    bob_provisional_identity = tankersdk_identity.create_provisional_identity(
        trustchain.id, bob_email)
    _, alice_session = await create_user_session(tmp_path, trustchain)
    _, bob_session = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    await alice_session.encrypt(message, share_with_users=[bob_provisional_identity])
    with pytest.raises(TankerError) as error:
        await bob_session.claim_provisional_identity(bob_provisional_identity, "badCode")
    assert error.value.code == ErrorCode.INVALID_VERIFICATION_CODE


@pytest.mark.asyncio
async def test_nothing_to_claim(tmp_path: Path, trustchain: Trustchain, admin: Admin) -> None:
    fake = Faker()
    bob_email = fake.email()
    bob_provisional_identity = tankersdk_identity.create_provisional_identity(
        trustchain.id, bob_email)
    _, alice_session = await create_user_session(tmp_path, trustchain)
    _, bob_session = await create_user_session(tmp_path, trustchain)
    verif_code = admin.get_verification_code(trustchain.id, bob_email)
    with pytest.raises(TankerError) as error:
        await bob_session.claim_provisional_identity(bob_provisional_identity, verif_code)
    assert error.value.code == ErrorCode.NOTHING_TO_CLAIM
