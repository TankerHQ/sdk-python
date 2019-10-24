import asyncio
import base64
from collections import namedtuple
import os
import io
import json

from path import Path
from faker import Faker
import requests
from typing import cast, Any, Dict, Iterator, Tuple

import tankersdk
from tankersdk import Admin, Tanker, Error as TankerError, ErrorCode
from tankersdk import Status as TankerStatus
from tankersdk.tanker import CVerification, VerificationMethodType
from tankersdk.admin import App, OIDCConfig
import tankersdk_identity

import pytest


def encode(string: str) -> str:
    return base64.b64encode(string.encode()).decode()


def assert_env(name: str) -> str:
    value = os.environ.get(name)
    assert value, f"{name} should be set before running tests"
    return value


def read_test_config() -> Dict[str, Any]:
    config_path = assert_env("TANKER_CONFIG_FILEPATH")
    test_config = json.loads(Path(config_path).text())

    config_name = assert_env("TANKER_CONFIG_NAME")
    assert config_name in test_config, f"unknown TANKER_CONFIG_NAME: {config_name}"

    res = {}
    res["server"] = test_config[config_name]
    res["oidc"] = test_config["oidc"]
    return res


TEST_CONFIG = read_test_config()


def create_tanker(trustchain_id: str, *, writable_path: str) -> Tanker:
    return Tanker(
        trustchain_id,
        url=cast(str, TEST_CONFIG["server"]["url"]),
        sdk_type="sdk-python-test",
        writable_path=writable_path,
    )


@pytest.fixture()
def tmp_path(tmpdir: str) -> Path:
    return Path(str(tmpdir))


@pytest.fixture(scope="session")
def admin() -> Iterator[Admin]:
    yield Admin(
        url=TEST_CONFIG["server"]["url"], token=TEST_CONFIG["server"]["idToken"]
    )


class TestVerificationSanityChecks:
    def assert_value_error(self, **kwargs: str) -> None:
        with pytest.raises(ValueError):
            CVerification(**kwargs)

    def test_accepts_correct_arguments(self) -> None:
        CVerification(passphrase="my-passphrase")
        CVerification(verification_key="THE-KEY")
        CVerification(email="john@domain.tld", verification_code="1234")

    def test_rejects_all_none(self) -> None:
        self.assert_value_error()

    def test_rejects_two_methods(self) -> None:
        self.assert_value_error(passphrase="my-passphrase", verification_key="THE-KEY")

    def test_rejects_email_without_verification_code(self) -> None:
        self.assert_value_error(email="john@domain.tld")


@pytest.fixture(scope="session")
def trustchain(admin: Admin) -> Iterator[App]:
    name = "python_bindings"
    trustchain = admin.create_app(name)
    yield trustchain
    admin.delete_app(trustchain.id)


def test_native_version() -> None:
    native_version = tankersdk.native_version()
    assert native_version


def test_create_trustchain() -> None:
    name = "python_bindings"
    admin = Admin(
        url=TEST_CONFIG["server"]["url"], token=TEST_CONFIG["server"]["idToken"]
    )
    trustchain = admin.create_app(name)
    assert trustchain.name == name
    admin.delete_app(trustchain.id)


def test_init_tanker_ok(tmp_path: Path, trustchain: App) -> None:
    tanker = create_tanker(trustchain_id=trustchain.id, writable_path=tmp_path)
    assert tanker.url == TEST_CONFIG["server"]["url"]


def test_init_tanker_invalid_id(tmp_path: Path) -> None:
    with pytest.raises(TankerError) as error:
        create_tanker(trustchain_id="invalid bad 64", writable_path=tmp_path)
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_tanker_start_invalid_path(trustchain: App) -> None:
    tanker = create_tanker(
        trustchain_id=trustchain.id, writable_path="/path/to/no-such"
    )
    fake = Faker()
    user_id = fake.email()
    identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, user_id
    )
    with pytest.raises(TankerError) as error:
        await tanker.start(identity)
    assert error.value.code == ErrorCode.INTERNAL_ERROR


@pytest.mark.asyncio
async def test_tanker_sdk_version(tmp_path: Path, trustchain: App) -> None:
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    sdk_version = tanker.sdk_version
    assert sdk_version


@pytest.mark.asyncio
async def test_start_new_account(tmp_path: Path, trustchain: App) -> None:
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    fake = Faker()
    user_id = fake.email()
    identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, user_id
    )
    status = await tanker.start(identity)
    assert status == TankerStatus.IDENTITY_REGISTRATION_NEEDED
    key = await tanker.generate_verification_key()
    await tanker.register_identity(verification_key=key)
    assert tanker.status == TankerStatus.READY
    device_id = await tanker.device_id()
    assert device_id
    await tanker.stop()
    assert tanker.status == TankerStatus.STOPPED


@pytest.mark.asyncio
async def test_start_identity_incorrect_format(tmp_path: Path, trustchain: App) -> None:
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    with pytest.raises(TankerError) as error:
        await tanker.start("bad identity")
    assert error.value.code == ErrorCode.INVALID_ARGUMENT
    await tanker.stop()


@pytest.mark.asyncio
async def test_create_account_then_sign_in(tmp_path: Path, trustchain: App) -> None:
    fake = Faker()
    user_id = fake.email()
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, user_id
    )
    await tanker.start(identity)
    key = await tanker.generate_verification_key()
    await tanker.register_identity(verification_key=key)
    await tanker.stop()

    await tanker.start(identity)
    assert tanker.status == TankerStatus.READY
    await tanker.stop()


User = namedtuple("User", ["session", "public_identity", "private_identity"])


async def create_user_session(tmp_path: Path, trustchain: App) -> User:
    fake = Faker()
    user_id = fake.email()
    user_path = tmp_path.joinpath(user_id)
    user_path.mkdir_p()
    tanker = create_tanker(trustchain.id, writable_path=user_path)
    private_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, user_id
    )
    public_identity = tankersdk_identity.get_public_identity(private_identity)
    await tanker.start(private_identity)
    key = await tanker.generate_verification_key()
    await tanker.register_identity(verification_key=key)
    return User(
        session=tanker,
        private_identity=private_identity,
        public_identity=public_identity,
    )


class InMemoryAsyncStream:
    def __init__(self, contents: bytes) -> None:
        self._buffer = io.BytesIO(contents)

    async def read(self, size: int) -> bytes:
        return self._buffer.read(size)


class FailingStream:
    def __init__(self, contents: bytes) -> None:
        self._buffer = io.BytesIO(contents)

    async def read(self, size: int) -> bytes:
        raise Exception("Kaboom")


class TestStreams:
    @pytest.mark.asyncio
    async def test_async_read_write_by_chunks(
        self, tmp_path: Path, trustchain: App
    ) -> None:
        alice = await create_user_session(tmp_path, trustchain)
        chunk_size = 1024 ** 2
        message = bytearray(
            3 * chunk_size + 2
        )  # three big chunks plus a little something
        input_stream = InMemoryAsyncStream(message)
        decrypted_message = bytearray()
        encrypted_stream = await alice.session.encrypt_stream(input_stream)
        async with await alice.session.decrypt_stream(encrypted_stream) as f:
            while True:
                clear_chunk = await f.read(chunk_size)
                if clear_chunk:
                    decrypted_message += clear_chunk
                else:
                    break
        assert decrypted_message == message
        await alice.session.stop()

    @pytest.mark.asyncio
    async def test_async_read_in_one_go(self, tmp_path: Path, trustchain: App) -> None:
        alice = await create_user_session(tmp_path, trustchain)
        chunk_size = 1024 ** 2
        message = bytearray(
            3 * chunk_size + 2
        )  # three big chunks plus a little something
        input_stream = InMemoryAsyncStream(message)
        encrypted_stream = await alice.session.encrypt_stream(input_stream)
        async with await alice.session.decrypt_stream(encrypted_stream) as f:
            decrypted_message = await f.read()
        assert decrypted_message == message
        await alice.session.stop()

    @pytest.mark.asyncio
    async def test_error_handling(self, tmp_path: Path, trustchain: App) -> None:
        alice = await create_user_session(tmp_path, trustchain)
        message = bytearray(1024 * 1024 * 3 + 2)
        input_stream = FailingStream(message)
        encrypted_stream = await alice.session.encrypt_stream(input_stream)
        with pytest.raises(Exception) as e:
            await alice.session.decrypt_stream(encrypted_stream)
        assert e.value.args == ("Kaboom",)
        await alice.session.stop()

    @pytest.mark.asyncio
    async def test_empty_message(self, tmp_path: Path, trustchain: App) -> None:
        alice = await create_user_session(tmp_path, trustchain)
        empty_message = bytearray()
        input_stream = InMemoryAsyncStream(empty_message)
        encrypted_stream = await alice.session.encrypt_stream(input_stream)
        async with await alice.session.decrypt_stream(encrypted_stream) as f:
            result = await f.read(1024)
            assert len(result) == 0
        await alice.session.stop()


@pytest.mark.asyncio
async def test_encrypt_decrypt(tmp_path: Path, trustchain: App) -> None:
    alice = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted_data = await alice.session.encrypt(message)
    clear_data = await alice.session.decrypt(encrypted_data)
    assert clear_data == message
    await alice.session.stop()


@pytest.mark.asyncio
async def test_share_during_encrypt(tmp_path: Path, trustchain: App) -> None:
    alice = await create_user_session(tmp_path, trustchain)
    bob = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted = await alice.session.encrypt(
        message, share_with_users=[bob.public_identity]
    )
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()
    await bob.session.stop()


@pytest.mark.asyncio
async def test_postponed_share(tmp_path: Path, trustchain: App) -> None:
    alice = await create_user_session(tmp_path, trustchain)
    bob = await create_user_session(tmp_path, trustchain)
    message = b"I love you"
    encrypted = await alice.session.encrypt(message)
    resource_id = alice.session.get_resource_id(encrypted)
    await alice.session.share([resource_id], users=[bob.public_identity])

    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()
    await bob.session.stop()


async def check_share_with_group_works(
    alice: User, group_id: str, bob: User, charlie: User
) -> None:
    message = b"Hi, guys"
    encrypted = await alice.session.encrypt(message, share_with_groups=[group_id])
    decrypted = await charlie.session.decrypt(encrypted)
    assert decrypted == message
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_create_group(tmp_path: Path, trustchain: App) -> None:
    alice = await create_user_session(tmp_path, trustchain)
    bob = await create_user_session(tmp_path, trustchain)
    charlie = await create_user_session(tmp_path, trustchain)

    group_id = await alice.session.create_group(
        [bob.public_identity, charlie.public_identity]
    )
    await check_share_with_group_works(alice, group_id, bob, charlie)


@pytest.mark.asyncio
async def test_update_group(tmp_path: Path, trustchain: App) -> None:
    alice = await create_user_session(tmp_path, trustchain)
    bob = await create_user_session(tmp_path, trustchain)
    charlie = await create_user_session(tmp_path, trustchain)

    group_id = await alice.session.create_group(
        [alice.public_identity, bob.public_identity]
    )
    await alice.session.update_group_members(group_id, add=[charlie.public_identity])
    await check_share_with_group_works(alice, group_id, bob, charlie)


async def create_two_devices(
    tmp_path: Path, trustchain: App
) -> Tuple[str, Tanker, Tanker]:
    fake = Faker()
    passphrase = "this is my secure passphrase"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, fake.email()
    )
    await laptop_tanker.start(identity)
    await laptop_tanker.register_identity(passphrase=passphrase)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)

    await phone_tanker.start(identity)
    await phone_tanker.verify_identity(passphrase=passphrase)
    return identity, laptop_tanker, phone_tanker


@pytest.mark.asyncio
async def test_add_device(tmp_path: Path, trustchain: App) -> None:
    _, laptop, phone = await create_two_devices(tmp_path, trustchain)
    assert phone.status == TankerStatus.READY
    await laptop.stop()
    await phone.stop()


@pytest.mark.asyncio
async def test_revoke_device(tmp_path: Path, trustchain: App) -> None:
    identity, laptop, phone = await create_two_devices(tmp_path, trustchain)
    laptop_id = await laptop.device_id()
    laptop_revoked = asyncio.Event()
    loop = asyncio.get_event_loop()

    def on_revoked() -> None:
        async def cb() -> None:
            laptop_revoked.set()

        asyncio.run_coroutine_threadsafe(cb(), loop)

    laptop.on_revoked = on_revoked
    await phone.revoke_device(laptop_id)
    # Check callback is called
    await asyncio.wait_for(laptop_revoked.wait(), timeout=1)
    assert laptop.status == TankerStatus.STOPPED


@pytest.mark.asyncio
async def test_get_device_list(tmp_path: Path, trustchain: App) -> None:
    _, laptop, phone = await create_two_devices(tmp_path, trustchain)
    laptop_id = await laptop.device_id()
    phone_id = await phone.device_id()

    await phone.revoke_device(laptop_id)

    actual_list = await phone.get_device_list()
    actual_ids = [x.device_id for x in actual_list]
    assert set(actual_ids) == set([laptop_id, phone_id])
    revoked = [x for x in actual_list if x.is_revoked]
    assert len(revoked) == 1
    actual_revoked_id = revoked[0].device_id
    assert actual_revoked_id == laptop_id


@pytest.mark.asyncio
async def test_must_verify_identity_on_second_device(
    tmp_path: Path, trustchain: App
) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, fake.email()
    )
    passphrase = "my secure passphrase"
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(passphrase=passphrase)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()

    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)

    status = await phone_tanker.start(alice_identity)
    assert status == TankerStatus.IDENTITY_VERIFICATION_NEEDED


@pytest.mark.asyncio
async def test_using_verification_key_on_second_device(
    tmp_path: Path, trustchain: App
) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, fake.email()
    )
    await laptop_tanker.start(alice_identity)
    verification_key = await laptop_tanker.generate_verification_key()
    await laptop_tanker.register_identity(verification_key=verification_key)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)
    await phone_tanker.start(alice_identity)
    await phone_tanker.verify_identity(verification_key=verification_key)
    assert phone_tanker.status == TankerStatus.READY
    await laptop_tanker.stop()
    await phone_tanker.stop()


@pytest.mark.asyncio
async def test_invalid_verification_key(tmp_path: Path, trustchain: App) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, fake.email()
    )
    await laptop_tanker.start(alice_identity)
    verification_key = await laptop_tanker.generate_verification_key()
    await laptop_tanker.register_identity(verification_key=verification_key)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)
    await phone_tanker.start(alice_identity)

    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(verification_key="plop")
    assert error.value.code == ErrorCode.INVALID_VERIFICATION

    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(verification_key="")
    assert error.value.code == ErrorCode.INVALID_VERIFICATION

    key_json = base64.b64decode(verification_key.encode()).decode()
    key = json.loads(key_json)
    key[
        "privateSignatureKey"
    ] = "O85hg7XxxGWq3cQf4xQ/VXaTiAPcqWoUIGDvaLpZ+trNQkp+rNzZrLvIfhERwb33iUjV0sFiL5XqweVgqTdg6Q=="
    key_json = json.dumps(key)
    key = base64.b64encode(key_json.encode()).decode()

    with pytest.raises(TankerError):
        await phone_tanker.verify_identity(verification_key=key)


@pytest.mark.asyncio
async def test_email_verification(
    tmp_path: Path, trustchain: App, admin: Admin
) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    email = fake.email()
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, email
    )
    await laptop_tanker.start(alice_identity)
    verification_code = admin.get_verification_code(trustchain.id, email)
    await laptop_tanker.register_identity(
        email=email, verification_code=verification_code
    )
    assert len(verification_code) == 8

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    verification_code = admin.get_verification_code(trustchain.id, email)
    await phone_tanker.verify_identity(email=email, verification_code=verification_code)
    assert phone_tanker.status == TankerStatus.READY
    await laptop_tanker.stop()
    await phone_tanker.stop()


@pytest.mark.asyncio
async def test_bad_verification_code(
    tmp_path: Path, trustchain: App, admin: Admin
) -> None:
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
    await laptop_tanker.start(alice_identity)
    verification_code = admin.get_verification_code(trustchain.id, email)
    await laptop_tanker.register_identity(
        email=email, verification_code=verification_code
    )
    await phone_tanker.start(alice_identity)
    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(email=email, verification_code="12345678")
    assert error.value.code == ErrorCode.INVALID_VERIFICATION
    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(email=email, verification_code="azerty")
    assert error.value.code == ErrorCode.INVALID_VERIFICATION
    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(email=email, verification_code="")
    assert error.value.code == ErrorCode.INVALID_VERIFICATION
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    await laptop_tanker.stop()


PreUser = namedtuple(
    "PreUser",
    [
        "session",
        "public_identity",
        "private_identity",
        "public_provisional_identity",
        "private_provisional_identity",
        "email",
        "verification_code",
    ],
)


async def set_up_preshare(
    tmp_path: Path, trustchain: App, admin: Admin
) -> Tuple[User, PreUser]:
    fake = Faker()
    bob_email = fake.email()
    bob_provisional_identity = tankersdk_identity.create_provisional_identity(
        trustchain.id, bob_email
    )
    bob_public_provisional_identity = tankersdk_identity.get_public_identity(
        bob_provisional_identity
    )
    alice = await create_user_session(tmp_path, trustchain)
    bob = await create_user_session(tmp_path, trustchain)
    pre_bob = PreUser(
        session=bob.session,
        public_identity=bob.public_identity,
        private_identity=bob.private_identity,
        public_provisional_identity=bob_public_provisional_identity,
        private_provisional_identity=bob_provisional_identity,
        email=bob_email,
        verification_code=admin.get_verification_code(trustchain.id, bob_email),
    )
    return alice, pre_bob


@pytest.mark.asyncio
async def test_cannot_decrypt_if_provisional_identity_not_attached(
    tmp_path: Path, trustchain: App, admin: Admin
) -> None:
    alice, bob = await set_up_preshare(tmp_path, trustchain, admin)
    message = b"I love you"
    encrypted = await alice.session.encrypt(
        message, share_with_users=[bob.public_provisional_identity]
    )
    with pytest.raises(TankerError) as error:
        await bob.session.decrypt(encrypted)
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


async def share_and_attach_provisional_identity(
    tmp_path: Path, trustchain: App, admin: Admin
) -> Tuple[PreUser, bytes, bytes]:
    alice, bob = await set_up_preshare(tmp_path, trustchain, admin)
    message = b"I love you"
    encrypted = await alice.session.encrypt(
        message, share_with_users=[bob.public_provisional_identity]
    )
    attach_result = await bob.session.attach_provisional_identity(
        bob.private_provisional_identity
    )
    assert attach_result.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    actual_method = attach_result.verification_method
    assert actual_method.email == bob.email
    assert actual_method.method_type == tankersdk.VerificationMethodType.EMAIL

    verification_code = admin.get_verification_code(trustchain.id, bob.email)
    await bob.session.verify_provisional_identity(
        email=bob.email, verification_code=verification_code
    )
    return bob, encrypted, message


@pytest.mark.asyncio
async def test_attach_provisional_identity_simple(
    tmp_path: Path, trustchain: App, admin: Admin
) -> None:
    bob, encrypted, message = await share_and_attach_provisional_identity(
        tmp_path, trustchain, admin
    )
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_attach_provisional_identity_after_sign_out(
    tmp_path: Path, trustchain: App, admin: Admin
) -> None:
    bob, encrypted, message = await share_and_attach_provisional_identity(
        tmp_path, trustchain, admin
    )
    await bob.session.stop()
    await bob.session.start(bob.private_identity)
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_already_attached_identity(
    tmp_path: Path, trustchain: App, admin: Admin
) -> None:
    bob, _, _ = await share_and_attach_provisional_identity(tmp_path, trustchain, admin)
    attach_result = await bob.session.attach_provisional_identity(
        bob.private_provisional_identity
    )
    assert attach_result.status == TankerStatus.READY
    await bob.session.stop()


@pytest.mark.asyncio
async def test_attach_provisional_identity_with_incorrect_code(
    tmp_path: Path, trustchain: App, admin: Admin
) -> None:
    alice, bob = await set_up_preshare(tmp_path, trustchain, admin)
    message = b"I love you"
    await alice.session.encrypt(
        message, share_with_users=[bob.public_provisional_identity]
    )
    await bob.session.attach_provisional_identity(bob.private_provisional_identity)
    with pytest.raises(TankerError) as error:
        await bob.session.verify_identity(email=bob.email, verification_code="badCode")
    assert error.value.code == ErrorCode.PRECONDITION_FAILED


@pytest.mark.asyncio
async def test_update_verification_passphrase(tmp_path: Path, trustchain: App) -> None:
    fake = Faker()
    old_passphrase = "plop"
    new_passphrase = "zzzz"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(trustchain.id, writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, fake.email()
    )
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(passphrase=old_passphrase)

    await laptop_tanker.set_verification_method(passphrase=new_passphrase)

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(trustchain.id, writable_path=phone_path)
    await phone_tanker.start(alice_identity)

    # Old passphrase should not work
    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(passphrase=old_passphrase)
    assert error.value.code == ErrorCode.INVALID_VERIFICATION

    # But new passphrase should
    await phone_tanker.verify_identity(passphrase=new_passphrase)
    assert phone_tanker.status == TankerStatus.READY


@pytest.mark.asyncio
async def test_create_group_with_prov_id(
    tmp_path: Path, trustchain: App, admin: Admin
) -> None:
    alice, bob = await set_up_preshare(tmp_path, trustchain, admin)
    message = b"I love you all, my group"
    group_id = await alice.session.create_group([bob.public_provisional_identity])
    encrypted = await alice.session.encrypt(message, share_with_groups=[group_id])
    await bob.session.attach_provisional_identity(bob.private_provisional_identity)
    await bob.session.verify_provisional_identity(
        email=bob.email, verification_code=bob.verification_code
    )
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_add_to_group_with_prov_id(
    tmp_path: Path, trustchain: App, admin: Admin
) -> None:
    alice, bob = await set_up_preshare(tmp_path, trustchain, admin)
    message = b"Hi, this is for a group"
    group_id = await alice.session.create_group([alice.public_identity])
    encrypted = await alice.session.encrypt(message, share_with_groups=[group_id])
    await alice.session.update_group_members(
        group_id, add=[bob.public_provisional_identity]
    )
    await bob.session.attach_provisional_identity(bob.private_provisional_identity)
    await bob.session.verify_provisional_identity(
        email=bob.email, verification_code=bob.verification_code
    )
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_user_not_found(tmp_path: Path, trustchain: App) -> None:
    user_id = encode("*" * 32)
    identity_obj = {"trustchain_id": trustchain.id, "target": "user", "value": user_id}
    identity = encode(json.dumps(identity_obj))
    alice = await create_user_session(tmp_path, trustchain)
    with pytest.raises(TankerError) as error:
        await alice.session.create_group([identity])
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_decrypt_invalid_argument(tmp_path: Path, trustchain: App) -> None:
    alice = await create_user_session(tmp_path, trustchain)
    with pytest.raises(TankerError) as error:
        await alice.session.decrypt(b"zz")
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_recipient_not_found(tmp_path: Path, trustchain: App) -> None:
    group_id = encode("*" * 32)
    alice = await create_user_session(tmp_path, trustchain)
    with pytest.raises(TankerError) as error:
        await alice.session.encrypt(b"zz", share_with_groups=[group_id])
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_group_not_found(tmp_path: Path, trustchain: App) -> None:
    group_id = encode("*" * 32)
    alice = await create_user_session(tmp_path, trustchain)
    with pytest.raises(TankerError) as error:
        await alice.session.update_group_members(group_id, add=[alice.public_identity])
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_device_not_found(tmp_path: Path, trustchain: App) -> None:
    device_id = encode("*" * 32)
    alice = await create_user_session(tmp_path, trustchain)
    with pytest.raises(TankerError) as error:
        await alice.session.revoke_device(device_id)
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_get_verification_methods(
    tmp_path: Path, trustchain: App, admin: Admin
) -> None:
    tanker = create_tanker(trustchain.id, writable_path=tmp_path)
    faker = Faker()
    email = faker.email()
    identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, email
    )
    await tanker.start(identity)
    passphrase = "my passphrase"
    await tanker.register_identity(passphrase=passphrase)
    await tanker.stop()

    await tanker.start(identity)
    methods = await tanker.get_verification_methods()
    assert len(methods) == 1
    (actual_method,) = methods
    assert actual_method.method_type == VerificationMethodType.PASSPHRASE

    verification_code = admin.get_verification_code(trustchain.id, email)
    await tanker.set_verification_method(
        email=email, verification_code=verification_code
    )

    methods = await tanker.get_verification_methods()
    assert len(methods) == 2
    email_methods = [
        x for x in methods if x.method_type == VerificationMethodType.EMAIL
    ]
    assert len(email_methods) == 1
    (email_method,) = email_methods
    assert email_method.email == email


@pytest.mark.asyncio
async def test_oidc_verification(tmp_path: Path, trustchain: App, admin: Admin) -> None:
    oidc_test_config = TEST_CONFIG["oidc"]["googleAuth"]

    oidc_client_id = oidc_test_config["clientId"]
    oidc_client_secret = oidc_test_config["clientSecret"]
    oidc_client_provider = oidc_test_config["provider"]
    oidc_app_config = OIDCConfig(
        client_id=oidc_client_id, client_provider=oidc_client_provider
    )
    admin.update_app(trustchain.id, oidc_config=oidc_app_config)

    test_users = oidc_test_config["users"]
    user = "martine"
    assert user in test_users
    email = test_users[user]["email"]
    refresh_token = test_users[user]["refreshToken"]

    phone_path = tmp_path / "phone"
    phone_path.mkdir()
    martine_phone = create_tanker(trustchain.id, writable_path=phone_path)
    identity = tankersdk_identity.create_identity(
        trustchain.id, trustchain.private_key, email
    )

    response = requests.post(
        "https://www.googleapis.com/oauth2/v4/token",
        headers={"content-type": "application/json"},
        json={
            "client_id": oidc_client_id,
            "client_secret": oidc_client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
    )
    response.raise_for_status()
    oidc_id_token = response.json()["id_token"]

    await martine_phone.start(identity)
    await martine_phone.register_identity(oidc_id_token=oidc_id_token)
    await martine_phone.stop()

    laptop_path = tmp_path / "laptop"
    laptop_path.mkdir()
    martine_laptop = create_tanker(trustchain.id, writable_path=laptop_path)
    await martine_laptop.start(identity)

    assert martine_laptop.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    await martine_laptop.verify_identity(oidc_id_token=oidc_id_token)
    assert martine_laptop.status == TankerStatus.READY

    actual_methods = await martine_laptop.get_verification_methods()
    actual_method, = actual_methods
    assert actual_method.method_type == VerificationMethodType.OIDC_ID_TOKEN

    await martine_laptop.stop()
