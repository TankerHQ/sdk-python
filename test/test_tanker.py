import asyncio
import random
import base64
from collections import namedtuple
import io
import json
import os
import uuid

from path import Path
from faker import Faker
import requests
from typing import cast, Any, Dict, Iterator, Tuple

import tankersdk
from tankersdk import Tanker, Error as TankerError, ErrorCode
from tankersdk import Status as TankerStatus
from tankersdk import (
    EncryptionOptions,
    EmailVerification,
    EmailVerificationMethod,
    VerificationMethodType,
    PassphraseVerification,
    SharingOptions,
    OidcIdTokenVerification,
    VerificationKeyVerification,
)
import tankersdk_identity
import tankeradminsdk
from tankeradminsdk import Admin

import pytest


def encode(string: str) -> str:
    return base64.b64encode(string.encode()).decode()


def assert_env(name: str) -> str:
    value = os.environ.get(name)
    assert value, f"{name} should be set before running tests"
    return value


def read_test_config() -> Dict[str, Any]:
    res: Dict[str, Any] = {}
    res["server"] = {
        "adminUrl": assert_env("TANKER_ADMIND_URL"),
        "idToken": assert_env("TANKER_ID_TOKEN"),
        "url": assert_env("TANKER_TRUSTCHAIND_URL"),
    }
    res["oidc"] = {
        "clientId": assert_env("TANKER_OIDC_CLIENT_ID"),
        "clientSecret": assert_env("TANKER_OIDC_CLIENT_SECRET"),
        "provider": assert_env("TANKER_OIDC_PROVIDER"),
    }
    res["oidc"]["users"] = {
        "martine": {
            "email": assert_env("TANKER_OIDC_MARTINE_EMAIL"),
            "refreshToken": assert_env("TANKER_OIDC_MARTINE_REFRESH_TOKEN"),
        }
    }
    return res


TEST_CONFIG = read_test_config()


def create_tanker(app_id: str, *, writable_path: str) -> Tanker:
    return Tanker(
        app_id,
        url=cast(str, TEST_CONFIG["server"]["url"]),
        sdk_type="sdk-python-test",
        writable_path=writable_path,
    )


@pytest.fixture()
def tmp_path(tmpdir: str) -> Path:
    path = Path(str(tmpdir))
    path.mkdir_p()
    return path


@pytest.fixture(scope="session")
def admin() -> Iterator[Admin]:
    yield Admin(
        url=TEST_CONFIG["server"]["adminUrl"], id_token=TEST_CONFIG["server"]["idToken"]
    )


@pytest.fixture(scope="session")
def app(admin: Admin) -> Iterator[Dict[str, str]]:
    name = "python_bindings"
    app = admin.create_app(name, is_test=True)
    yield app
    admin.delete_app(app["id"])


def test_native_version() -> None:
    native_version = tankersdk.native_version()
    assert native_version


def test_init_tanker_ok(tmp_path: Path, app: Dict[str, str]) -> None:
    tanker = create_tanker(app_id=app["id"], writable_path=tmp_path)
    assert tanker.url == TEST_CONFIG["server"]["url"]


def test_init_tanker_invalid_id(tmp_path: Path) -> None:
    with pytest.raises(TankerError) as error:
        create_tanker(app_id="invalid bad 64", writable_path=tmp_path)
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_tanker_start_invalid_path(app: Dict[str, str]) -> None:
    tanker = create_tanker(app_id=app["id"], writable_path="/path/to/no-such")
    fake = Faker()
    user_id = fake.email(domain="tanker.io")
    identity = tankersdk_identity.create_identity(app["id"], app["app_secret"], user_id)
    with pytest.raises(TankerError) as error:
        await tanker.start(identity)
    assert error.value.code == ErrorCode.INTERNAL_ERROR


@pytest.mark.asyncio
async def test_tanker_sdk_version(tmp_path: Path, app: Dict[str, str]) -> None:
    tanker = create_tanker(app["id"], writable_path=tmp_path)
    sdk_version = tanker.sdk_version
    assert sdk_version


@pytest.mark.asyncio
async def test_start_new_account(tmp_path: Path, app: Dict[str, str]) -> None:
    tanker = create_tanker(app["id"], writable_path=tmp_path)
    fake = Faker()
    user_id = fake.email(domain="tanker.io")
    identity = tankersdk_identity.create_identity(app["id"], app["app_secret"], user_id)
    status = await tanker.start(identity)
    assert status == TankerStatus.IDENTITY_REGISTRATION_NEEDED
    key = await tanker.generate_verification_key()
    await tanker.register_identity(VerificationKeyVerification(key))
    assert tanker.status == TankerStatus.READY
    device_id = await tanker.device_id()
    assert device_id
    await tanker.stop()
    assert tanker.status == TankerStatus.STOPPED


@pytest.mark.asyncio
async def test_start_identity_incorrect_format(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    tanker = create_tanker(app["id"], writable_path=tmp_path)
    with pytest.raises(TankerError) as error:
        await tanker.start("bad identity")
    assert error.value.code == ErrorCode.INVALID_ARGUMENT
    await tanker.stop()


@pytest.mark.asyncio
async def test_create_account_then_sign_in(tmp_path: Path, app: Dict[str, str]) -> None:
    fake = Faker()
    user_id = fake.email(domain="tanker.io")
    tanker = create_tanker(app["id"], writable_path=tmp_path)
    identity = tankersdk_identity.create_identity(app["id"], app["app_secret"], user_id)
    await tanker.start(identity)
    key = await tanker.generate_verification_key()
    await tanker.register_identity(VerificationKeyVerification(key))
    await tanker.stop()

    await tanker.start(identity)
    assert tanker.status == TankerStatus.READY
    await tanker.stop()


User = namedtuple("User", ["session", "public_identity", "private_identity"])


async def create_user_session(tmp_path: Path, app: Dict[str, str]) -> User:
    user_id = str(random.randrange(1 << 64))
    tanker = create_tanker(app["id"], writable_path=tmp_path)
    private_identity = tankersdk_identity.create_identity(
        app["id"], app["app_secret"], user_id
    )
    public_identity = tankersdk_identity.get_public_identity(private_identity)
    await tanker.start(private_identity)
    key = await tanker.generate_verification_key()
    await tanker.register_identity(VerificationKeyVerification(key))
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
        self, tmp_path: Path, app: Dict[str, str]
    ) -> None:
        alice = await create_user_session(tmp_path, app)
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
    async def test_async_read_in_one_go(
        self, tmp_path: Path, app: Dict[str, str]
    ) -> None:
        alice = await create_user_session(tmp_path, app)
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
    async def test_error_handling(self, tmp_path: Path, app: Dict[str, str]) -> None:
        alice = await create_user_session(tmp_path, app)
        message = bytearray(1024 * 1024 * 3 + 2)
        input_stream = FailingStream(message)
        encrypted_stream = await alice.session.encrypt_stream(input_stream)
        with pytest.raises(Exception) as e:
            await alice.session.decrypt_stream(encrypted_stream)
        assert e.value.args == ("Kaboom",)
        await alice.session.stop()

    @pytest.mark.asyncio
    async def test_empty_message(self, tmp_path: Path, app: Dict[str, str]) -> None:
        alice = await create_user_session(tmp_path, app)
        empty_message = bytearray()
        input_stream = InMemoryAsyncStream(empty_message)
        encrypted_stream = await alice.session.encrypt_stream(input_stream)
        async with await alice.session.decrypt_stream(encrypted_stream) as f:
            result = await f.read(1024)
            assert len(result) == 0
        await alice.session.stop()


@pytest.mark.asyncio
async def test_encrypt_decrypt(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b"I love you"
    encrypted_data = await alice.session.encrypt(message)
    clear_data = await alice.session.decrypt(encrypted_data)
    assert clear_data == message
    await alice.session.stop()


@pytest.mark.asyncio
async def test_share_during_encrypt(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    bob = await create_user_session(tmp_path, app)
    message = b"I love you"
    encrypted = await alice.session.encrypt(
        message, EncryptionOptions(share_with_users=[bob.public_identity])
    )
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()
    await bob.session.stop()


@pytest.mark.asyncio
async def test_share_during_encrypt_without_self(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice = await create_user_session(tmp_path, app)
    bob = await create_user_session(tmp_path, app)
    message = b"I love you"
    encrypted = await alice.session.encrypt(
        message,
        EncryptionOptions(
            share_with_users=[bob.public_identity], share_with_self=False
        ),
    )
    with pytest.raises(TankerError) as error:
        await alice.session.decrypt(encrypted)
    assert error.value.code == ErrorCode.INVALID_ARGUMENT
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()
    await bob.session.stop()


@pytest.mark.asyncio
async def test_postponed_share(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    bob = await create_user_session(tmp_path, app)
    message = b"I love you"
    encrypted = await alice.session.encrypt(message)
    resource_id = alice.session.get_resource_id(encrypted)
    await alice.session.share(
        [resource_id], SharingOptions(share_with_users=[bob.public_identity])
    )

    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()
    await bob.session.stop()


async def check_share_with_group_works(
    alice: User, group_id: str, bob: User, charlie: User
) -> None:
    message = b"Hi, guys"
    encrypted = await alice.session.encrypt(
        message, EncryptionOptions(share_with_groups=[group_id])
    )
    decrypted = await charlie.session.decrypt(encrypted)
    assert decrypted == message
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_create_group(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    bob = await create_user_session(tmp_path, app)
    charlie = await create_user_session(tmp_path, app)

    group_id = await alice.session.create_group(
        [bob.public_identity, charlie.public_identity]
    )
    await check_share_with_group_works(alice, group_id, bob, charlie)


@pytest.mark.asyncio
async def test_update_group(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    bob = await create_user_session(tmp_path, app)
    charlie = await create_user_session(tmp_path, app)

    group_id = await alice.session.create_group(
        [alice.public_identity, bob.public_identity]
    )
    await alice.session.update_group_members(
        group_id, users_to_add=[charlie.public_identity]
    )
    await check_share_with_group_works(alice, group_id, bob, charlie)


@pytest.mark.asyncio
async def test_encryption_session_resource_id_matches_ciphertext(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b"Henri-Robert-Marcel"
    async with await alice.session.create_encryption_session() as enc_session:
        encrypted = await enc_session.encrypt(message)
        sess_id = enc_session.get_resource_id()

    cipher_id = alice.session.get_resource_id(encrypted)
    assert sess_id == cipher_id
    await alice.session.stop()


@pytest.mark.asyncio
async def test_share_with_encryption_session(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice = await create_user_session(tmp_path, app)
    bob = await create_user_session(tmp_path, app)
    message = b"Ceci n'est pas un test"
    enc_session = await alice.session.create_encryption_session(
        EncryptionOptions(share_with_users=[bob.public_identity])
    )
    encrypted = await enc_session.encrypt(message)

    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()
    await bob.session.stop()


@pytest.mark.asyncio
async def test_share_with_encryption_session_without_self(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice = await create_user_session(tmp_path, app)
    bob = await create_user_session(tmp_path, app)
    message = b"Ceci n'est pas un test"
    options = EncryptionOptions(
        share_with_users=[bob.public_identity], share_with_self=False,
    )
    async with await alice.session.create_encryption_session(options) as enc_session:
        encrypted = await enc_session.encrypt(message)

    with pytest.raises(TankerError) as error:
        await alice.session.decrypt(encrypted)
    assert error.value.code == ErrorCode.INVALID_ARGUMENT

    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()
    await bob.session.stop()


@pytest.mark.asyncio
async def test_encryption_session_streams(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    chunk_size = 1024 ** 2
    message = bytearray(3 * chunk_size + 2)  # three big chunks plus a little something
    input_stream = InMemoryAsyncStream(message)
    async with await alice.session.create_encryption_session() as enc_session:
        encrypted_stream = await enc_session.encrypt_stream(input_stream)
    async with await alice.session.decrypt_stream(encrypted_stream) as f:
        decrypted_message = await f.read()
    assert decrypted_message == message
    await alice.session.stop()


async def create_two_devices(
    tmp_path: Path, app: Dict[str, str]
) -> Tuple[str, Tanker, Tanker]:
    fake = Faker()
    passphrase = "this is my secure passphrase"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(app["id"], writable_path=laptop_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["app_secret"], fake.email(domain="tanker.io")
    )
    await laptop_tanker.start(identity)
    await laptop_tanker.register_identity(PassphraseVerification(passphrase))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(app["id"], writable_path=phone_path)

    await phone_tanker.start(identity)
    await phone_tanker.verify_identity(PassphraseVerification(passphrase))
    return identity, laptop_tanker, phone_tanker


@pytest.mark.asyncio
async def test_add_device(tmp_path: Path, app: Dict[str, str]) -> None:
    _, laptop, phone = await create_two_devices(tmp_path, app)
    assert phone.status == TankerStatus.READY
    await laptop.stop()
    await phone.stop()


@pytest.mark.asyncio
async def test_revoke_device(tmp_path: Path, app: Dict[str, str]) -> None:
    _, laptop, phone = await create_two_devices(tmp_path, app)
    laptop_id = await laptop.device_id()
    laptop_revoked = asyncio.Event()
    loop = asyncio.get_event_loop()

    def on_revoked() -> None:
        async def cb() -> None:
            laptop_revoked.set()

        asyncio.run_coroutine_threadsafe(cb(), loop)

    laptop.on_revoked = on_revoked
    await phone.revoke_device(laptop_id)
    with pytest.raises(TankerError) as error:
        await laptop.encrypt(b"will fail")
    assert error.value.code == ErrorCode.DEVICE_REVOKED
    # Check callback is called
    await asyncio.wait_for(laptop_revoked.wait(), timeout=1)
    assert laptop.status == TankerStatus.STOPPED


@pytest.mark.asyncio
async def test_get_device_list(tmp_path: Path, app: Dict[str, str]) -> None:
    _, laptop, phone = await create_two_devices(tmp_path, app)
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
    tmp_path: Path, app: Dict[str, str]
) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(app["id"], writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"], app["app_secret"], fake.email(domain="tanker.io")
    )
    passphrase = "my secure passphrase"
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(PassphraseVerification(passphrase))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()

    phone_tanker = create_tanker(app["id"], writable_path=phone_path)

    status = await phone_tanker.start(alice_identity)
    assert status == TankerStatus.IDENTITY_VERIFICATION_NEEDED


@pytest.mark.asyncio
async def test_using_verification_key_on_second_device(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(app["id"], writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"], app["app_secret"], fake.email(domain="tanker.io")
    )
    await laptop_tanker.start(alice_identity)
    verification_key = await laptop_tanker.generate_verification_key()
    await laptop_tanker.register_identity(VerificationKeyVerification(verification_key))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(app["id"], writable_path=phone_path)
    await phone_tanker.start(alice_identity)
    await phone_tanker.verify_identity(VerificationKeyVerification(verification_key))
    assert phone_tanker.status == TankerStatus.READY
    await laptop_tanker.stop()
    await phone_tanker.stop()


@pytest.mark.asyncio
async def test_invalid_verification_key(tmp_path: Path, app: Dict[str, str]) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(app["id"], writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"], app["app_secret"], fake.email(domain="tanker.io")
    )
    await laptop_tanker.start(alice_identity)
    verification_key = await laptop_tanker.generate_verification_key()
    await laptop_tanker.register_identity(VerificationKeyVerification(verification_key))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(app["id"], writable_path=phone_path)
    await phone_tanker.start(alice_identity)

    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(VerificationKeyVerification("plop"))
    assert error.value.code == ErrorCode.INVALID_VERIFICATION

    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(VerificationKeyVerification(""))
    assert error.value.code == ErrorCode.INVALID_VERIFICATION

    key_json = base64.b64decode(verification_key.encode()).decode()
    key = json.loads(key_json)
    key[
        "privateSignatureKey"
    ] = "O85hg7XxxGWq3cQf4xQ/VXaTiAPcqWoUIGDvaLpZ+trNQkp+rNzZrLvIfhERwb33iUjV0sFiL5XqweVgqTdg6Q=="
    key_json = json.dumps(key)
    key = base64.b64encode(key_json.encode()).decode()

    with pytest.raises(TankerError):
        await phone_tanker.verify_identity(VerificationKeyVerification(key))


def get_verification_code(app: Dict[str, str], email: str) -> str:
    return tankeradminsdk.get_verification_code(
        url=TEST_CONFIG["server"]["url"],
        app_id=app["id"],
        auth_token=app["auth_token"],
        email=email,
    )


@pytest.mark.asyncio
async def test_email_verification(tmp_path: Path, app: Dict[str, str]) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(app["id"], writable_path=laptop_path)
    email = fake.email(domain="tanker.io")
    alice_identity = tankersdk_identity.create_identity(
        app["id"], app["app_secret"], email
    )
    await laptop_tanker.start(alice_identity)
    verification_code = get_verification_code(app, email)
    await laptop_tanker.register_identity(EmailVerification(email, verification_code))
    assert len(verification_code) == 8

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(app["id"], writable_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    verification_code = get_verification_code(app, email)
    await phone_tanker.verify_identity(EmailVerification(email, verification_code))
    assert phone_tanker.status == TankerStatus.READY
    await laptop_tanker.stop()
    await phone_tanker.stop()


@pytest.mark.asyncio
async def test_bad_verification_code(tmp_path: Path, app: Dict[str, str]) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(app["id"], writable_path=laptop_path)
    email = fake.email(domain="tanker.io")
    alice_identity = tankersdk_identity.create_identity(
        app["id"], app["app_secret"], email
    )
    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(app["id"], writable_path=phone_path)
    await laptop_tanker.start(alice_identity)
    verification_code = get_verification_code(app, email)
    await laptop_tanker.register_identity(EmailVerification(email, verification_code))
    await phone_tanker.start(alice_identity)
    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(EmailVerification(email, "12345678"))
    assert error.value.code == ErrorCode.INVALID_VERIFICATION
    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(EmailVerification(email, "azerty"))
    assert error.value.code == ErrorCode.INVALID_VERIFICATION
    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(EmailVerification(email, ""))
    assert error.value.code == ErrorCode.INVALID_ARGUMENT
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


async def set_up_preshare(tmp_path: Path, app: Dict[str, str]) -> Tuple[User, PreUser]:
    fake = Faker()
    bob_email = fake.email(domain="tanker.io")
    bob_provisional_identity = tankersdk_identity.create_provisional_identity(
        app["id"], bob_email
    )
    bob_public_provisional_identity = tankersdk_identity.get_public_identity(
        bob_provisional_identity
    )
    alice = await create_user_session(tmp_path, app)
    bob = await create_user_session(tmp_path, app)
    pre_bob = PreUser(
        session=bob.session,
        public_identity=bob.public_identity,
        private_identity=bob.private_identity,
        public_provisional_identity=bob_public_provisional_identity,
        private_provisional_identity=bob_provisional_identity,
        email=bob_email,
        verification_code=get_verification_code(app, bob_email),
    )
    return alice, pre_bob


@pytest.mark.asyncio
async def test_cannot_decrypt_if_provisional_identity_not_attached(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice, bob = await set_up_preshare(tmp_path, app)
    message = b"I love you"
    encrypted = await alice.session.encrypt(
        message, EncryptionOptions(share_with_users=[bob.public_provisional_identity])
    )
    with pytest.raises(TankerError) as error:
        await bob.session.decrypt(encrypted)
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


async def share_and_attach_provisional_identity(
    tmp_path: Path, app: Dict[str, str]
) -> Tuple[PreUser, bytes, bytes]:
    alice, bob = await set_up_preshare(tmp_path, app)
    message = b"I love you"
    encrypted = await alice.session.encrypt(
        message, EncryptionOptions(share_with_users=[bob.public_provisional_identity])
    )
    attach_result = await bob.session.attach_provisional_identity(
        bob.private_provisional_identity
    )
    assert attach_result.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    actual_method = attach_result.verification_method
    assert actual_method.email == bob.email
    assert actual_method.method_type == tankersdk.VerificationMethodType.EMAIL

    verification_code = get_verification_code(app, bob.email)
    await bob.session.verify_provisional_identity(
        EmailVerification(bob.email, verification_code)
    )
    return bob, encrypted, message


@pytest.mark.asyncio
async def test_attach_provisional_identity_simple(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    bob, encrypted, message = await share_and_attach_provisional_identity(tmp_path, app)
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_attach_provisional_identity_after_sign_out(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    bob, encrypted, message = await share_and_attach_provisional_identity(tmp_path, app)
    await bob.session.stop()
    await bob.session.start(bob.private_identity)
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_already_attached_identity(tmp_path: Path, app: Dict[str, str]) -> None:
    bob, _, _ = await share_and_attach_provisional_identity(tmp_path, app)
    attach_result = await bob.session.attach_provisional_identity(
        bob.private_provisional_identity
    )
    assert attach_result.status == TankerStatus.READY
    await bob.session.stop()


@pytest.mark.asyncio
async def test_attach_provisional_identity_with_incorrect_code(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice, bob = await set_up_preshare(tmp_path, app)
    message = b"I love you"
    await alice.session.encrypt(
        message, EncryptionOptions(share_with_users=[bob.public_provisional_identity])
    )
    await bob.session.attach_provisional_identity(bob.private_provisional_identity)
    with pytest.raises(TankerError) as error:
        await bob.session.verify_identity(EmailVerification(bob.email, "badCode"))
    assert error.value.code == ErrorCode.PRECONDITION_FAILED


@pytest.mark.asyncio
async def test_update_verification_passphrase(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    fake = Faker()
    old_passphrase = "plop"
    new_passphrase = "zzzz"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir_p()
    laptop_tanker = create_tanker(app["id"], writable_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"], app["app_secret"], fake.email(domain="tanker.io")
    )
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(PassphraseVerification(old_passphrase))

    await laptop_tanker.set_verification_method(PassphraseVerification(new_passphrase))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir_p()
    phone_tanker = create_tanker(app["id"], writable_path=phone_path)
    await phone_tanker.start(alice_identity)

    # Old passphrase should not work
    with pytest.raises(TankerError) as error:
        await phone_tanker.verify_identity(PassphraseVerification(old_passphrase))
    assert error.value.code == ErrorCode.INVALID_VERIFICATION

    # But new passphrase should
    await phone_tanker.verify_identity(PassphraseVerification(new_passphrase))
    assert phone_tanker.status == TankerStatus.READY


@pytest.mark.asyncio
async def test_create_group_with_prov_id(tmp_path: Path, app: Dict[str, str]) -> None:
    alice, bob = await set_up_preshare(tmp_path, app)
    message = b"I love you all, my group"
    group_id = await alice.session.create_group([bob.public_provisional_identity])
    encrypted = await alice.session.encrypt(
        message, EncryptionOptions(share_with_groups=[group_id])
    )
    await bob.session.attach_provisional_identity(bob.private_provisional_identity)
    await bob.session.verify_provisional_identity(
        EmailVerification(bob.email, bob.verification_code)
    )
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_add_to_group_with_prov_id(tmp_path: Path, app: Dict[str, str]) -> None:
    alice, bob = await set_up_preshare(tmp_path, app)
    message = b"Hi, this is for a group"
    group_id = await alice.session.create_group([alice.public_identity])
    encrypted = await alice.session.encrypt(
        message, EncryptionOptions(share_with_groups=[group_id])
    )
    await alice.session.update_group_members(
        group_id, users_to_add=[bob.public_provisional_identity]
    )
    await bob.session.attach_provisional_identity(bob.private_provisional_identity)
    await bob.session.verify_provisional_identity(
        EmailVerification(bob.email, bob.verification_code)
    )
    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message


@pytest.mark.asyncio
async def test_user_not_found(tmp_path: Path, app: Dict[str, str]) -> None:
    user_id = encode("*" * 32)
    identity_obj = {"app_id": app["id"], "target": "user", "value": user_id}
    identity = encode(json.dumps(identity_obj))
    alice = await create_user_session(tmp_path, app)
    with pytest.raises(TankerError) as error:
        await alice.session.create_group([identity])
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_decrypt_invalid_argument(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    with pytest.raises(TankerError) as error:
        await alice.session.decrypt(b"zz")
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_recipient_not_found(tmp_path: Path, app: Dict[str, str]) -> None:
    group_id = encode("*" * 32)
    alice = await create_user_session(tmp_path, app)
    with pytest.raises(TankerError) as error:
        await alice.session.encrypt(
            b"zz", EncryptionOptions(share_with_groups=[group_id])
        )
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_group_not_found(tmp_path: Path, app: Dict[str, str]) -> None:
    group_id = encode("*" * 32)
    alice = await create_user_session(tmp_path, app)
    with pytest.raises(TankerError) as error:
        await alice.session.update_group_members(
            group_id, users_to_add=[alice.public_identity]
        )
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_device_not_found(tmp_path: Path, app: Dict[str, str]) -> None:
    device_id = encode("*" * 32)
    alice = await create_user_session(tmp_path, app)
    with pytest.raises(TankerError) as error:
        await alice.session.revoke_device(device_id)
    assert error.value.code == ErrorCode.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_get_verification_methods(tmp_path: Path, app: Dict[str, str]) -> None:
    tanker = create_tanker(app["id"], writable_path=tmp_path)
    faker = Faker()
    email = faker.email(domain="tanker.io")
    identity = tankersdk_identity.create_identity(app["id"], app["app_secret"], email)
    await tanker.start(identity)
    passphrase = "my passphrase"
    await tanker.register_identity(PassphraseVerification(passphrase))
    await tanker.stop()

    await tanker.start(identity)
    methods = await tanker.get_verification_methods()
    assert len(methods) == 1
    (actual_method,) = methods
    assert actual_method.method_type == VerificationMethodType.PASSPHRASE

    verification_code = get_verification_code(app, email)
    await tanker.set_verification_method(EmailVerification(email, verification_code))

    methods = await tanker.get_verification_methods()
    assert len(methods) == 2
    email_methods = [x for x in methods if isinstance(x, EmailVerificationMethod)]
    assert len(email_methods) == 1
    (email_method,) = email_methods
    assert email_method.email == email


def set_up_oidc(app: Dict[str, str], admin: Admin, user: str) -> Tuple[str, str]:
    oidc_test_config = TEST_CONFIG["oidc"]

    oidc_client_id = oidc_test_config["clientId"]
    oidc_client_secret = oidc_test_config["clientSecret"]
    oidc_provider = oidc_test_config["provider"]
    admin.update_app(
        app["id"], oidc_client_id=oidc_client_id, oidc_provider=oidc_provider,
    )

    test_users = oidc_test_config["users"]
    assert user in test_users
    email = test_users[user]["email"]
    refresh_token = test_users[user]["refreshToken"]
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
    return email, oidc_id_token


@pytest.mark.asyncio
async def test_oidc_verification(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    _, oidc_id_token = set_up_oidc(app, admin, "martine")

    phone_path = tmp_path / "phone"
    phone_path.mkdir()
    martine_phone = create_tanker(app["id"], writable_path=phone_path)
    user_id = str(uuid.uuid4())
    identity = tankersdk_identity.create_identity(app["id"], app["app_secret"], user_id)

    await martine_phone.start(identity)
    await martine_phone.register_identity(OidcIdTokenVerification(oidc_id_token))
    await martine_phone.stop()

    laptop_path = tmp_path / "laptop"
    laptop_path.mkdir()
    martine_laptop = create_tanker(app["id"], writable_path=laptop_path)
    await martine_laptop.start(identity)

    assert martine_laptop.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    await martine_laptop.verify_identity(OidcIdTokenVerification(oidc_id_token))
    assert martine_laptop.status == TankerStatus.READY

    actual_methods = await martine_laptop.get_verification_methods()
    (actual_method,) = actual_methods
    assert actual_method.method_type == VerificationMethodType.OIDC_ID_TOKEN

    await martine_laptop.stop()


@pytest.mark.asyncio
async def test_oidc_preshare(tmp_path: Path, app: Dict[str, str], admin: Admin) -> None:
    email, oidc_id_token = set_up_oidc(app, admin, "martine")
    alice = await create_user_session(tmp_path, app)

    provisional_identity = tankersdk_identity.create_provisional_identity(
        app["id"], email
    )
    public_provisional_identity = tankersdk_identity.get_public_identity(
        provisional_identity
    )

    message = b"hello OIDC user"
    encrypted = await alice.session.encrypt(
        message, EncryptionOptions(share_with_users=[public_provisional_identity])
    )

    martine_phone = create_tanker(app["id"], writable_path=tmp_path)
    user_id = str(uuid.uuid4())
    identity = tankersdk_identity.create_identity(app["id"], app["app_secret"], user_id)

    status = await martine_phone.start(identity)
    assert status == TankerStatus.IDENTITY_REGISTRATION_NEEDED
    await martine_phone.register_identity(OidcIdTokenVerification(oidc_id_token))
    res = await martine_phone.attach_provisional_identity(provisional_identity)
    assert res.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    await martine_phone.verify_provisional_identity(
        OidcIdTokenVerification(oidc_id_token)
    )
    clear_data = await alice.session.decrypt(encrypted)
    assert clear_data == message
    await martine_phone.stop()
    await alice.session.stop()


def test_prehash_password_empty() -> None:
    with pytest.raises(TankerError) as e:
        tankersdk.prehash_password("")
    assert e.value.code == ErrorCode.INVALID_ARGUMENT


def test_prehash_password_vector_1() -> None:
    input = "super secretive password"
    expected = "UYNRgDLSClFWKsJ7dl9uPJjhpIoEzadksv/Mf44gSHI="
    assert tankersdk.prehash_password(input) == expected


def test_prehash_password_vector_2() -> None:
    input = "test éå 한국어 😃"
    expected = "Pkn/pjub2uwkBDpt2HUieWOXP5xLn0Zlen16ID4C7jI="
    assert tankersdk.prehash_password(input) == expected
