import base64
import io
import json
import os
import uuid
from collections import namedtuple
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple, cast

import pytest
import requests
import tankeradminsdk
import tankersdk_identity
from faker import Faker
from tankeradminsdk import Admin, AppOidcProvider

import tankersdk
from tankersdk import (
    E2ePassphraseVerification,
    EmailVerification,
    EmailVerificationMethod,
    EncryptionOptions,
    OidcIdTokenVerification,
    OidcIdTokenVerificationMethod,
    Padding,
    PassphraseVerification,
    PhoneNumberVerification,
    PhoneNumberVerificationMethod,
    PreverifiedEmailVerification,
    PreverifiedEmailVerificationMethod,
    PreverifiedOIDCVerification,
    PreverifiedPhoneNumberVerification,
    PreverifiedPhoneNumberVerificationMethod,
    SharingOptions,
)
from tankersdk import Status as TankerStatus
from tankersdk import (
    Tanker,
    VerificationKeyVerification,
    VerificationMethodType,
    VerificationOptions,
    error,
)
from tankersdk.experimental import authenticate_with_idp


def encode(string: str) -> str:
    return base64.b64encode(string.encode()).decode()


def assert_env(name: str) -> str:
    value = os.environ.get(name)
    assert value, f"{name} should be set before running tests"
    return value


def read_test_config() -> Dict[str, Any]:
    res: Dict[str, Any] = {}
    res["server"] = {
        "appManagementApiToken": assert_env("TANKER_MANAGEMENT_API_ACCESS_TOKEN"),
        "appManagementApiUrl": assert_env("TANKER_MANAGEMENT_API_URL"),
        "environmentName": assert_env("TANKER_MANAGEMENT_API_DEFAULT_ENVIRONMENT_NAME"),
        "url": assert_env("TANKER_APPD_URL"),
        "trustchaindUrl": assert_env("TANKER_TRUSTCHAIND_URL"),
        "verificationApiToken": assert_env("TANKER_VERIFICATION_API_TEST_TOKEN"),
    }
    res["oidc"] = {
        "clientId": assert_env("TANKER_OIDC_CLIENT_ID"),
        "clientSecret": assert_env("TANKER_OIDC_CLIENT_SECRET"),
        "provider": assert_env("TANKER_OIDC_PROVIDER"),
        "issuer": assert_env("TANKER_OIDC_ISSUER"),
        "fakeOidcIssuerUrl": assert_env("TANKER_FAKE_OIDC_URL") + "/issuer",
    }
    res["oidc"]["users"] = {
        "martine": {
            "email": assert_env("TANKER_OIDC_MARTINE_EMAIL"),
            "refreshToken": assert_env("TANKER_OIDC_MARTINE_REFRESH_TOKEN"),
        }
    }
    return res


TEST_CONFIG = read_test_config()


def create_tanker(app_id: str, *, persistent_path: Path) -> Tanker:
    return Tanker(
        app_id,
        url=cast(str, TEST_CONFIG["server"]["url"]),
        sdk_type="sdk-python-test",
        persistent_path=str(persistent_path),
        cache_path=str(persistent_path),
    )


@pytest.fixture()
def tmp_path(tmpdir: str) -> Path:
    path = Path(str(tmpdir))
    path.mkdir(exist_ok=True)
    return path


@pytest.fixture(scope="session")
def admin() -> Iterator[Admin]:
    yield Admin(
        url=TEST_CONFIG["server"]["appManagementApiUrl"],
        app_management_token=TEST_CONFIG["server"]["appManagementApiToken"],
        environment_name=TEST_CONFIG["server"]["environmentName"],
    )


@pytest.fixture(scope="session")
def app(admin: Admin) -> Iterator[Dict[str, str]]:
    name = "sdk-python-tests"
    app = admin.create_app(name)
    yield app
    admin.delete_app(app["id"])


def test_native_version() -> None:
    native_version = tankersdk.native_version()
    assert native_version


def test_init_tanker_ok(tmp_path: Path, app: Dict[str, str]) -> None:
    tanker = create_tanker(app_id=app["id"], persistent_path=tmp_path)
    assert tanker.url == TEST_CONFIG["server"]["url"]


def test_init_tanker_invalid_id(tmp_path: Path) -> None:
    with pytest.raises(error.InvalidArgument):
        create_tanker(app_id="invalid bad 64", persistent_path=tmp_path)


@pytest.mark.asyncio
async def test_tanker_start_invalid_path(app: Dict[str, str]) -> None:
    tanker = create_tanker(app_id=app["id"], persistent_path=Path("/path/to/no-such"))
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    with pytest.raises(error.InternalError):
        await tanker.start(identity)


@pytest.mark.asyncio
async def test_tanker_enroll_user_fails_with_passphrase(
    app: Dict[str, str], admin: Admin
) -> None:
    admin.update_app(
        app["id"],
        user_enrollment=True,
    )
    server = create_tanker(app["id"], persistent_path=tmp_path)

    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )

    passphrase = "this is my secure passphrase"

    with pytest.raises(error.InvalidArgument):
        await server.enroll_user(
            identity, [PassphraseVerification(passphrase=passphrase)]
        )


@pytest.mark.asyncio
async def test_tanker_enroll_user_fails_with_email(
    app: Dict[str, str], admin: Admin
) -> None:
    admin.update_app(
        app["id"],
        user_enrollment=True,
    )
    server = create_tanker(app["id"], persistent_path=tmp_path)

    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )

    fake = Faker()
    email = fake.email(domain="tanker.io")

    verification_code = get_verification_code_email(app, email)

    with pytest.raises(error.InvalidArgument):
        await server.enroll_user(
            identity, [EmailVerification(email, verification_code)]
        )


@pytest.mark.asyncio
async def test_tanker_enroll_user_fails_with_phone_number(
    app: Dict[str, str], admin: Admin
) -> None:
    admin.update_app(
        app["id"],
        user_enrollment=True,
    )
    server = create_tanker(app["id"], persistent_path=tmp_path)

    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )

    phone_number = "+33639982233"

    verification_code = get_verification_code_sms(app, phone_number)

    with pytest.raises(error.InvalidArgument):
        await server.enroll_user(
            identity, [PhoneNumberVerification(phone_number, verification_code)]
        )


@pytest.mark.asyncio
async def test_tanker_enroll_user_with_preverified_methods(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    admin.update_app(
        app["id"],
        user_enrollment=True,
    )
    server = create_tanker(app["id"], persistent_path=tmp_path)

    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )

    fake = Faker()
    email = fake.email(domain="tanker.io")

    phone_number = "+33639982233"

    provider_config = set_up_oidc(app, admin)
    oidc_id_token = get_id_token()
    subject = extract_subject(oidc_id_token)

    await server.enroll_user(
        identity,
        [
            PreverifiedEmailVerification(preverified_email=email),
            PreverifiedPhoneNumberVerification(preverified_phone_number=phone_number),
            PreverifiedOIDCVerification(
                subject=subject, provider_id=provider_config["id"]
            ),
        ],
    )

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    await phone_tanker.start(identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED

    verification_code = get_verification_code_email(app, email)
    await phone_tanker.verify_identity(EmailVerification(email, verification_code))
    assert phone_tanker.status == TankerStatus.READY

    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)

    await laptop_tanker.start(identity)
    assert laptop_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED

    verification_code = get_verification_code_sms(app, phone_number)
    await laptop_tanker.verify_identity(
        PhoneNumberVerification(phone_number, verification_code)
    )
    assert laptop_tanker.status == TankerStatus.READY

    tablet_path = tmp_path.joinpath("tablet")
    tablet_path.mkdir(exist_ok=True)
    tablet_tanker = create_tanker(app["id"], persistent_path=tablet_path)

    await tablet_tanker.start(identity)
    assert tablet_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED

    nonce = await tablet_tanker.create_oidc_nonce()
    await tablet_tanker.set_oidc_test_nonce(nonce)
    await tablet_tanker.verify_identity(OidcIdTokenVerification(oidc_id_token))
    assert tablet_tanker.status == TankerStatus.READY


@pytest.mark.asyncio
async def test_tanker_sdk_version(tmp_path: Path, app: Dict[str, str]) -> None:
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    sdk_version = tanker.sdk_version
    assert sdk_version


@pytest.mark.asyncio
async def test_start_new_account(tmp_path: Path, app: Dict[str, str]) -> None:
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    status = await tanker.start(identity)
    assert status == TankerStatus.IDENTITY_REGISTRATION_NEEDED
    key = await tanker.generate_verification_key()
    await tanker.register_identity(VerificationKeyVerification(key))
    assert tanker.status == TankerStatus.READY
    await tanker.stop()
    assert tanker.status == TankerStatus.STOPPED


@pytest.mark.asyncio
async def test_start_identity_incorrect_format(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    with pytest.raises(error.InvalidArgument):
        await tanker.start("bad identity")
    await tanker.stop()


@pytest.mark.asyncio
async def test_create_account_then_sign_in(tmp_path: Path, app: Dict[str, str]) -> None:
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    await tanker.start(identity)
    key = await tanker.generate_verification_key()
    await tanker.register_identity(VerificationKeyVerification(key))
    await tanker.stop()

    await tanker.start(identity)
    assert tanker.status == TankerStatus.READY
    await tanker.stop()


User = namedtuple("User", ["session", "public_identity", "private_identity"])


async def create_user_session(tmp_path: Path, app: Dict[str, str]) -> User:
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    private_identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
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
        chunk_size = 1024**2
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
        chunk_size = 1024**2
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
    async def test_encrypt_with_padding(
        self, tmp_path: Path, app: Dict[str, str]
    ) -> None:
        alice = await create_user_session(tmp_path, app)
        chunk_size = 1024**2
        message = bytearray(
            3 * chunk_size + 2
        )  # three big chunks plus a little something
        input_stream = InMemoryAsyncStream(message)
        async with await alice.session.encrypt_stream(
            input_stream, EncryptionOptions(padding_step=500)
        ) as encrypted_stream:
            encrypted_message = await encrypted_stream.read()
        assert len(encrypted_message) == 3 * 1024 * 1024 + 389
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
async def test_encrypt_decrypt_empty(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b""
    encrypted_data = await alice.session.encrypt(message)
    clear_data = await alice.session.decrypt(encrypted_data)
    assert clear_data == message
    await alice.session.stop()


# Encryption format v10 overhead
SIMPLE_ENCRYPTION_OVERHEAD = 49

SIMPLE_PADDED_ENCRYPTION_OVERHEAD = SIMPLE_ENCRYPTION_OVERHEAD + 1


@pytest.mark.asyncio
async def test_auto_padding_is_default(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b"my clear data is clear!"
    length_with_padme = 24
    encrypted_data = await alice.session.encrypt(message)
    assert len(encrypted_data) - SIMPLE_PADDED_ENCRYPTION_OVERHEAD == length_with_padme
    clear_data = await alice.session.decrypt(encrypted_data)
    assert clear_data == message
    await alice.session.stop()


@pytest.mark.asyncio
async def test_padding_opt_auto(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b"my clear data is clear!"
    length_with_padme = 24
    encrypted_data = await alice.session.encrypt(
        message, EncryptionOptions(padding_step=Padding.AUTO)
    )
    assert len(encrypted_data) - SIMPLE_PADDED_ENCRYPTION_OVERHEAD == length_with_padme
    clear_data = await alice.session.decrypt(encrypted_data)
    assert clear_data == message
    await alice.session.stop()


@pytest.mark.asyncio
async def test_padding_opt_disable(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b"I love you"
    encrypted_data = await alice.session.encrypt(
        message, EncryptionOptions(padding_step=Padding.OFF)
    )
    assert len(encrypted_data) == len(message) + SIMPLE_ENCRYPTION_OVERHEAD
    clear_data = await alice.session.decrypt(encrypted_data)
    assert clear_data == message
    await alice.session.stop()


@pytest.mark.asyncio
async def test_padding_opt_enable(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b"I love you"
    step = 13
    encrypted_data = await alice.session.encrypt(
        message, EncryptionOptions(padding_step=step)
    )
    assert (len(encrypted_data) - SIMPLE_PADDED_ENCRYPTION_OVERHEAD) % step == 0
    clear_data = await alice.session.decrypt(encrypted_data)
    assert clear_data == message
    await alice.session.stop()


def test_padding_opt_error(tmp_path: Path, app: Dict[str, str]) -> None:
    with pytest.raises(error.InvalidArgument):
        EncryptionOptions(padding_step=0)

    with pytest.raises(error.InvalidArgument):
        EncryptionOptions(padding_step=1)

    with pytest.raises(error.InvalidArgument):
        EncryptionOptions(padding_step=-1)

    with pytest.raises(error.InvalidArgument):
        EncryptionOptions(padding_step=2.42)  # type: ignore


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
    with pytest.raises(error.InvalidArgument):
        await alice.session.decrypt(encrypted)
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
    alice: User, group_id: str, members: List[User], non_members: List[User] = []
) -> None:
    message = b"Hi, guys"
    encrypted = await alice.session.encrypt(
        message, EncryptionOptions(share_with_groups=[group_id])
    )
    for m in members:
        decrypted = await m.session.decrypt(encrypted)
        assert decrypted == message
    for n in non_members:
        with pytest.raises(error.InvalidArgument):
            await n.session.decrypt(encrypted)


@pytest.mark.asyncio
async def test_create_group(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    bob = await create_user_session(tmp_path, app)
    charlie = await create_user_session(tmp_path, app)
    tom = await create_user_session(tmp_path, app)

    group_id = await alice.session.create_group(
        [bob.public_identity, charlie.public_identity, tom.public_identity]
    )
    await check_share_with_group_works(alice, group_id, [bob, charlie, tom])


@pytest.mark.asyncio
async def test_update_group(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    bob = await create_user_session(tmp_path, app)
    charlie = await create_user_session(tmp_path, app)
    tom = await create_user_session(tmp_path, app)

    group_id = await alice.session.create_group(
        [alice.public_identity, tom.public_identity, bob.public_identity]
    )
    await alice.session.update_group_members(
        group_id,
        users_to_add=[charlie.public_identity],
        users_to_remove=[tom.public_identity],
    )
    await check_share_with_group_works(alice, group_id, [bob, charlie], [tom])


@pytest.mark.asyncio
async def test_update_group_empty(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)

    group_id = await alice.session.create_group([alice.public_identity])
    with pytest.raises(error.InvalidArgument):
        await alice.session.update_group_members(
            group_id,
            users_to_add=[],
            users_to_remove=[],
        )


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
        share_with_users=[bob.public_identity],
        share_with_self=False,
    )
    async with await alice.session.create_encryption_session(options) as enc_session:
        encrypted = await enc_session.encrypt(message)

    with pytest.raises(error.InvalidArgument):
        await alice.session.decrypt(encrypted)

    decrypted = await bob.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()
    await bob.session.stop()


ENCRYPTION_SESSION_OVERHEAD = 57

ENCRYPTION_SESSION_PADDED_OVERHEAD = ENCRYPTION_SESSION_OVERHEAD + 1


@pytest.mark.asyncio
async def test_encryption_session_auto_padding_by_default(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b"my clear data is clear!"
    length_with_padme = 24
    enc_session = await alice.session.create_encryption_session()
    encrypted = await enc_session.encrypt(message)
    assert len(encrypted) - ENCRYPTION_SESSION_PADDED_OVERHEAD == length_with_padme

    decrypted = await alice.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()


@pytest.mark.asyncio
async def test_encryption_session_auto_padding(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b"my clear data is clear!"
    length_with_padme = 24
    enc_session = await alice.session.create_encryption_session(
        EncryptionOptions(padding_step=Padding.AUTO)
    )
    encrypted = await enc_session.encrypt(message)
    assert len(encrypted) - ENCRYPTION_SESSION_PADDED_OVERHEAD == length_with_padme

    decrypted = await alice.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()


@pytest.mark.asyncio
async def test_encryption_session_no_padding(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b"Ceci n'est pas un test"
    enc_session = await alice.session.create_encryption_session(
        EncryptionOptions(padding_step=Padding.OFF)
    )
    encrypted = await enc_session.encrypt(message)
    assert len(encrypted) - ENCRYPTION_SESSION_OVERHEAD == len(message)

    decrypted = await alice.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()


@pytest.mark.asyncio
async def test_encryption_session_padding_step(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice = await create_user_session(tmp_path, app)
    message = b"Ceci n'est pas un test"
    step = 13
    enc_session = await alice.session.create_encryption_session(
        EncryptionOptions(padding_step=step)
    )
    encrypted = await enc_session.encrypt(message)
    assert (len(encrypted) - ENCRYPTION_SESSION_PADDED_OVERHEAD) % step == 0

    decrypted = await alice.session.decrypt(encrypted)
    assert decrypted == message
    await alice.session.stop()


@pytest.mark.asyncio
async def test_encryption_session_streams(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    chunk_size = 1024**2
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
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], fake.email(domain="tanker.io")
    )
    await laptop_tanker.start(identity)
    await laptop_tanker.register_identity(PassphraseVerification(passphrase))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

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
async def test_must_verify_identity_on_second_device(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    passphrase = "my secure passphrase"
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(PassphraseVerification(passphrase))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)

    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    status = await phone_tanker.start(alice_identity)
    assert status == TankerStatus.IDENTITY_VERIFICATION_NEEDED


@pytest.mark.asyncio
async def test_using_verification_key_on_second_device(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    verification_key = await laptop_tanker.generate_verification_key()
    await laptop_tanker.register_identity(VerificationKeyVerification(verification_key))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)
    await phone_tanker.start(alice_identity)
    await phone_tanker.verify_identity(VerificationKeyVerification(verification_key))
    assert phone_tanker.status == TankerStatus.READY
    await laptop_tanker.stop()
    await phone_tanker.stop()


@pytest.mark.asyncio
async def test_invalid_verification_key(tmp_path: Path, app: Dict[str, str]) -> None:
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    verification_key = await laptop_tanker.generate_verification_key()
    await laptop_tanker.register_identity(VerificationKeyVerification(verification_key))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)
    await phone_tanker.start(alice_identity)

    with pytest.raises(error.InvalidVerification):
        await phone_tanker.verify_identity(VerificationKeyVerification("plop"))

    with pytest.raises(error.InvalidVerification):
        await phone_tanker.verify_identity(VerificationKeyVerification(""))

    key_json = base64.b64decode(verification_key.encode()).decode()
    key = json.loads(key_json)
    key[
        "privateSignatureKey"
    ] = "O85hg7XxxGWq3cQf4xQ/VXaTiAPcqWoUIGDvaLpZ+trNQkp+rNzZrLvIfhERwb33iUjV0sFiL5XqweVgqTdg6Q=="
    key_json = json.dumps(key)
    key = base64.b64encode(key_json.encode()).decode()

    with pytest.raises(error.InvalidVerification):
        await phone_tanker.verify_identity(VerificationKeyVerification(key))


def get_verification_code_email(app: Dict[str, str], email: str) -> str:
    return tankeradminsdk.get_verification_code_email(
        url=TEST_CONFIG["server"]["trustchaindUrl"],
        app_id=app["id"],
        verification_api_token=TEST_CONFIG["server"]["verificationApiToken"],
        email=email,
    )


def get_verification_code_sms(app: Dict[str, str], phone_number: str) -> str:
    return tankeradminsdk.get_verification_code_sms(
        url=TEST_CONFIG["server"]["trustchaindUrl"],
        app_id=app["id"],
        verification_api_token=TEST_CONFIG["server"]["verificationApiToken"],
        phone_number=phone_number,
    )


@pytest.mark.asyncio
async def test_email_verification(tmp_path: Path, app: Dict[str, str]) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    email = fake.email(domain="tanker.io")
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    verification_code = get_verification_code_email(app, email)
    await laptop_tanker.register_identity(EmailVerification(email, verification_code))
    assert len(verification_code) == 8

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    verification_code = get_verification_code_email(app, email)
    await phone_tanker.verify_identity(EmailVerification(email, verification_code))
    assert phone_tanker.status == TankerStatus.READY
    await laptop_tanker.stop()
    await phone_tanker.stop()


@pytest.mark.asyncio
async def test_sms_verification(tmp_path: Path, app: Dict[str, str]) -> None:
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    phone_number = "+33639982233"
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    verification_code = get_verification_code_sms(app, phone_number)
    await laptop_tanker.register_identity(
        PhoneNumberVerification(phone_number, verification_code)
    )
    assert len(verification_code) == 8

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    verification_code = get_verification_code_sms(app, phone_number)
    await phone_tanker.verify_identity(
        PhoneNumberVerification(phone_number, verification_code)
    )
    assert phone_tanker.status == TankerStatus.READY
    await laptop_tanker.stop()
    await phone_tanker.stop()


@pytest.mark.asyncio
async def test_bad_verification_code(tmp_path: Path, app: Dict[str, str]) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    email = fake.email(domain="tanker.io")
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)
    await laptop_tanker.start(alice_identity)
    verification_code = get_verification_code_email(app, email)
    await laptop_tanker.register_identity(EmailVerification(email, verification_code))
    await phone_tanker.start(alice_identity)
    with pytest.raises(error.InvalidVerification):
        await phone_tanker.verify_identity(EmailVerification(email, "12345678"))
    with pytest.raises(error.InvalidVerification):
        await phone_tanker.verify_identity(EmailVerification(email, "azerty"))
    with pytest.raises(error.InvalidArgument):
        await phone_tanker.verify_identity(EmailVerification(email, ""))
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


async def create_pre_user(tmp_path: Path, app: Dict[str, str]) -> PreUser:
    fake = Faker()
    bob_email = fake.email(domain="tanker.io")
    bob_provisional_identity = tankersdk_identity.create_provisional_identity(
        app["id"], "email", bob_email
    )
    bob_public_provisional_identity = tankersdk_identity.get_public_identity(
        bob_provisional_identity
    )
    bob = await create_user_session(tmp_path, app)
    pre_bob = PreUser(
        session=bob.session,
        public_identity=bob.public_identity,
        private_identity=bob.private_identity,
        public_provisional_identity=bob_public_provisional_identity,
        private_provisional_identity=bob_provisional_identity,
        email=bob_email,
        verification_code=get_verification_code_email(app, bob_email),
    )
    return pre_bob


async def set_up_preshare(tmp_path: Path, app: Dict[str, str]) -> Tuple[User, PreUser]:
    alice = await create_user_session(tmp_path, app)
    return alice, await create_pre_user(tmp_path, app)


@pytest.mark.asyncio
async def test_cannot_decrypt_if_provisional_identity_not_attached(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice, bob = await set_up_preshare(tmp_path, app)
    message = b"I love you"
    encrypted = await alice.session.encrypt(
        message, EncryptionOptions(share_with_users=[bob.public_provisional_identity])
    )
    with pytest.raises(error.InvalidArgument):
        await bob.session.decrypt(encrypted)


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

    verification_code = get_verification_code_email(app, bob.email)
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
async def test_already_attached_identity_by_someone_else(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice, bob = await set_up_preshare(tmp_path, app)

    attach_result = await bob.session.attach_provisional_identity(
        bob.private_provisional_identity
    )
    assert attach_result.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED

    verification_code = get_verification_code_email(app, bob.email)
    await bob.session.verify_provisional_identity(
        EmailVerification(bob.email, verification_code)
    )
    attach_result2 = await alice.session.attach_provisional_identity(
        bob.private_provisional_identity
    )
    assert attach_result2.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    verification_code2 = get_verification_code_email(app, bob.email)
    with pytest.raises(error.IdentityAlreadyAttached):
        await alice.session.verify_provisional_identity(
            EmailVerification(bob.email, verification_code2)
        )


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
    with pytest.raises(error.PreconditionFailed):
        await bob.session.verify_identity(EmailVerification(bob.email, "badCode"))


@pytest.mark.asyncio
async def test_update_verification_passphrase(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    old_passphrase = "plop"
    new_passphrase = "zzzz"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(PassphraseVerification(old_passphrase))

    await laptop_tanker.set_verification_method(PassphraseVerification(new_passphrase))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)
    await phone_tanker.start(alice_identity)

    # Old passphrase should not work
    with pytest.raises(error.InvalidVerification):
        await phone_tanker.verify_identity(PassphraseVerification(old_passphrase))

    # But new passphrase should
    await phone_tanker.verify_identity(PassphraseVerification(new_passphrase))
    assert phone_tanker.status == TankerStatus.READY


@pytest.mark.asyncio
async def test_register_e2e_passphrase(tmp_path: Path, app: Dict[str, str]) -> None:
    passphrase = "portocaval anastomosis"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(E2ePassphraseVerification(passphrase))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)
    await phone_tanker.start(alice_identity)

    await phone_tanker.verify_identity(E2ePassphraseVerification(passphrase))
    assert phone_tanker.status == TankerStatus.READY


@pytest.mark.asyncio
async def test_update_e2e_passphrase(tmp_path: Path, app: Dict[str, str]) -> None:
    old_passphrase = "alkalosis"
    new_passphrase = "acidosis"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(E2ePassphraseVerification(old_passphrase))

    await laptop_tanker.set_verification_method(
        E2ePassphraseVerification(new_passphrase)
    )

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)
    await phone_tanker.start(alice_identity)

    # Old passphrase should not work
    with pytest.raises(error.InvalidVerification):
        await phone_tanker.verify_identity(E2ePassphraseVerification(old_passphrase))

    # But new passphrase should
    await phone_tanker.verify_identity(E2ePassphraseVerification(new_passphrase))
    assert phone_tanker.status == TankerStatus.READY


@pytest.mark.asyncio
async def test_switch_to_e2e_passphrase(tmp_path: Path, app: Dict[str, str]) -> None:
    old_passphrase = "alkalosis"
    new_passphrase = "acidosis"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(PassphraseVerification(old_passphrase))

    options = VerificationOptions(allow_e2e_method_switch=True)
    await laptop_tanker.set_verification_method(
        E2ePassphraseVerification(new_passphrase), options
    )

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)
    await phone_tanker.start(alice_identity)

    # Old passphrase should not work
    with pytest.raises(error.InvalidVerification):
        await phone_tanker.verify_identity(E2ePassphraseVerification(old_passphrase))

    # But new passphrase should
    await phone_tanker.verify_identity(E2ePassphraseVerification(new_passphrase))
    assert phone_tanker.status == TankerStatus.READY


@pytest.mark.asyncio
async def test_switch_from_e2e_passphrase(tmp_path: Path, app: Dict[str, str]) -> None:
    old_passphrase = "alkalosis"
    new_passphrase = "acidosis"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(E2ePassphraseVerification(old_passphrase))

    options = VerificationOptions(allow_e2e_method_switch=True)
    await laptop_tanker.set_verification_method(
        PassphraseVerification(new_passphrase), options
    )

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)
    await phone_tanker.start(alice_identity)

    # Old passphrase should not work
    with pytest.raises(error.InvalidVerification):
        await phone_tanker.verify_identity(PassphraseVerification(old_passphrase))

    # But new passphrase should
    await phone_tanker.verify_identity(PassphraseVerification(new_passphrase))
    assert phone_tanker.status == TankerStatus.READY


@pytest.mark.asyncio
async def test_cannot_switch_to_e2e_passphrase_without_e2e_switch_flag(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    old_passphrase = "alkalosis"
    new_passphrase = "acidosis"
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(PassphraseVerification(old_passphrase))

    with pytest.raises(error.InvalidArgument):
        await laptop_tanker.set_verification_method(
            E2ePassphraseVerification(new_passphrase)
        )


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
async def test_add_group_members_with_prov_id(
    tmp_path: Path, app: Dict[str, str]
) -> None:
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
async def test_remove_group_members_with_prov_id(
    tmp_path: Path, app: Dict[str, str]
) -> None:
    alice, bob = await set_up_preshare(tmp_path, app)
    message = b"Hi, this is for a group"
    group_id = await alice.session.create_group(
        [alice.public_identity, bob.public_provisional_identity]
    )

    await bob.session.attach_provisional_identity(bob.private_provisional_identity)
    await bob.session.verify_provisional_identity(
        EmailVerification(bob.email, bob.verification_code)
    )

    encrypted = await alice.session.encrypt(
        message, EncryptionOptions(share_with_groups=[group_id])
    )
    await alice.session.update_group_members(
        group_id, users_to_remove=[bob.public_identity]
    )
    with pytest.raises(error.InvalidArgument):
        await bob.session.decrypt(encrypted)


@pytest.mark.asyncio
async def test_user_not_found(tmp_path: Path, app: Dict[str, str]) -> None:
    user_id = encode("*" * 32)
    identity_obj = {"app_id": app["id"], "target": "user", "value": user_id}
    identity = encode(json.dumps(identity_obj))
    alice = await create_user_session(tmp_path, app)
    with pytest.raises(error.InvalidArgument):
        await alice.session.create_group([identity])


@pytest.mark.asyncio
async def test_decrypt_invalid_argument(tmp_path: Path, app: Dict[str, str]) -> None:
    alice = await create_user_session(tmp_path, app)
    with pytest.raises(error.InvalidArgument):
        await alice.session.decrypt(b"zz")


@pytest.mark.asyncio
async def test_recipient_not_found(tmp_path: Path, app: Dict[str, str]) -> None:
    group_id = encode("*" * 32)
    alice = await create_user_session(tmp_path, app)
    with pytest.raises(error.InvalidArgument):
        await alice.session.encrypt(
            b"zz", EncryptionOptions(share_with_groups=[group_id])
        )


@pytest.mark.asyncio
async def test_group_not_found(tmp_path: Path, app: Dict[str, str]) -> None:
    group_id = encode("*" * 32)
    alice = await create_user_session(tmp_path, app)
    with pytest.raises(error.InvalidArgument):
        await alice.session.update_group_members(
            group_id, users_to_add=[alice.public_identity]
        )


@pytest.mark.asyncio
async def test_get_verification_methods(tmp_path: Path, app: Dict[str, str]) -> None:
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    fake = Faker()
    email = fake.email(domain="tanker.io")
    phone_number = "+33639982233"
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    await tanker.start(identity)
    passphrase = "my passphrase"
    await tanker.register_identity(PassphraseVerification(passphrase))
    await tanker.stop()

    await tanker.start(identity)
    methods = await tanker.get_verification_methods()
    assert len(methods) == 1
    (actual_method,) = methods
    assert actual_method.method_type == VerificationMethodType.PASSPHRASE

    verification_code = get_verification_code_email(app, email)
    await tanker.set_verification_method(EmailVerification(email, verification_code))

    methods = await tanker.get_verification_methods()
    assert len(methods) == 2
    email_methods = [x for x in methods if isinstance(x, EmailVerificationMethod)]
    assert len(email_methods) == 1
    (email_method,) = email_methods
    assert email_method.email == email

    verification_code = get_verification_code_sms(app, phone_number)
    await tanker.set_verification_method(
        PhoneNumberVerification(phone_number, verification_code)
    )

    methods = await tanker.get_verification_methods()
    assert len(methods) == 3
    phone_number_methods = [
        x for x in methods if isinstance(x, PhoneNumberVerificationMethod)
    ]
    assert len(phone_number_methods) == 1
    (phone_number_method,) = phone_number_methods
    assert phone_number_method.phone_number == phone_number

    options = VerificationOptions(allow_e2e_method_switch=True)
    await tanker.set_verification_method(E2ePassphraseVerification(passphrase), options)

    methods = await tanker.get_verification_methods()
    assert len(methods) == 1
    (e2e_passphrase_method,) = methods
    assert e2e_passphrase_method.method_type == VerificationMethodType.E2E_PASSPHRASE


def get_id_token(user: str = "martine") -> str:
    oidc_test_config = TEST_CONFIG["oidc"]
    oidc_client_id = oidc_test_config["clientId"]
    oidc_client_secret = oidc_test_config["clientSecret"]

    test_users = oidc_test_config["users"]
    assert user in test_users
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
    return cast(str, oidc_id_token)


def extract_subject(id_token: str) -> str:
    jwt_body = id_token.split(".")[1]
    # Add padding because urlsafe_b64decode requires it
    body = base64.urlsafe_b64decode(jwt_body + "==")
    return cast(str, json.loads(body)["sub"])


def set_up_oidc(app: Dict[str, str], admin: Admin) -> Dict[str, str]:
    oidc_test_config = TEST_CONFIG["oidc"]

    oidc_client_id = oidc_test_config["clientId"]
    oidc_provider = oidc_test_config["provider"]
    oidc_issuer = oidc_test_config["issuer"]
    admin.update_app(
        app["id"],
        oidc_providers=[
            AppOidcProvider(
                client_id=oidc_client_id, display_name=oidc_provider, issuer=oidc_issuer
            )
        ],
    )

    return cast(Dict[str, str], admin.get_app(app["id"])["oidc_providers"][0])


def set_up_fake_oidc(app: Dict[str, str], admin: Admin) -> Dict[str, str]:
    fake_oidc_issuer_url = TEST_CONFIG["oidc"]["fakeOidcIssuerUrl"]

    oidc_issuer = fake_oidc_issuer_url
    oidc_client_id = "tanker"
    oidc_provider = "fake-oidc"
    admin.update_app(
        app["id"],
        oidc_providers=[
            AppOidcProvider(
                client_id=oidc_client_id, display_name=oidc_provider, issuer=oidc_issuer
            )
        ],
    )

    return cast(Dict[str, str], admin.get_app(app["id"])["oidc_providers"][0])


@pytest.mark.asyncio
async def test_oidc_verification(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    _ = set_up_oidc(app, admin)
    oidc_id_token = get_id_token()

    phone_path = tmp_path / "phone"
    phone_path.mkdir(exist_ok=True)
    martine_phone = create_tanker(app["id"], persistent_path=phone_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )

    nonce = await martine_phone.create_oidc_nonce()
    await martine_phone.start(identity)
    await martine_phone.set_oidc_test_nonce(nonce)
    await martine_phone.register_identity(OidcIdTokenVerification(oidc_id_token))
    await martine_phone.stop()

    laptop_path = tmp_path / "laptop"
    laptop_path.mkdir(exist_ok=True)
    martine_laptop = create_tanker(app["id"], persistent_path=laptop_path)
    await martine_laptop.start(identity)

    assert martine_laptop.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    nonce = await martine_laptop.create_oidc_nonce()
    await martine_laptop.set_oidc_test_nonce(nonce)
    await martine_laptop.verify_identity(OidcIdTokenVerification(oidc_id_token))
    assert martine_laptop.status == TankerStatus.READY

    actual_methods = await martine_laptop.get_verification_methods()
    (actual_method,) = actual_methods
    assert actual_method.method_type == VerificationMethodType.OIDC_ID_TOKEN

    await martine_laptop.stop()


@pytest.mark.asyncio
async def test_oidc_authorization_code_verification(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    provider_config = set_up_fake_oidc(app, admin)
    provider_id = provider_config["id"]
    subject_cookie = "fake_oidc_subject=martine"

    phone_path = tmp_path / "phone"
    phone_path.mkdir(exist_ok=True)
    martine_phone = create_tanker(app["id"], persistent_path=phone_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )

    await martine_phone.start(identity)

    verification1 = await authenticate_with_idp(
        martine_phone, provider_id, subject_cookie
    )
    verification2 = await authenticate_with_idp(
        martine_phone, provider_id, subject_cookie
    )
    await martine_phone.register_identity(verification1)
    await martine_phone.stop()

    laptop_path = tmp_path / "laptop"
    laptop_path.mkdir(exist_ok=True)
    martine_laptop = create_tanker(app["id"], persistent_path=laptop_path)
    await martine_laptop.start(identity)

    assert martine_laptop.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    await martine_laptop.verify_identity(verification2)
    assert martine_laptop.status == TankerStatus.READY

    actual_methods = await martine_laptop.get_verification_methods()
    (actual_method,) = actual_methods
    assert actual_method.method_type == VerificationMethodType.OIDC_ID_TOKEN

    await martine_laptop.stop()

    tablet_path = tmp_path / "tablet"
    tablet_path.mkdir(exist_ok=True)
    martine_tablet = create_tanker(app["id"], persistent_path=tablet_path)
    await martine_tablet.start(identity)
    verification3 = await authenticate_with_idp(
        martine_tablet, provider_id, "fake_oidc_subject=not_martine"
    )

    assert martine_tablet.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    with pytest.raises(error.InvalidVerification):
        await martine_tablet.verify_identity(verification3)
    await martine_tablet.stop()


@pytest.mark.asyncio
async def test_register_fails_with_preverified_email(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    fake = Faker()
    email = fake.email(domain="tanker.io")

    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    await tanker.start(identity)

    with pytest.raises(error.InvalidArgument):
        await tanker.register_identity(
            PreverifiedEmailVerification(preverified_email=email)
        )


@pytest.mark.asyncio
async def test_register_fails_with_preverified_phone_number(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    phone_number = "+33639982233"

    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    await tanker.start(identity)

    with pytest.raises(error.InvalidArgument):
        await tanker.register_identity(
            PreverifiedPhoneNumberVerification(preverified_phone_number=phone_number)
        )


@pytest.mark.asyncio
async def test_register_fails_with_preverified_oidc(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    provider_config = set_up_oidc(app, admin)

    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    await tanker.start(identity)

    with pytest.raises(error.InvalidArgument):
        await tanker.register_identity(
            PreverifiedOIDCVerification(
                subject="subject",
                provider_id=provider_config["id"],
            )
        )


@pytest.mark.asyncio
async def test_verify_fails_with_preverified_email(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    email = fake.email(domain="tanker.io")
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    verification_code = get_verification_code_email(app, email)
    await laptop_tanker.register_identity(EmailVerification(email, verification_code))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    with pytest.raises(error.InvalidArgument):
        await phone_tanker.verify_identity(
            PreverifiedEmailVerification(preverified_email=email)
        )


@pytest.mark.asyncio
async def test_verify_fails_with_preverified_phone_number(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    phone_number = "+33639982233"
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    verification_code = get_verification_code_sms(app, phone_number)
    await laptop_tanker.register_identity(
        PhoneNumberVerification(phone_number, verification_code)
    )

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    with pytest.raises(error.InvalidArgument):
        await phone_tanker.verify_identity(
            PreverifiedPhoneNumberVerification(preverified_phone_number=phone_number)
        )


@pytest.mark.asyncio
async def test_verify_fails_with_preverified_oidc(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    provider_config = set_up_oidc(app, admin)
    oidc_id_token = get_id_token()

    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    nonce = await laptop_tanker.create_oidc_nonce()
    await laptop_tanker.set_oidc_test_nonce(nonce)
    await laptop_tanker.register_identity(OidcIdTokenVerification(oidc_id_token))

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED
    with pytest.raises(error.InvalidArgument):
        await phone_tanker.verify_identity(
            PreverifiedOIDCVerification(
                subject=extract_subject(oidc_id_token),
                provider_id=provider_config["id"],
            )
        )


@pytest.mark.asyncio
async def test_set_verification_method_with_preverified_email(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    fake = Faker()
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    passphrase = "The cake is not a lie"
    email = fake.email(domain="tanker.io")
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(PassphraseVerification(passphrase))

    await laptop_tanker.set_verification_method(PreverifiedEmailVerification(email))

    methods = set(await laptop_tanker.get_verification_methods())
    assert len(methods) == 2
    preverified_email_methods = [
        x for x in methods if isinstance(x, PreverifiedEmailVerificationMethod)
    ]
    (preverified_email_method,) = preverified_email_methods
    assert preverified_email_method.preverified_email == email

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED

    verification_code = get_verification_code_email(app, email)
    await phone_tanker.verify_identity(EmailVerification(email, verification_code))
    assert phone_tanker.status == TankerStatus.READY

    methods = set(await laptop_tanker.get_verification_methods())
    email_methods = [x for x in methods if isinstance(x, EmailVerificationMethod)]
    (email_method,) = email_methods
    assert email_method.email == email

    await laptop_tanker.stop()
    await phone_tanker.stop()


@pytest.mark.asyncio
async def test_set_verification_method_with_preverified_phone_number(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    passphrase = "The chocolate is in the kitchen"
    phone_number = "+33639982233"
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )
    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(PassphraseVerification(passphrase))

    await laptop_tanker.set_verification_method(
        PreverifiedPhoneNumberVerification(phone_number)
    )

    methods = set(await laptop_tanker.get_verification_methods())
    assert len(methods) == 2
    preverified_phone_number_methods = [
        x for x in methods if isinstance(x, PreverifiedPhoneNumberVerificationMethod)
    ]
    (preverified_phone_number_method,) = preverified_phone_number_methods
    assert preverified_phone_number_method.preverified_phone_number == phone_number

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED

    verification_code = get_verification_code_sms(app, phone_number)
    await phone_tanker.verify_identity(
        PhoneNumberVerification(phone_number, verification_code)
    )
    assert phone_tanker.status == TankerStatus.READY

    methods = set(await laptop_tanker.get_verification_methods())
    phone_number_methods = [
        x for x in methods if isinstance(x, PhoneNumberVerificationMethod)
    ]
    (phone_number_method,) = phone_number_methods
    assert phone_number_method.phone_number == phone_number

    await laptop_tanker.stop()
    await phone_tanker.stop()


@pytest.mark.asyncio
async def test_set_verification_method_with_oidc(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    laptop_path = tmp_path.joinpath("laptop")
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    passphrase = "The cake is not a lie"
    alice_identity = tankersdk_identity.create_identity(
        app["id"],
        app["secret"],
        str(uuid.uuid4()),
    )

    provider_config = set_up_oidc(app, admin)
    oidc_id_token = get_id_token()
    subject = extract_subject(oidc_id_token)

    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(PassphraseVerification(passphrase))

    await laptop_tanker.set_verification_method(
        PreverifiedOIDCVerification(subject=subject, provider_id=provider_config["id"])
    )

    methods = set(await laptop_tanker.get_verification_methods())
    assert len(methods) == 2
    oidc_methods = [x for x in methods if isinstance(x, OidcIdTokenVerificationMethod)]
    assert oidc_methods[0].provider_id == provider_config["id"]
    assert oidc_methods[0].provider_display_name == provider_config["display_name"]

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED

    nonce = await phone_tanker.create_oidc_nonce()
    await phone_tanker.set_oidc_test_nonce(nonce)
    await phone_tanker.verify_identity(OidcIdTokenVerification(oidc_id_token))
    assert phone_tanker.status == TankerStatus.READY

    await laptop_tanker.stop()
    await phone_tanker.stop()


@pytest.mark.asyncio
async def test_set_oidc_authorization_code_verification(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    provider_config = set_up_fake_oidc(app, admin)
    provider_id = provider_config["id"]
    subject_cookie = "fake_oidc_subject=alice"
    passphrase = "The cake is not a lie"

    laptop_path = tmp_path / "laptop"
    laptop_path.mkdir(exist_ok=True)
    laptop_tanker = create_tanker(app["id"], persistent_path=laptop_path)
    alice_identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )

    await laptop_tanker.start(alice_identity)
    await laptop_tanker.register_identity(PassphraseVerification(passphrase))

    verification2 = await authenticate_with_idp(
        laptop_tanker, provider_id, subject_cookie
    )
    await laptop_tanker.set_verification_method(verification2)

    methods = set(await laptop_tanker.get_verification_methods())
    assert len(methods) == 2
    oidc_methods = [x for x in methods if isinstance(x, OidcIdTokenVerificationMethod)]
    assert oidc_methods[0].provider_id == provider_config["id"]
    assert oidc_methods[0].provider_display_name == provider_config["display_name"]

    phone_path = tmp_path.joinpath("phone")
    phone_path.mkdir(exist_ok=True)
    phone_tanker = create_tanker(app["id"], persistent_path=phone_path)

    await phone_tanker.start(alice_identity)
    assert phone_tanker.status == TankerStatus.IDENTITY_VERIFICATION_NEEDED

    verification2 = await authenticate_with_idp(
        laptop_tanker, provider_id, subject_cookie
    )
    await phone_tanker.verify_identity(verification2)
    assert phone_tanker.status == TankerStatus.READY

    await laptop_tanker.stop()
    await phone_tanker.stop()


def test_prehash_password_empty() -> None:
    with pytest.raises(error.InvalidArgument):
        tankersdk.prehash_password("")


def test_prehash_password_vector_1() -> None:
    input = "super secretive password"
    expected = "UYNRgDLSClFWKsJ7dl9uPJjhpIoEzadksv/Mf44gSHI="
    assert tankersdk.prehash_password(input) == expected


def test_prehash_password_vector_2() -> None:
    input = "test éå 한국어 😃"
    expected = "Pkn/pjub2uwkBDpt2HUieWOXP5xLn0Zlen16ID4C7jI="
    assert tankersdk.prehash_password(input) == expected


def check_session_token(
    app_id: str,
    public_identity: str,
    session_token: str,
    method: str,
    value: str = "",
) -> str:
    url = TEST_CONFIG["server"]["trustchaindUrl"] + "/verification/session-token"
    allowed_method = {"type": method}
    if method in ("email", "phone_number"):
        allowed_method[method] = value
    allowed_methods = [allowed_method]

    response = requests.post(
        url,
        headers={"content-type": "application/json"},
        json={
            "app_id": app_id,
            "auth_token": TEST_CONFIG["server"]["verificationApiToken"],
            "public_identity": public_identity,
            "session_token": session_token,
            "allowed_methods": allowed_methods,
        },
    )
    response.raise_for_status()
    return response.json()["verification_method"]  # type: ignore


@pytest.mark.asyncio
async def test_get_session_token_with_register_identity(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    passphrase = "50lbs bags of white rocks"
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    await tanker.start(identity)

    options = VerificationOptions(with_session_token=True)
    token = await tanker.register_identity(PassphraseVerification(passphrase), options)
    assert token

    expected_method = "passphrase"
    public_identity = tankersdk_identity.get_public_identity(identity)
    actual_method = check_session_token(
        app["id"], public_identity, token, expected_method
    )
    assert expected_method == actual_method
    await tanker.stop()


@pytest.mark.asyncio
async def test_get_session_token_with_verify_identity(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    await tanker.start(identity)

    verif = PassphraseVerification("What the stones are for")
    options = VerificationOptions(with_session_token=True)
    await tanker.register_identity(verif)
    token = await tanker.verify_identity(verif, options)
    assert token

    expected_method = "passphrase"
    public_identity = tankersdk_identity.get_public_identity(identity)
    actual_method = check_session_token(
        app["id"], public_identity, token, expected_method
    )
    assert expected_method == actual_method
    await tanker.stop()


@pytest.mark.asyncio
async def test_get_session_token_with_set_verification_method_with_passphrase(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    await tanker.start(identity)

    verif = PassphraseVerification("Still carrying the rock")
    options = VerificationOptions(with_session_token=True)
    await tanker.register_identity(verif)
    token = await tanker.set_verification_method(verif, options)
    assert token

    expected_method = "passphrase"
    public_identity = tankersdk_identity.get_public_identity(identity)
    actual_method = check_session_token(
        app["id"], public_identity, token, expected_method
    )
    assert expected_method == actual_method
    await tanker.stop()


@pytest.mark.asyncio
async def test_get_session_token_with_set_verification_method_with_email(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    await tanker.start(identity)
    verif_passphrase = PassphraseVerification("Still carrying the rock")
    await tanker.register_identity(verif_passphrase)

    fake = Faker()
    email = fake.email(domain="tanker.io")
    verification_code = get_verification_code_email(app, email)
    verif_email = EmailVerification(email, verification_code)
    options = VerificationOptions(with_session_token=True)

    token = await tanker.set_verification_method(verif_email, options)
    assert token

    expected_method = "email"
    public_identity = tankersdk_identity.get_public_identity(identity)
    actual_method = check_session_token(
        app["id"], public_identity, token, expected_method, email
    )
    assert expected_method == actual_method
    await tanker.stop()


@pytest.mark.asyncio
async def test_get_session_token_with_set_verification_method_with_phone_number(
    tmp_path: Path, app: Dict[str, str], admin: Admin
) -> None:
    tanker = create_tanker(app["id"], persistent_path=tmp_path)
    identity = tankersdk_identity.create_identity(
        app["id"], app["secret"], str(uuid.uuid4())
    )
    await tanker.start(identity)
    verif_passphrase = PassphraseVerification("Still carrying the rock")
    await tanker.register_identity(verif_passphrase)

    phone_number = "+33639982234"
    verification_code = get_verification_code_sms(app, phone_number)
    verif_phone_number = PhoneNumberVerification(phone_number, verification_code)
    options = VerificationOptions(with_session_token=True)

    token = await tanker.set_verification_method(verif_phone_number, options)
    assert token

    expected_method = "phone_number"
    public_identity = tankersdk_identity.get_public_identity(identity)
    actual_method = check_session_token(
        app["id"],
        public_identity,
        token,
        expected_method,
        phone_number,
    )
    assert expected_method == actual_method
    await tanker.stop()
