import asyncio
import os
import warnings
import weakref
from enum import Enum
from typing import Any, Callable, List, Optional, cast

import typing_extensions
from _tanker import ffi
from _tanker import lib as tankerlib

from .error import Error as TankerError
from .ffi_helpers import CCharList, CData, FFIHelpers, OptionalStrList
from .version import __version__

ffihelpers = FFIHelpers(ffi, tankerlib)


@ffi.def_extern()  # type: ignore
def log_handler(record: CData) -> None:
    if os.environ.get("TANKER_SDK_DEBUG"):
        #  We can't assume that print() on Windows knows how to handle non-ASCII characters
        #  (it depends on a lot of things)
        #  So to be safe we check if the message from Native is readable in ASCII, and
        #  if this fails we print `repr(message)` so that no information is lost.
        message_bytes = ffihelpers.c_string_to_bytes(record.message)
        category = ffihelpers.c_string_to_str(record.category)
        try:
            message = message_bytes.decode("ascii")
        except UnicodeDecodeError:
            message = repr(message_bytes)
        print(category, message, sep=": ")


tankerlib.tanker_set_log_handler(tankerlib.log_handler)


@ffi.def_extern()  # type: ignore
def revoke_callback(args: CData, data: CData) -> None:
    tanker_instance = ffi.from_handle(data)()  # data is a weakref.ref
    if tanker_instance and tanker_instance.on_revoked:
        tanker_instance.on_revoked()


class Status(Enum):
    """Represent the status of a Tanker session"""

    STOPPED = 0
    READY = 1
    IDENTITY_REGISTRATION_NEEDED = 2
    IDENTITY_VERIFICATION_NEEDED = 3


class VerificationMethodType(Enum):
    """Types of available methods for identity verification"""

    EMAIL = 1
    PASSPHRASE = 2
    VERIFICATION_KEY = 3
    OIDC_ID_TOKEN = 4
    PHONE_NUMBER = 5
    PREVERIFIED_EMAIL = 6
    PREVERIFIED_PHONE_NUMBER = 7


class Verification:
    # Note: we want every subclass to have a 'method_type' attribute
    # of type VerificationMethodType, but there's no "good"
    # value to use here except None
    method_type: VerificationMethodType = None  # type: ignore


class VerificationOptions:
    def __init__(self, with_session_token: bool):
        self.with_session_token = with_session_token


class EmailVerification(Verification):
    method_type = VerificationMethodType.EMAIL

    def __init__(self, email: str, verification_code: str):
        self.email = email
        self.verification_code = verification_code


class PhoneNumberVerification(Verification):
    method_type = VerificationMethodType.PHONE_NUMBER

    def __init__(self, phone_number: str, verification_code: str):
        self.phone_number = phone_number
        self.verification_code = verification_code


class OidcIdTokenVerification(Verification):
    method_type = VerificationMethodType.OIDC_ID_TOKEN

    def __init__(self, oidc_id_token: str):
        self.oidc_id_token = oidc_id_token


class PassphraseVerification(Verification):
    method_type = VerificationMethodType.PASSPHRASE

    def __init__(self, passphrase: str):
        self.passphrase = passphrase


class VerificationKeyVerification(Verification):
    method_type = VerificationMethodType.VERIFICATION_KEY

    def __init__(self, verification_key: str):
        self.verification_key = verification_key


class PreverifiedEmailVerification(Verification):
    method_type = VerificationMethodType.PREVERIFIED_EMAIL

    def __init__(self, preverified_email: str):
        self.preverified_email = preverified_email


class PreverifiedPhoneNumberVerification(Verification):
    method_type = VerificationMethodType.PREVERIFIED_PHONE_NUMBER

    def __init__(self, preverified_phone_number: str):
        self.preverified_phone_number = preverified_phone_number


class VerificationMethod:
    # Note: we want every subclass to have a 'mehod_type' attribute
    # of type VerificationMethodType, but there's no "good"
    # value to use here except None
    method_type: VerificationMethodType = None  # type: ignore


class EmailVerificationMethod(VerificationMethod):
    method_type = VerificationMethodType.EMAIL

    def __init__(self, email: str):
        self.email = email


class PhoneNumberVerificationMethod(VerificationMethod):
    method_type = VerificationMethodType.PHONE_NUMBER

    def __init__(self, phone_number: str):
        self.phone_number = phone_number


class OidcIdTokenVerificationMethod(VerificationMethod):
    method_type = VerificationMethodType.OIDC_ID_TOKEN


class PassphraseVerificationMethod(VerificationMethod):
    method_type = VerificationMethodType.PASSPHRASE


class VerificationKeyVerificationMethod(VerificationMethod):
    method_type = VerificationMethodType.VERIFICATION_KEY


class PreverifiedEmailVerificationMethod(VerificationMethod):
    method_type = VerificationMethodType.PREVERIFIED_EMAIL

    def __init__(self, preverified_email: str):
        self.preverified_email = preverified_email


class PreverifiedPhoneNumberVerificationMethod(VerificationMethod):
    method_type = VerificationMethodType.PREVERIFIED_PHONE_NUMBER

    def __init__(self, preverified_phone_number: str):
        self.preverified_phone_number = preverified_phone_number


def verification_method_from_c(c_verification_method: CData) -> VerificationMethod:
    method_type = VerificationMethodType(c_verification_method.verification_method_type)
    res: Optional[VerificationMethod] = None
    if method_type == VerificationMethodType.EMAIL:
        c_email = c_verification_method.value
        res = EmailVerificationMethod(ffihelpers.c_string_to_str(c_email))
    elif method_type == VerificationMethodType.PASSPHRASE:
        res = PassphraseVerificationMethod()
    elif method_type == VerificationMethodType.VERIFICATION_KEY:
        res = VerificationKeyVerificationMethod()
    elif method_type == VerificationMethodType.OIDC_ID_TOKEN:
        res = OidcIdTokenVerificationMethod()
    elif method_type == VerificationMethodType.PHONE_NUMBER:
        c_phone_number = c_verification_method.value
        res = PhoneNumberVerificationMethod(ffihelpers.c_string_to_str(c_phone_number))
    elif method_type == VerificationMethodType.PREVERIFIED_EMAIL:
        c_preverified_email = c_verification_method.value
        res = PreverifiedEmailVerificationMethod(
            ffihelpers.c_string_to_str(c_preverified_email)
        )
    elif method_type == VerificationMethodType.PREVERIFIED_PHONE_NUMBER:
        c_preverified_phone_number = c_verification_method.value
        res = PreverifiedPhoneNumberVerificationMethod(
            ffihelpers.c_string_to_str(c_preverified_phone_number)
        )
    assert (
        res
    ), f"Could not convert C verification method to python: unknown type: {type}"
    return res


RevokeFunc = Callable[[], None]


class AttachResult:
    """Represent the result of a call to `attach_provisional_identity`

    :ivar status:  An instance of :py:class:`Status` enum

    :ivar verification_method: An instance of :py:class:`VerificationMethod`,
                               if status is  `IDENTITY_VERIFICATION_NEEDED`
    """

    def __init__(self, status: Status):
        self.status = status

        self.verification_method: Optional[VerificationMethod] = None


class EncryptionOptions:
    """Represent encryption options"""

    def __init__(
        self,
        *,
        share_with_users: Optional[List[str]] = None,
        share_with_groups: Optional[List[str]] = None,
        share_with_self: bool = True,
    ):
        self.share_with_users = share_with_users
        self.share_with_groups = share_with_groups
        self.share_with_self = share_with_self


class CEncryptionOptions:
    """Wraps the tanker_encrypt_options_t C type"""

    def __init__(
        self,
        *,
        share_with_users: OptionalStrList = None,
        share_with_groups: OptionalStrList = None,
        share_with_self: bool = True,
    ) -> None:
        self.user_list = CCharList(share_with_users, ffi, tankerlib)
        self.group_list = CCharList(share_with_groups, ffi, tankerlib)

        self._c_data = ffi.new(
            "tanker_encrypt_options_t *",
            {
                "version": 3,
                "share_with_users": self.user_list.data,
                "nb_users": self.user_list.size,
                "share_with_groups": self.group_list.data,
                "nb_groups": self.group_list.size,
                "share_with_self": share_with_self,
            },
        )

    def get(self) -> CData:
        return self._c_data


class SharingOptions:
    """Represent sharing options"""

    def __init__(
        self,
        *,
        share_with_users: Optional[List[str]] = None,
        share_with_groups: Optional[List[str]] = None,
    ):
        self.share_with_users = share_with_users
        self.share_with_groups = share_with_groups


class CSharingOptions:
    """Wraps the tanker_sharing_options_t C type"""

    def __init__(
        self,
        *,
        share_with_users: OptionalStrList,
        share_with_groups: OptionalStrList,
    ) -> None:
        self.user_list = CCharList(share_with_users, ffi, tankerlib)
        self.group_list = CCharList(share_with_groups, ffi, tankerlib)

        self._c_data = ffi.new(
            "tanker_sharing_options_t *",
            {
                "version": 1,
                "share_with_users": self.user_list.data,
                "nb_users": self.user_list.size,
                "share_with_groups": self.group_list.data,
                "nb_groups": self.group_list.size,
            },
        )

    def get(self) -> CData:
        return self._c_data


class CVerificationOptions:
    """Wraps the tanker_verification_options_t C type"""

    def __init__(
        self,
        with_session_token: bool,
    ):
        self._c_data = ffi.new(
            "tanker_verification_options_t *",
            {"version": 1, "with_session_token": with_session_token},
        )

    def get(self) -> CData:
        return self._c_data


class CVerification:
    """Wraps the tanker_verification_t C type"""

    def __init__(
        self,
        verification: Verification,
    ):

        # Note: we store things in `self` so they don't get
        # garbage collected later on
        c_verification = ffi.new("tanker_verification_t *", {"version": 5})
        if isinstance(verification, VerificationKeyVerification):
            c_verification.verification_method_type = (
                tankerlib.TANKER_VERIFICATION_METHOD_VERIFICATION_KEY
            )
            self._verification_key = ffihelpers.str_to_c_string(
                verification.verification_key
            )
            c_verification.verification_key = self._verification_key

        elif isinstance(verification, PassphraseVerification):
            c_verification.verification_method_type = (
                tankerlib.TANKER_VERIFICATION_METHOD_PASSPHRASE
            )
            self._passphrase = ffihelpers.str_to_c_string(verification.passphrase)
            c_verification.passphrase = self._passphrase

        elif isinstance(verification, EmailVerification):
            c_verification.verification_method_type = (
                tankerlib.TANKER_VERIFICATION_METHOD_EMAIL
            )
            self._email_verification = {
                "version": 1,
                "email": ffihelpers.str_to_c_string(verification.email),
                "verification_code": ffihelpers.str_to_c_string(
                    verification.verification_code
                ),
            }
            c_verification.email_verification = self._email_verification

        elif isinstance(verification, OidcIdTokenVerification):
            c_verification.verification_method_type = (
                tankerlib.TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN
            )
            self._oidc_id_token = ffihelpers.str_to_c_string(verification.oidc_id_token)
            c_verification.oidc_id_token = self._oidc_id_token

        elif isinstance(verification, PhoneNumberVerification):
            c_verification.verification_method_type = (
                tankerlib.TANKER_VERIFICATION_METHOD_PHONE_NUMBER
            )
            self._phone_number_verification = {
                "version": 1,
                "phone_number": ffihelpers.str_to_c_string(verification.phone_number),
                "verification_code": ffihelpers.str_to_c_string(
                    verification.verification_code
                ),
            }
            c_verification.phone_number_verification = self._phone_number_verification

        elif isinstance(verification, PreverifiedEmailVerification):
            c_verification.verification_method_type = (
                tankerlib.TANKER_VERIFICATION_METHOD_PREVERIFIED_EMAIL
            )
            self._preverified_email = ffihelpers.str_to_c_string(
                verification.preverified_email
            )
            c_verification.preverified_email = self._preverified_email

        elif isinstance(verification, PreverifiedPhoneNumberVerification):
            c_verification.verification_method_type = (
                tankerlib.TANKER_VERIFICATION_METHOD_PREVERIFIED_PHONE_NUMBER
            )
            self._preverified_phone_number = ffihelpers.str_to_c_string(
                verification.preverified_phone_number
            )
            c_verification.preverified_phone_number = self._preverified_phone_number

        self._c_verification = c_verification

    def get(self) -> CData:
        return self._c_verification


class CVerificationList:
    """Wraps the tanker_verification_list_t C type"""

    def __init__(
        self,
        verifications: List[Verification],
    ):
        c_verification_list = ffi.new("tanker_verification_list_t *", {"version": 1})
        c_verification_list.count = len(verifications)
        self._tanker_verifications = ffi.new(
            "tanker_verification_t [%i]" % len(verifications)
        )
        c_verification_list.verifications = self._tanker_verifications
        # We need to keep the reference to the CVerifications to prevent deallocation
        self._verification_list = []
        for (i, verification) in enumerate(verifications):
            c_verification = CVerification(verification)
            self._verification_list.append(c_verification)
            # We use [0] to dereference the pointer
            c_verification_list.verifications[i] = c_verification.get()[0]

        self._c_verification_list = c_verification_list

    def get(self) -> CData:
        return self._c_verification_list


class Device:
    """An element of the list returned by `tanker.get_device_list()`

    :ivar device_id: The id of the device
    :ivar is_revoked: Whether the device is revoked

    """

    def __init__(self, device_id: str, is_revoked: bool):
        self.device_id = device_id
        self.is_revoked = is_revoked

    @classmethod
    def from_c(cls, c_device_list_elem: CData) -> "Device":
        device_id = ffihelpers.c_string_to_str(c_device_list_elem.device_id)
        is_revoked = c_device_list_elem.is_revoked
        return cls(device_id, is_revoked)


class InputStream(typing_extensions.Protocol):
    async def read(self, size: int) -> bytes:
        ...


class Stream:
    """Stream type returned by stream encryption/decryption functions"""

    def __init__(self, input_stream: InputStream) -> None:
        """Create a new Stream from the underlying InputStream"""
        self._stream = input_stream
        self.c_stream: Optional[CData] = None
        self.c_handle: Optional[CData] = None
        self.error: Optional[Exception] = None

    async def __aexit__(self, *unused: Any) -> None:
        tankerlib.tanker_future_destroy(tankerlib.tanker_stream_close(self.c_stream))

    async def __aenter__(self) -> "Stream":
        return self

    async def read(self, size: Optional[int] = None) -> bytes:
        """Read some bytes from the undelying stream

        If `size` is not None, at most `size` bytes will be returned,  otherwise
        all the data will be returned at once
        """
        if size is not None:
            return await self._read_with_size(size)
        else:
            chunk_size = 1024 ** 2
            res = bytearray()
            while True:
                chunk = await self._read_with_size(chunk_size)
                if not chunk:
                    break
                res += chunk
            return res

    async def _read_with_size(self, size: int) -> bytes:
        buf = bytearray(size)
        c_buf = ffi.from_buffer("uint8_t[]", buf)
        read_fut = tankerlib.tanker_stream_read(self.c_stream, c_buf, size)
        try:
            c_voidptr = await ffihelpers.handle_tanker_future(read_fut)
        except TankerError:
            if self.error:
                raise self.error
            else:
                raise
        nb_read = int(ffi.cast("intptr_t", c_voidptr))
        return buf[0:nb_read]


class EncryptionSession:
    """Allows doing multiple encryption operations with a reduced number of keys."""

    def __init__(self, c_session: CData) -> None:
        """Create a new EncryptionSession from the C struct"""
        self.c_session = c_session

    async def __aexit__(self, *unused: Any) -> None:
        tankerlib.tanker_future_destroy(
            tankerlib.tanker_encryption_session_close(self.c_session)
        )

    async def __aenter__(self) -> "EncryptionSession":
        return self

    def get_resource_id(self) -> str:
        """Get the session's resource id"""
        c_expected = tankerlib.tanker_encryption_session_get_resource_id(self.c_session)
        c_id = ffihelpers.unwrap_expected(c_expected, "char*")
        return ffihelpers.c_string_to_str(c_id)

    async def encrypt(self, clear_data: bytes) -> bytes:
        """Encrypt `clear_data` with the session"""
        c_clear_buffer = ffihelpers.bytes_to_c_buffer(clear_data)  # type: CData
        clear_size = len(c_clear_buffer)
        size = tankerlib.tanker_encryption_session_encrypted_size(clear_size)
        c_encrypted_buffer = ffi.new("uint8_t[%i]" % size)
        c_future = tankerlib.tanker_encryption_session_encrypt(
            self.c_session, c_encrypted_buffer, c_clear_buffer, clear_size
        )

        await ffihelpers.handle_tanker_future(c_future)
        return ffihelpers.c_buffer_to_bytes(c_encrypted_buffer)

    async def encrypt_stream(self, clear_stream: InputStream) -> Stream:
        """Encrypt `clear_stream` with the session

        :param clear_stream: An object implementing the :py:class:`InputStream` protocol
        :return: A :py:class:`Stream` object
        """
        result = Stream(clear_stream)
        handle = ffi.new_handle([result, asyncio.get_event_loop()])
        result.c_handle = handle

        encryption_fut = tankerlib.tanker_encryption_session_stream_encrypt(
            self.c_session, tankerlib.stream_input_source_callback, handle
        )
        result.c_stream = await ffihelpers.handle_tanker_future(encryption_fut)
        return result


async def read_coroutine(
    c_output_buffer: CData,
    c_buffer_size: int,
    c_op: CData,
    stream_wrapper: Stream,
) -> None:
    try:
        buffer: bytes = await stream_wrapper._stream.read(c_buffer_size)
        size = len(buffer)
        ffi.memmove(c_output_buffer, buffer, size)
        tankerlib.tanker_stream_read_operation_finish(c_op, size)
    except Exception as e:
        stream_wrapper.error = e
        tankerlib.tanker_stream_read_operation_finish(c_op, -1)


@ffi.def_extern()  # type: ignore
def stream_input_source_callback(
    c_output_buffer: CData, c_buffer_size: int, c_op: CData, c_additional_data: CData
) -> None:
    try:
        stream_instance, loop = ffi.from_handle(c_additional_data)
        asyncio.run_coroutine_threadsafe(
            read_coroutine(c_output_buffer, c_buffer_size, c_op, stream_instance), loop
        )
    except Exception as e:
        stream_instance._error = e
        tankerlib.tanker_stream_read_operation_finish(c_op, -1)


def prehash_password(password: str) -> str:
    """Hash a password client-side.

    Useful when using identity verification by passphrase
    """
    c_password = ffihelpers.str_to_c_string(password)
    c_expected_hashed = tankerlib.tanker_prehash_password(c_password)
    c_hashed = ffihelpers.unwrap_expected(c_expected_hashed, "char*")
    hashed = ffihelpers.c_string_to_str(c_hashed)
    return hashed


_GLOBAL_TANKERS: "weakref.WeakKeyDictionary[Tanker, Any]" = weakref.WeakKeyDictionary()


class Tanker:
    """
    tankersdk.Tanker(app_id, *, persistent_path, cache_path)

    :param app_id: The App ID
    :param writeable_path: A writeable path to store user data

    """

    def __init__(
        self,
        app_id: str,
        *,
        url: Optional[str] = None,
        # Note: the sdk-type is used for analytics. Set it to something else
        # if you are not a Tanker customer (for instance, when running tests)
        sdk_type: str = "client-python",
        persistent_path: str,
        cache_path: str,
    ):
        self.sdk_type = sdk_type
        self.sdk_version = __version__
        self.app_id = app_id
        self.url = url or "https://api.tanker.io"
        self.persistent_path = persistent_path
        self.cache_path = cache_path
        self.c_tanker = None

        self._create_tanker_obj()
        self._set_event_callbacks()
        self.on_revoked = None  # type: Optional[RevokeFunc]

    def __del__(self) -> None:
        if getattr(self, "c_tanker", None):
            # We can't tanker_future_wait() this future here because this object
            # can be deleted at any time: when its refcount reaches zero, or
            # when the GC is invoked. Since these events can occur while a lock
            # (a simple python lock, not the GIL or any internal incantation) is
            # held, it can lead to a dead lock. Here's a scenario:
            # - some python code takes a lock (in Future, or ThreadPoolExecutor,
            # or anything)
            # - there's no more memory and the GC is called while the lock is
            # held
            # - this function is called and we wait for the async destruction on
            # tconcurrent's thread
            # - tconcurrent's thread is currently executing python code and
            # waiting for the previous python lock
            # - DEADLOCK
            # One solution to this can be to never run python code on
            # tconcurrent's thread but asynchronously on another thread. Doing
            # this would force us to drop the guarantee that when
            # tanker_destroy() returns, no more event callback will be running
            # or will run in the future for that instance.
            tankerlib.tanker_destroy(self.c_tanker)

    def _create_tanker_obj(self) -> None:
        c_url = ffihelpers.str_to_c_string(self.url)
        c_app_id = ffihelpers.str_to_c_string(self.app_id)
        c_persistent_path = ffihelpers.str_to_c_string(self.persistent_path)
        c_cache_path = ffihelpers.str_to_c_string(self.cache_path)
        c_sdk_type = ffihelpers.str_to_c_string(self.sdk_type)
        c_sdk_version = ffihelpers.str_to_c_string(__version__)
        tanker_options = ffi.new(
            "tanker_options_t *",
            {
                "version": 4,
                "app_id": c_app_id,
                "url": c_url,
                "persistent_path": c_persistent_path,
                "sdk_type": c_sdk_type,
                "sdk_version": c_sdk_version,
                "http_options": {
                    "send_request": ffi.NULL,
                    "cancel_request": ffi.NULL,
                    "data": ffi.NULL,
                },
                "cache_path": c_cache_path,
                "datastore_options": {
                    "open": ffi.NULL,
                    "close": ffi.NULL,
                    "nuke": ffi.NULL,
                    "put_serialized_device": ffi.NULL,
                    "find_serialized_device": ffi.NULL,
                    "put_cache_values": ffi.NULL,
                    "find_cache_values": ffi.NULL,
                },
            },
        )
        create_fut = tankerlib.tanker_create(tanker_options)
        ffihelpers.wait_fut_or_raise(create_fut)
        c_voidp = tankerlib.tanker_future_get_voidptr(create_fut)
        self.c_tanker = ffi.cast("tanker_t*", c_voidp)

    def _set_event_callbacks(self) -> None:
        # userdata must live as long as self, and userdata must not hold a
        # reference on self
        userdata = ffi.new_handle(weakref.ref(self))
        _GLOBAL_TANKERS[self] = userdata
        c_future_connect = tankerlib.tanker_event_connect(
            self.c_tanker,
            tankerlib.TANKER_EVENT_DEVICE_REVOKED,
            tankerlib.revoke_callback,
            userdata,
        )
        ffihelpers.wait_fut_or_raise(c_future_connect)

    @property
    def status(self) -> Status:
        """Retrieve the status of the current session, as a :py:class:`Status` instance"""
        return Status(tankerlib.tanker_status(self.c_tanker))

    async def enroll_user(
        self, identity: str, verifications: List[Verification]
    ) -> None:
        """Enroll a user

        :param identity: The user's Tanker identity
        :param options: The list of preverified verifications
        """
        c_identity = ffihelpers.str_to_c_string(identity)
        c_verifications = CVerificationList(verifications)

        c_future_enroll = tankerlib.tanker_enroll_user(
            self.c_tanker, c_identity, c_verifications.get()
        )
        await ffihelpers.handle_tanker_future(c_future_enroll)

    async def start(self, identity: str) -> Status:
        """Start a new Tanker session

        :param identity: The user's Tanker identity
        :return: A :py:class:`Status` enum
        """
        c_identity = ffihelpers.str_to_c_string(identity)
        c_future = tankerlib.tanker_start(self.c_tanker, c_identity)
        c_voidp = await ffihelpers.handle_tanker_future(c_future)
        return Status(int(ffi.cast("int", c_voidp)))

    async def stop(self) -> None:
        """Stop the Tanker session"""
        c_future = tankerlib.tanker_stop(self.c_tanker)
        await ffihelpers.handle_tanker_future(c_future)

    async def encrypt(
        self, clear_data: bytes, options: Optional[EncryptionOptions] = None
    ) -> bytes:
        """Encrypt `clear_data`

        :param options: An optional instance of :py:class:EncryptionOptions`
        :return: Encrypted data, as `bytes`
        """
        if options:
            c_encrypt_options = CEncryptionOptions(
                share_with_users=options.share_with_users,
                share_with_groups=options.share_with_groups,
                share_with_self=options.share_with_self,
            )
        else:
            c_encrypt_options = CEncryptionOptions()
        c_clear_buffer = ffihelpers.bytes_to_c_buffer(clear_data)  # type: CData
        clear_size = len(c_clear_buffer)
        size = tankerlib.tanker_encrypted_size(clear_size)
        c_encrypted_buffer = ffi.new("uint8_t[%i]" % size)
        c_future = tankerlib.tanker_encrypt(
            self.c_tanker,
            c_encrypted_buffer,
            c_clear_buffer,
            clear_size,
            c_encrypt_options.get(),
        )

        await ffihelpers.handle_tanker_future(c_future)
        return ffihelpers.c_buffer_to_bytes(c_encrypted_buffer)

    async def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt `encrypted_data`"""
        c_encrypted_buffer = encrypted_data
        c_expected_size = tankerlib.tanker_decrypted_size(
            c_encrypted_buffer, len(c_encrypted_buffer)
        )
        c_size = ffihelpers.unwrap_expected(c_expected_size, "uint64_t")
        size = cast(int, c_size)
        c_clear_buffer = ffi.new("uint8_t[%i]" % size)
        c_future = tankerlib.tanker_decrypt(
            self.c_tanker, c_clear_buffer, c_encrypted_buffer, len(c_encrypted_buffer)
        )
        await ffihelpers.handle_tanker_future(c_future)
        return ffihelpers.c_buffer_to_bytes(c_clear_buffer)

    async def encrypt_stream(
        self, clear_stream: InputStream, options: Optional[EncryptionOptions] = None
    ) -> Stream:
        """Encrypt `clear_stream`

        :param clear_stream: An object implementing the :py:class:`InputStream` protocol
        :param options: An optional instance of :py:class:EncryptionOptions`
        :return: A :py:class:`StreamWrapper` object
        """
        if options:
            c_encrypt_options = CEncryptionOptions(
                share_with_users=options.share_with_users,
                share_with_groups=options.share_with_groups,
                share_with_self=options.share_with_self,
            )
        else:
            c_encrypt_options = CEncryptionOptions()

        result = Stream(clear_stream)
        handle = ffi.new_handle([result, asyncio.get_event_loop()])
        result.c_handle = handle

        encryption_fut = tankerlib.tanker_stream_encrypt(
            self.c_tanker,
            tankerlib.stream_input_source_callback,
            handle,
            c_encrypt_options.get(),
        )
        result.c_stream = await ffihelpers.handle_tanker_future(encryption_fut)
        return result

    async def decrypt_stream(self, encrypted_stream: Stream) -> Stream:
        """Decrypt `encrypted_stream`

        :param encrypted_stream: A :py:class:`StreamWrapper` object,
                                 returned by :py:meth:`encrypt_stream`
        :return: A :py:class:`StreamWrapper` object
        """
        result = Stream(encrypted_stream)
        handle = ffi.new_handle([result, asyncio.get_event_loop()])
        result.c_handle = handle
        decryption_fut = tankerlib.tanker_stream_decrypt(
            self.c_tanker, tankerlib.stream_input_source_callback, handle
        )
        try:
            result.c_stream = await ffihelpers.handle_tanker_future(decryption_fut)
        except TankerError:
            if result.error:
                raise result.error
            else:
                raise
        return result

    async def device_id(self) -> str:
        """:return: the current device id"""
        c_future = tankerlib.tanker_device_id(self.c_tanker)
        c_voidp = await ffihelpers.handle_tanker_future(c_future)
        c_str = ffi.cast("char*", c_voidp)
        res = ffihelpers.c_string_to_str(c_str)
        tankerlib.tanker_free_buffer(c_str)
        return res

    async def get_device_list(self) -> List[Device]:
        """Get the list of devices owned by the current user

        :returns: a list of :py:class`Device` instances
        """
        c_future = tankerlib.tanker_get_device_list(self.c_tanker)
        c_voidp = await ffihelpers.handle_tanker_future(c_future)
        c_list = ffi.cast("tanker_device_list_t*", c_voidp)
        count = c_list.count
        c_devices = c_list.devices
        res = list()
        for i in range(count):
            c_device_list_elem = c_devices[i]
            device_description = Device.from_c(c_device_list_elem)
            res.append(device_description)
        tankerlib.tanker_free_device_list(c_list)
        return res

    async def revoke_device(self, device_id: str) -> None:
        """Revoke the given device"""
        warnings.warn(
            'The "revoke_device" method is deprecated, it will be removed in the future',
            DeprecationWarning,
        )
        c_device_id = ffihelpers.str_to_c_string(device_id)
        c_future = tankerlib.tanker_revoke_device(self.c_tanker, c_device_id)
        await ffihelpers.handle_tanker_future(c_future)

    def get_resource_id(self, encrypted_data: bytes) -> str:
        """Get resource ID from `encrypted` data"""
        c_expected = tankerlib.tanker_get_resource_id(
            encrypted_data, len(encrypted_data)
        )
        c_id = ffihelpers.unwrap_expected(c_expected, "char*")
        return ffihelpers.c_string_to_str(c_id)

    async def share(self, resources: List[str], options: SharingOptions) -> None:
        """Share the given list of resources to users or groups

        :param options: An instance of :py:class:SharingOptions`
        """
        resource_list = CCharList(resources, ffi, tankerlib)
        c_sharing_options = CSharingOptions(
            share_with_users=options.share_with_users,
            share_with_groups=options.share_with_groups,
        )

        c_future = tankerlib.tanker_share(
            self.c_tanker,
            resource_list.data,
            resource_list.size,
            c_sharing_options.get(),
        )

        await ffihelpers.handle_tanker_future(c_future)

    async def register_identity(
        self, verification: Verification, options: Optional[VerificationOptions] = None
    ) -> Optional[str]:
        """Register users' identity"""
        c_verification = CVerification(verification)
        if options:
            c_verif_opts = CVerificationOptions(
                with_session_token=options.with_session_token,
            ).get()
        else:
            c_verif_opts = ffi.NULL

        c_future = tankerlib.tanker_register_identity(
            self.c_tanker, c_verification.get(), c_verif_opts
        )

        c_voidp = await ffihelpers.handle_tanker_future(c_future)
        if c_voidp == ffi.NULL:
            return None
        c_str = ffi.cast("char*", c_voidp)
        res = ffihelpers.c_string_to_str(c_str)
        tankerlib.tanker_free_buffer(c_str)
        return res

    async def verify_identity(
        self, verification: Verification, options: Optional[VerificationOptions] = None
    ) -> Optional[str]:
        """Verify users' identity"""
        c_verification = CVerification(verification)
        if options:
            c_verif_opts = CVerificationOptions(
                with_session_token=options.with_session_token,
            ).get()
        else:
            c_verif_opts = ffi.NULL
        c_future = tankerlib.tanker_verify_identity(
            self.c_tanker, c_verification.get(), c_verif_opts
        )
        c_voidp = await ffihelpers.handle_tanker_future(c_future)
        if c_voidp == ffi.NULL:
            return None
        c_str = ffi.cast("char*", c_voidp)
        res = ffihelpers.c_string_to_str(c_str)
        tankerlib.tanker_free_buffer(c_str)
        return res

    async def generate_verification_key(self) -> str:
        """Generate a private unlock key

        This can be used to verify an indentity later on
        """
        c_future = tankerlib.tanker_generate_verification_key(self.c_tanker)
        c_voidp = await ffihelpers.handle_tanker_future(c_future)
        c_str = ffi.cast("char*", c_voidp)
        res = ffihelpers.c_string_to_str(c_str)
        tankerlib.tanker_free_buffer(c_str)
        return res

    async def set_verification_method(
        self, verification: Verification, options: Optional[VerificationOptions] = None
    ) -> Optional[str]:
        """Set or update a verification method"""
        c_verification = CVerification(verification)
        if options:
            c_verif_opts = CVerificationOptions(
                with_session_token=options.with_session_token,
            ).get()
        else:
            c_verif_opts = ffi.NULL
        c_future = tankerlib.tanker_set_verification_method(
            self.c_tanker, c_verification.get(), c_verif_opts
        )

        c_voidp = await ffihelpers.handle_tanker_future(c_future)
        if c_voidp == ffi.NULL:
            return None
        c_str = ffi.cast("char*", c_voidp)
        res = ffihelpers.c_string_to_str(c_str)
        tankerlib.tanker_free_buffer(c_str)
        return res

    async def get_verification_methods(self) -> List[VerificationMethod]:
        """Get the list of available verification methods"""
        c_future = tankerlib.tanker_get_verification_methods(self.c_tanker)
        c_voidp = await ffihelpers.handle_tanker_future(c_future)

        c_list = ffi.cast("tanker_verification_method_list_t*", c_voidp)
        count = c_list.count
        c_methods = c_list.methods
        res = list()
        for i in range(count):
            c_method = c_methods[i]
            method = verification_method_from_c(c_method)
            res.append(method)
        tankerlib.tanker_free_verification_method_list(c_list)
        return res

    async def create_group(self, member_identities: List[str]) -> str:
        """Create a group containing the users in `user_ids`"""
        member_list = CCharList(member_identities, ffi, tankerlib)
        c_future = tankerlib.tanker_create_group(
            self.c_tanker, member_list.data, member_list.size
        )

        c_voidp = await ffihelpers.handle_tanker_future(c_future)
        c_str = ffi.cast("char*", c_voidp)
        return ffihelpers.c_string_to_str(c_str)

    async def update_group_members(
        self,
        group_id: str,
        *,
        users_to_add: OptionalStrList = None,
        users_to_remove: OptionalStrList = None,
    ) -> None:
        """Add or remove some users from an existing group"""
        add_list = CCharList(users_to_add, ffi, tankerlib)
        remove_list = CCharList(users_to_remove, ffi, tankerlib)
        c_group_id = ffihelpers.str_to_c_string(group_id)
        c_future = tankerlib.tanker_update_group_members(
            self.c_tanker,
            c_group_id,
            add_list.data,
            add_list.size,
            remove_list.data,
            remove_list.size,
        )

        await ffihelpers.handle_tanker_future(c_future)

    async def create_encryption_session(
        self, options: Optional[EncryptionOptions] = None
    ) -> EncryptionSession:
        """Create an encryption session

        :param options: An optional instance of :py:class:EncryptionOptions`
        :return: an EncryptionSession object
        """
        if options:
            c_encrypt_options = CEncryptionOptions(
                share_with_users=options.share_with_users,
                share_with_groups=options.share_with_groups,
                share_with_self=options.share_with_self,
            )
        else:
            c_encrypt_options = CEncryptionOptions()

        c_future = tankerlib.tanker_encryption_session_open(
            self.c_tanker,
            c_encrypt_options.get(),
        )
        c_session = await ffihelpers.handle_tanker_future(c_future)
        return EncryptionSession(c_session)

    async def attach_provisional_identity(
        self, provisional_identity: str
    ) -> AttachResult:
        """Attach a provisional identity

        :return: an instance of :py:class:`AttachResult`
        """
        c_future = tankerlib.tanker_attach_provisional_identity(
            self.c_tanker, ffihelpers.str_to_c_string(provisional_identity)
        )
        c_voidp = await ffihelpers.handle_tanker_future(c_future)
        c_attach_result = ffi.cast("tanker_attach_result_t*", c_voidp)
        status = Status(c_attach_result.status)
        result = AttachResult(status)
        if status == Status.IDENTITY_VERIFICATION_NEEDED:
            c_method = c_attach_result.method
            result.verification_method = verification_method_from_c(c_method)
        tankerlib.tanker_free_attach_result(c_attach_result)
        return result

    async def verify_provisional_identity(self, verification: Verification) -> None:
        """Verify a provisional identity"""
        c_verification = CVerification(verification)
        c_future = tankerlib.tanker_verify_provisional_identity(
            self.c_tanker, c_verification.get()
        )

        await ffihelpers.handle_tanker_future(c_future)
