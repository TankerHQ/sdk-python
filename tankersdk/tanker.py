from asyncio import Future  # noqa
from enum import Enum
import os

from typing import cast, Callable, List, Optional

from _tanker import ffi
from _tanker import lib as tankerlib

from .version import __version__
from .ffi_helpers import (
    CCharList,
    CData,
    OptionalStrList,
    bytes_to_c_buffer,
    c_buffer_to_bytes,
    c_string_to_bytes,
    c_string_to_str,
    handle_tanker_future,
    str_to_c_string,
    unwrap_expected,
    wait_fut_or_raise,
)


@ffi.def_extern()  # type: ignore
def log_handler(record: CData) -> None:
    if os.environ.get("TANKER_SDK_DEBUG"):
        #  We can't assume that print() on Windows knows how to handle non-ASCII characters
        #  (it depends on a lot of things)
        #  So to be safe we check if the message from Native is readable in ASCII, and
        #  if this fails we print `repr(message)` so that no information is lost.
        message_bytes = c_string_to_bytes(record.message)
        category = c_string_to_str(record.category)
        try:
            message = message_bytes.decode("ascii")
        except UnicodeDecodeError:
            message = repr(message_bytes)
        print(category, message, sep=": ")


tankerlib.tanker_set_log_handler(tankerlib.log_handler)


@ffi.def_extern()  # type: ignore
def revoke_callback(args: CData, data: CData) -> None:
    tanker_instance = ffi.from_handle(data)
    if tanker_instance.on_revoked:
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
    VERIFICATION_KEY = 2


class VerificationMethod:
    """Represent a verification method

    :ivar method_type: An instance of :py:class:`VerificationMethodType` enum
    :ivar email: The email to use for verification, if `method_type` is `EMAIL`
    """

    def __init__(
        self, method_type: VerificationMethodType, *, email: Optional[str] = None
    ):
        self.method_type = method_type
        if method_type == VerificationMethodType.EMAIL and not email:
            raise ValueError(
                "need an email value if method_type is VerificationMethodType.EMAIL"
            )
        self.email = email

    @classmethod
    def from_c(cls, c_verification_method: CData) -> "VerificationMethod":
        method_type = VerificationMethodType(
            c_verification_method.verification_method_type
        )
        if method_type == VerificationMethodType.EMAIL:
            c_email = c_verification_method.email
            email = c_string_to_str(c_email)
            return cls(method_type, email=email)
        else:
            return cls(method_type)


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


class CVerification:
    """Wraps the tanker_verification_t C type"""

    def __init__(
        self,
        passphrase: Optional[str] = None,
        verification_key: Optional[str] = None,
        email: Optional[str] = None,
        verification_code: Optional[str] = None,
    ):

        options_set = [
            x for x in (passphrase, verification_key, email) if x is not None
        ]
        if len(options_set) != 1:
            raise ValueError("Chose one among passphrase, verification_key and email")

        # Note: we store things in `self` so they don't get
        # garbage collected later on
        c_verification = ffi.new("tanker_verification_t *", {"version": 1})
        if verification_key is not None:
            c_verification.verification_method_type = (
                tankerlib.TANKER_VERIFICATION_METHOD_VERIFICATION_KEY
            )
            self._verification_key = str_to_c_string(verification_key)
            c_verification.verification_key = self._verification_key
        elif passphrase is not None:
            c_verification.verification_method_type = (
                tankerlib.TANKER_VERIFICATION_METHOD_PASSPHRASE
            )
            self._passphrase = str_to_c_string(passphrase)
            c_verification.passphrase = self._passphrase
        elif email is not None:
            if verification_code is None:
                raise ValueError(
                    "Connot create an email verification without a verification code"
                )
            c_verification.verification_method_type = (
                tankerlib.TANKER_VERIFICATION_METHOD_EMAIL
            )
            self._email_verification = {
                "version": 1,
                "email": str_to_c_string(email),
                "verification_code": str_to_c_string(verification_code),
            }
            c_verification.email_verification = self._email_verification
        self._c_verification = c_verification

    def get(self) -> CData:
        return self._c_verification  # type: ignore


class Tanker:
    """
    tankersdk.Tanker(trustchain_id: str, *, writable_path: str)

    :param trustchain_id: The Trustchain ID
    :param writeable_path: A writeable path to store user data

    """

    def __init__(
        self,
        trustchain_id: str,
        *,
        trustchain_url: Optional[str] = None,
        # Note: the sdk-type is used for analytics. Set it to something else
        # if you are not a Tanker customer (for instance, when running tests)
        sdk_type: str = "client-python",
        writable_path: str,
    ):
        self.sdk_type = sdk_type
        self.sdk_version = __version__
        self.trustchain_id = trustchain_id
        self.trustchain_url = trustchain_url or "https://api.tanker.io"
        self.writable_path = writable_path

        self._create_tanker_obj()
        self._set_event_callbacks()
        self.on_revoked = None  # type: Optional[RevokeFunc]

    def _create_tanker_obj(self) -> None:
        c_trustchain_url = str_to_c_string(self.trustchain_url)
        c_trustchain_id = str_to_c_string(self.trustchain_id)
        c_writable_path = str_to_c_string(self.writable_path)
        c_sdk_type = str_to_c_string(self.sdk_type)
        c_sdk_version = str_to_c_string(__version__)
        tanker_options = ffi.new(
            "tanker_options_t *",
            {
                "version": 2,
                "trustchain_id": c_trustchain_id,
                "trustchain_url": c_trustchain_url,
                "writable_path": c_writable_path,
                "sdk_type": c_sdk_type,
                "sdk_version": c_sdk_version,
            },
        )
        create_fut = tankerlib.tanker_create(tanker_options)
        wait_fut_or_raise(create_fut)
        c_voidp = tankerlib.tanker_future_get_voidptr(create_fut)
        self.c_tanker = ffi.cast("tanker_t*", c_voidp)

    def _set_event_callbacks(self) -> None:
        userdata = ffi.new_handle(self)
        self._userdata = userdata  # Must keep this alive
        c_future_connect = tankerlib.tanker_event_connect(
            self.c_tanker,
            tankerlib.TANKER_EVENT_DEVICE_REVOKED,
            tankerlib.revoke_callback,
            self._userdata,
        )
        wait_fut_or_raise(c_future_connect)

    @property
    def status(self) -> Status:
        """Retrieve the status of the current session, as a :py:class:`Status` instance"""
        return Status(tankerlib.tanker_status(self.c_tanker))

    async def start(self, identity: str) -> Status:
        """Start a new Tanker session

        :param identity: The user's Tanker identity
        :return: A :py:class:`Status` enum
        """
        c_identity = str_to_c_string(identity)
        c_future = tankerlib.tanker_start(self.c_tanker, c_identity)

        def callback() -> Status:
            c_voidp = tankerlib.tanker_future_get_voidptr(c_future)
            return Status(int(ffi.cast("int", c_voidp)))

        return await handle_tanker_future(c_future, callback)

    async def stop(self) -> None:
        """Stop the Tanker session"""
        c_future = tankerlib.tanker_stop(self.c_tanker)
        await handle_tanker_future(c_future)

    async def encrypt(
        self,
        clear_data: bytes,
        *,
        share_with_users: OptionalStrList = None,
        share_with_groups: OptionalStrList = None,
    ) -> bytes:
        """Encrypt `clear_data`

        :param share_with_users: An (optional) list of identities to share with
        :param share_with_groups: A list of groups to share with
        """
        user_list = CCharList(share_with_users)
        group_list = CCharList(share_with_groups)

        c_encrypt_options = ffi.new(
            "tanker_encrypt_options_t *",
            {
                "version": 2,
                "recipient_public_identities": user_list.data,
                "nb_recipient_public_identities": user_list.size,
                "recipient_gids": group_list.data,
                "nb_recipient_gids": group_list.size,
            },
        )
        c_clear_buffer = bytes_to_c_buffer(clear_data)  # type: CData
        clear_size = len(c_clear_buffer)  # type: ignore
        size = tankerlib.tanker_encrypted_size(clear_size)
        c_encrypted_buffer = ffi.new("uint8_t[%i]" % size)
        c_future = tankerlib.tanker_encrypt(
            self.c_tanker,
            c_encrypted_buffer,
            c_clear_buffer,
            clear_size,
            c_encrypt_options,
        )

        def callback() -> bytes:
            return c_buffer_to_bytes(c_encrypted_buffer)

        return await handle_tanker_future(c_future, callback)

    async def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt `encrypted_data`"""
        c_encrypted_buffer = encrypted_data
        c_expected_size = tankerlib.tanker_decrypted_size(
            c_encrypted_buffer, len(c_encrypted_buffer)
        )
        c_size = unwrap_expected(c_expected_size, "uint64_t")
        size = cast(int, c_size)
        c_clear_buffer = ffi.new("uint8_t[%i]" % size)
        c_future = tankerlib.tanker_decrypt(
            self.c_tanker, c_clear_buffer, c_encrypted_buffer, len(c_encrypted_buffer)
        )

        def callback() -> bytes:
            return c_buffer_to_bytes(c_clear_buffer)

        return await handle_tanker_future(c_future, callback)

    async def device_id(self) -> str:
        """:return: the current device id"""
        c_future = tankerlib.tanker_device_id(self.c_tanker)

        def callback() -> str:
            c_voidp = tankerlib.tanker_future_get_voidptr(c_future)
            c_str = ffi.cast("char*", c_voidp)
            return c_string_to_str(c_str)

        return await handle_tanker_future(c_future, callback)

    async def revoke_device(self, device_id: str) -> None:
        """Revoke the given device"""
        c_device_id = str_to_c_string(device_id)
        c_future = tankerlib.tanker_revoke_device(self.c_tanker, c_device_id)
        await handle_tanker_future(c_future)

    def get_resource_id(self, encrypted: bytes) -> str:
        """Get resource ID from `encrypted` data"""
        c_expected = tankerlib.tanker_get_resource_id(encrypted, len(encrypted))
        c_id = unwrap_expected(c_expected, "char*")
        return c_string_to_str(c_id)

    async def share(
        self,
        resources: List[str],
        *,
        users: OptionalStrList = None,
        groups: OptionalStrList = None,
    ) -> None:
        """Share the given list of resources to users or groups"""
        resource_list = CCharList(resources)
        user_list = CCharList(users)
        group_list = CCharList(groups)

        c_future = tankerlib.tanker_share(
            self.c_tanker,
            user_list.data,
            user_list.size,
            group_list.data,
            group_list.size,
            resource_list.data,
            resource_list.size,
        )

        await handle_tanker_future(c_future)

    async def register_identity(
        self,
        *,
        verification_key: Optional[str] = None,
        passphrase: Optional[str] = None,
        email: Optional[str] = None,
        verification_code: Optional[str] = None,
    ) -> None:
        """Register users' identity"""
        c_verification = CVerification(
            verification_key=verification_key,
            passphrase=passphrase,
            email=email,
            verification_code=verification_code,
        )

        c_future = tankerlib.tanker_register_identity(
            self.c_tanker, c_verification.get()
        )
        await handle_tanker_future(c_future)

    async def verify_identity(
        self,
        *,
        verification_key: Optional[str] = None,
        passphrase: Optional[str] = None,
        email: Optional[str] = None,
        verification_code: Optional[str] = None,
    ) -> None:
        """Verify users' identity"""
        c_verification = CVerification(
            verification_key=verification_key,
            passphrase=passphrase,
            email=email,
            verification_code=verification_code,
        )
        c_future = tankerlib.tanker_verify_identity(self.c_tanker, c_verification.get())
        await handle_tanker_future(c_future)

    async def generate_verification_key(self) -> str:
        """Generate a private unlock key

        This can be used to verify an indentity later on
        """
        c_future = tankerlib.tanker_generate_verification_key(self.c_tanker)

        def callback() -> str:
            c_voidp = tankerlib.tanker_future_get_voidptr(c_future)
            c_str = ffi.cast("char*", c_voidp)
            return c_string_to_str(c_str)

        return await handle_tanker_future(c_future, callback)

    async def set_verification_method(
        self,
        *,
        verification_key: Optional[str] = None,
        passphrase: Optional[str] = None,
        email: Optional[str] = None,
        verification_code: Optional[str] = None,
    ) -> None:
        """Set or update a verification method"""
        c_verification = CVerification(
            verification_key=verification_key,
            passphrase=passphrase,
            email=email,
            verification_code=verification_code,
        )
        c_future = tankerlib.tanker_set_verification_method(
            self.c_tanker, c_verification.get()
        )

        return await handle_tanker_future(c_future)

    async def get_verification_methods(self) -> List[VerificationMethod]:
        """Get the list of available verification methods"""
        c_future = tankerlib.tanker_get_verification_methods(self.c_tanker)

        def callback() -> List[VerificationMethod]:
            c_voidp = tankerlib.tanker_future_get_voidptr(c_future)
            c_list = ffi.cast("tanker_verification_method_list_t*", c_voidp)
            count = c_list.count
            c_methods = c_list.methods
            res = list()
            for i in range(count):
                c_method = c_methods[i]
                method = VerificationMethod.from_c(c_method)
                res.append(method)
            return res

        return await handle_tanker_future(c_future, callback)

    async def create_group(self, user_ids: List[str]) -> str:
        """Create a group containing the users in `user_ids`"""
        user_list = CCharList(user_ids)
        c_future = tankerlib.tanker_create_group(
            self.c_tanker, user_list.data, user_list.size
        )

        def callback() -> str:
            c_voidp = tankerlib.tanker_future_get_voidptr(c_future)
            c_str = ffi.cast("char*", c_voidp)
            return c_string_to_str(c_str)

        return await handle_tanker_future(c_future, callback)

    async def update_group_members(
        self, group_id: str, *, add: OptionalStrList = None
    ) -> None:
        """Add some users to an existing group"""
        add_list = CCharList(add)
        c_group_id = str_to_c_string(group_id)
        c_future = tankerlib.tanker_update_group_members(
            self.c_tanker, c_group_id, add_list.data, add_list.size
        )

        await handle_tanker_future(c_future)

    async def attach_provisional_identity(
        self, provisional_identity: str
    ) -> AttachResult:
        """Attach a provisional identity

        :return: an instance of :py:class:`AttachResult`
        """
        c_future = tankerlib.tanker_attach_provisional_identity(
            self.c_tanker, str_to_c_string(provisional_identity)
        )

        def callback() -> AttachResult:
            c_voidp = tankerlib.tanker_future_get_voidptr(c_future)
            c_attach_result = ffi.cast("tanker_attach_result_t*", c_voidp)
            status = Status(c_attach_result.status)
            result = AttachResult(status)
            if status == Status.IDENTITY_VERIFICATION_NEEDED:
                c_method = c_attach_result.method
                c_method_type = c_method.verification_method_type
                method_type = VerificationMethodType(c_method_type)
                if method_type == VerificationMethodType.EMAIL:
                    verification_method = VerificationMethod(
                        VerificationMethodType.EMAIL,
                        email=c_string_to_str(c_method.email),
                    )
                else:
                    verification_method = VerificationMethod(method_type)
                result.verification_method = verification_method
            return result

        return await handle_tanker_future(c_future, callback)

    async def verify_provisional_identity(
        self, *, email: str, verification_code: str
    ) -> None:
        """Verify a provisional identity"""
        verification = CVerification(email=email, verification_code=verification_code)
        c_future = tankerlib.tanker_verify_provisional_identity(
            self.c_tanker, verification.get()
        )

        await handle_tanker_future(c_future)
