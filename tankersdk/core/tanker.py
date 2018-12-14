from typing import cast, Callable, List, Optional
from asyncio import Future  # noqa
from enum import Enum
import os

from _tanker import ffi
from _tanker import lib as tankerlib

from .ffi_helpers import (
    CData,
    OptionalStrList,
    str_to_c_string,
    c_string_to_str,
    c_string_to_bytes,
    bytes_to_c_string,
    CCharList,
    wait_fut_or_raise,
    unwrap_expected,
    handle_tanker_future,
)

__version__ = "1.9.0b2"


@ffi.def_extern()  # type: ignore
def log_handler(category: CData, level: CData, message: CData) -> None:
    if os.environ.get("DEBUG"):
        print(c_string_to_str(message))


@ffi.def_extern()  # type: ignore
def verification_callback(args: CData, data: CData) -> None:
    tanker_instance = ffi.from_handle(data)
    if tanker_instance.on_unlock_required:
        tanker_instance.on_unlock_required()
    else:
        print("Warning: tanker.on_unlock_required not set, .open will not return")


@ffi.def_extern()  # type: ignore
def revoke_callback(args: CData, data: CData) -> None:
    tanker_instance = ffi.from_handle(data)
    if tanker_instance.on_revoked:
        tanker_instance.on_revoked()


class Status(Enum):
    CLOSED = 0
    OPEN = 1
    USER_CREATION = 2
    DEVICE_CREATION = 3
    CLOSING = 4


UnlockFunc = Callable[[], None]
RevokeFunc = Callable[[], None]


class Tanker:
    def __init__(
        self,
        trustchain_id: str,
        *,
        trustchain_url: Optional[str] = None,
        sdk_type: str = "client-python",
        writable_path: str
    ):
        self.sdk_type = sdk_type
        self.sdk_version = __version__
        self.trustchain_id = trustchain_id
        self.trustchain_url = trustchain_url or "https://api.tanker.io"
        self.writable_path = writable_path

        self._set_log_handler()
        self._create_tanker_obj()
        self._set_event_callbacks()
        self.on_unlock_required = None  # type: Optional[UnlockFunc]
        self.on_revoked = None  # type: Optional[RevokeFunc]

    def _set_log_handler(self) -> None:
        tankerlib.tanker_set_log_handler(tankerlib.log_handler)

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

    @property
    def status(self) -> Status:
        c_status = tankerlib.tanker_get_status(self.c_tanker)
        return Status(c_status)

    def _set_event_callbacks(self) -> None:
        userdata = ffi.new_handle(self)
        self._userdata = userdata  # Must keep this alive
        c_future_connect = tankerlib.tanker_event_connect(
            self.c_tanker,
            tankerlib.TANKER_EVENT_UNLOCK_REQUIRED,
            tankerlib.verification_callback,
            self._userdata,
        )
        wait_fut_or_raise(c_future_connect)
        c_future_connect = tankerlib.tanker_event_connect(
            self.c_tanker,
            tankerlib.TANKER_EVENT_DEVICE_REVOKED,
            tankerlib.revoke_callback,
            self._userdata,
        )
        wait_fut_or_raise(c_future_connect)

    async def open(self, user_id: str, user_token: str) -> None:
        c_token = str_to_c_string(user_token)
        c_user_id = str_to_c_string(user_id)
        c_open_fut = tankerlib.tanker_open(self.c_tanker, c_user_id, c_token)
        await handle_tanker_future(c_open_fut)

    async def close(self) -> None:
        c_close_fut = tankerlib.tanker_close(self.c_tanker)
        await handle_tanker_future(c_close_fut)

    async def encrypt(
        self,
        clear_data: bytes,
        *,
        share_with_users: OptionalStrList = None,
        share_with_groups: OptionalStrList = None
    ) -> bytes:
        user_list = CCharList(share_with_users)
        group_list = CCharList(share_with_groups)

        c_encrypt_options = ffi.new(
            "tanker_encrypt_options_t *",
            {
                "version": 1,
                "recipient_uids": user_list.data,
                "nb_recipient_uids": user_list.size,
                "recipient_gids": group_list.data,
                "nb_recipient_gids": group_list.size,
            },
        )
        c_clear_buffer = bytes_to_c_string(clear_data)  # type: CData
        clear_size = len(c_clear_buffer)  # type: ignore
        size = tankerlib.tanker_encrypted_size(clear_size)
        c_encrypted_buffer = ffi.new("uint8_t[%i]" % size)
        c_encrypt_fut = tankerlib.tanker_encrypt(
            self.c_tanker,
            c_encrypted_buffer,
            c_clear_buffer,
            clear_size,
            c_encrypt_options,
        )

        def encrypt_cb() -> bytes:
            res = ffi.buffer(c_encrypted_buffer, len(c_encrypted_buffer))
            # Make a copy of the ffi.buffer as a simple `bytes`
            # object so that it can be used without worrying
            # about the ffi buffer being garbage collected.
            return cast(bytes, res[:])

        return await handle_tanker_future(c_encrypt_fut, encrypt_cb)

    async def decrypt(self, encrypted_data: bytes) -> bytes:
        c_encrypted_buffer = encrypted_data
        c_expected_size = tankerlib.tanker_decrypted_size(
            c_encrypted_buffer, len(c_encrypted_buffer)
        )
        c_size = unwrap_expected(c_expected_size, "uint64_t")
        size = cast(int, c_size)
        c_clear_buffer = ffi.new("uint8_t[%i]" % size)
        c_decrypt_fut = tankerlib.tanker_decrypt(
            self.c_tanker,
            c_clear_buffer,
            c_encrypted_buffer,
            len(c_encrypted_buffer),
            ffi.NULL,
        )

        def decrypt_cb() -> bytes:
            return c_string_to_bytes(c_clear_buffer)

        return await handle_tanker_future(c_decrypt_fut, decrypt_cb)

    async def device_id(self) -> str:
        c_device_fut = tankerlib.tanker_device_id(self.c_tanker)

        def device_id_cb() -> str:
            c_voidp = tankerlib.tanker_future_get_voidptr(c_device_fut)
            c_str = ffi.cast("char*", c_voidp)
            return c_string_to_str(c_str)

        return await handle_tanker_future(c_device_fut, device_id_cb)

    async def revoke_device(self, device_id: str) -> None:
        c_device_id = str_to_c_string(device_id)
        c_revoke_fut = tankerlib.tanker_revoke_device(self.c_tanker, c_device_id)
        await handle_tanker_future(c_revoke_fut)

    def get_resource_id(self, encrypted: bytes) -> str:
        c_expected = tankerlib.tanker_get_resource_id(encrypted, len(encrypted))
        c_id = unwrap_expected(c_expected, "char*")
        return c_string_to_str(c_id)

    async def share(
        self,
        resources: List[str],
        *,
        users: OptionalStrList = None,
        groups: OptionalStrList = None
    ) -> None:
        resource_list = CCharList(resources)
        user_list = CCharList(users)
        group_list = CCharList(groups)

        await handle_tanker_future(
            tankerlib.tanker_share(
                self.c_tanker,
                user_list.data,
                user_list.size,
                group_list.data,
                group_list.size,
                resource_list.data,
                resource_list.size,
            )
        )

    def generate_user_token(self, trustchain_private_key: str, user_id: str) -> str:
        c_user_id = str_to_c_string(user_id)
        c_trustchain_id = str_to_c_string(self.trustchain_id)
        c_trustchain_private_key = str_to_c_string(trustchain_private_key)
        c_expected = tankerlib.tanker_generate_user_token(
            c_trustchain_id, c_trustchain_private_key, c_user_id
        )
        c_token = unwrap_expected(c_expected, "char*")
        return c_string_to_str(c_token)

    async def unlock_current_device_with_password(self, password: str) -> None:
        c_pwd = str_to_c_string(password)
        c_accept_fut = tankerlib.tanker_unlock_current_device_with_password(
            self.c_tanker, c_pwd
        )
        await handle_tanker_future(c_accept_fut)

    async def unlock(
        self, *, password: Optional[str] = None, verification_code: Optional[str] = None
    ) -> None:
        if password and verification_code:
            raise ValueError("Can't unlock both with password and verification_code")

        if password is None and verification_code is None:
            raise ValueError("Either password or verification_code must be set")

        if password:
            c_pwd = str_to_c_string(password)
            c_accept_fut = tankerlib.tanker_unlock_current_device_with_password(
                self.c_tanker, c_pwd
            )
        if verification_code:
            c_verification_code = str_to_c_string(verification_code)
            c_accept_fut = tankerlib.tanker_unlock_current_device_with_verification_code(
                self.c_tanker, c_verification_code
            )

        await handle_tanker_future(c_accept_fut)

    async def register_unlock(
        self, *, password: Optional[str] = None, email: Optional[str] = None
    ) -> None:
        if password:
            c_password = str_to_c_string(password)
        else:
            c_password = ffi.NULL
        if email:
            c_email = str_to_c_string(email)
        else:
            c_email = ffi.NULL
        c_register_unlock_fut = tankerlib.tanker_register_unlock(
            self.c_tanker, c_email, c_password
        )
        await handle_tanker_future(c_register_unlock_fut)

    async def create_group(self, user_ids: List[str]) -> str:
        user_list = CCharList(user_ids)
        c_create_group_fut = tankerlib.tanker_create_group(
            self.c_tanker, user_list.data, user_list.size
        )

        def create_group_cb() -> str:
            c_voidp = tankerlib.tanker_future_get_voidptr(c_create_group_fut)
            c_str = ffi.cast("char*", c_voidp)
            return c_string_to_str(c_str)

        return await handle_tanker_future(c_create_group_fut, create_group_cb)

    async def update_group_members(
        self, group_id: str, *, add: OptionalStrList = None
    ) -> None:
        add_list = CCharList(add)
        c_group_id = str_to_c_string(group_id)
        c_update_group_fut = tankerlib.tanker_update_group_members(
            self.c_tanker, c_group_id, add_list.data, add_list.size
        )

        await handle_tanker_future(c_update_group_fut)

    @property
    def version(self) -> str:
        c_str = tankerlib.tanker_version_string()
        return c_string_to_str(c_str)
