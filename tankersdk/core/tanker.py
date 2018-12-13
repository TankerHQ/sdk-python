import attr
from enum import Enum
import os

from _tanker import ffi
from _tanker import lib as tankerlib

from .ffi_helpers import (
    str_to_c_string,
    c_string_to_str,
    c_string_to_bytes,
    bytes_to_c_string,
    CCharList,
    wait_fut_or_raise,
    unwrap_expected,
    handle_tanker_future,
)

__version__ = "1.9.0-alpha1"


@ffi.def_extern()
def log_handler(category, level, message):
    if os.environ.get("DEBUG"):
        print(c_string_to_str(message))


@ffi.def_extern()
def verification_callback(args, data):
    tanker_instance = ffi.from_handle(data)
    if tanker_instance.on_unlock_required:
        tanker_instance.on_unlock_required()
    else:
        print("Warning: tanker.on_unlock_required not set, .open will not return")


class Status(Enum):
    CLOSED = 0
    OPEN = 1
    USER_CREATION = 2
    DEVICE_CREATION = 3
    CLOSING = 4


class Tanker:
    def __init__(
        self,
        trustchain_id,
        *,
        trustchain_url="https://api.tanker.io",
        sdk_type="client-python",
        writable_path
    ):
        self.sdk_type = sdk_type
        self.sdk_version = __version__
        self.trustchain_id = trustchain_id
        self.trustchain_url = trustchain_url
        self.writable_path = writable_path

        self._set_log_handler()
        self._create_tanker_obj()
        self._set_event_callbacks()
        self.on_unlock_required = None

    def _set_log_handler(self):
        tankerlib.tanker_set_log_handler(tankerlib.log_handler)

    def _create_tanker_obj(self):
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
    def status(self):
        c_status = tankerlib.tanker_get_status(self.c_tanker)
        return Status(c_status)

    def _set_event_callbacks(self):
        userdata = ffi.new_handle(self)
        self._userdata = userdata  # Must keep this alive
        c_future_connect = tankerlib.tanker_event_connect(
            self.c_tanker,
            tankerlib.TANKER_EVENT_UNLOCK_REQUIRED,
            tankerlib.verification_callback,
            self._userdata,
        )
        wait_fut_or_raise(c_future_connect)

    async def open(self, user_id, user_token):
        c_token = str_to_c_string(user_token)
        c_user_id = str_to_c_string(user_id)
        c_open_fut = tankerlib.tanker_open(self.c_tanker, c_user_id, c_token)
        await handle_tanker_future(c_open_fut)

    async def close(self):
        c_destroy_fut = tankerlib.tanker_destroy(self.c_tanker)
        await handle_tanker_future(c_destroy_fut)

    async def encrypt(
        self, clear_data, *, share_with_users=None, share_with_groups=None
    ):
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
        c_clear_buffer = bytes_to_c_string(clear_data)
        size = tankerlib.tanker_encrypted_size(len(c_clear_buffer))
        c_encrypted_buffer = ffi.new("uint8_t[%i]" % size)
        c_encrypt_fut = tankerlib.tanker_encrypt(
            self.c_tanker,
            c_encrypted_buffer,
            c_clear_buffer,
            len(c_clear_buffer),
            c_encrypt_options,
        )

        def encrypt_cb():
            # Make a copy of the ffi.buffer as a simple `bytes`
            # object so that it can be used without worrying
            # about the ffi buffer being garbage collected.
            res = ffi.buffer(c_encrypted_buffer, len(c_encrypted_buffer))
            return res[:]

        return await handle_tanker_future(c_encrypt_fut, encrypt_cb)

    async def decrypt(self, encrypted_data):
        c_encrypted_buffer = encrypted_data
        c_expected_size = tankerlib.tanker_decrypted_size(
            c_encrypted_buffer, len(c_encrypted_buffer)
        )
        c_size = unwrap_expected(c_expected_size, "uint64_t")
        c_clear_buffer = ffi.new("uint8_t[%i]" % c_size)
        c_decrypt_fut = tankerlib.tanker_decrypt(
            self.c_tanker,
            c_clear_buffer,
            c_encrypted_buffer,
            len(c_encrypted_buffer),
            ffi.NULL,
        )

        def decrypt_cb():
            return c_string_to_bytes(c_clear_buffer)

        return await handle_tanker_future(c_decrypt_fut, decrypt_cb)

    def get_resource_id(self, encrypted):
        c_expected = tankerlib.tanker_get_resource_id(encrypted, len(encrypted))
        c_id = unwrap_expected(c_expected, "char*")
        return c_string_to_str(c_id)

    async def share(self, resources, *, users=None, groups=None):
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

    def generate_user_token(self, trustchain_private_key, user_id):
        c_user_id = str_to_c_string(user_id)
        c_trustchain_id = str_to_c_string(self.trustchain_id)
        c_trustchain_private_key = str_to_c_string(trustchain_private_key)
        c_expected = tankerlib.tanker_generate_user_token(
            c_trustchain_id, c_trustchain_private_key, c_user_id
        )
        c_token = unwrap_expected(c_expected, "char*")
        return c_string_to_str(c_token)

    async def unlock_current_device_with_password(self, password):
        c_pwd = str_to_c_string(password)
        c_accept_fut = tankerlib.tanker_unlock_current_device_with_password(
            self.c_tanker, c_pwd
        )
        return await handle_tanker_future(c_accept_fut)

    async def unlock(self, *, password=None, verification_code=None):
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

        return await handle_tanker_future(c_accept_fut)

    async def register_unlock(self, *, password=None, email=None):
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
        return await handle_tanker_future(c_register_unlock_fut)

    async def create_group(self, user_ids):
        user_list = CCharList(user_ids)
        c_create_group_fut = tankerlib.tanker_create_group(
            self.c_tanker, user_list.data, user_list.size
        )

        def create_group_cb():
            c_voidp = tankerlib.tanker_future_get_voidptr(c_create_group_fut)
            c_str = ffi.cast("char*", c_voidp)
            return c_string_to_str(c_str)

        return await handle_tanker_future(c_create_group_fut, create_group_cb)

    async def update_group_members(self, group_id, *, add=None):
        add_list = CCharList(add)
        c_group_id = str_to_c_string(group_id)
        c_update_group_fut = tankerlib.tanker_update_group_members(
            self.c_tanker, c_group_id, add_list.data, add_list.size
        )

        await handle_tanker_future(c_update_group_fut)

    @property
    def version(self):
        c_str = tankerlib.tanker_version_string()
        return c_string_to_str(c_str)
