import asyncio
from enum import Enum
import os


from _tanker import ffi
from _tanker import lib as tankerlib


class Error(Exception):
    pass


def str_to_c(text):
    return ffi.new("char[]", text.encode())


def bytes_to_c(buffer):
    return ffi.new("char[]", buffer)


@ffi.def_extern()
def log_handler(category, level, message):
    if os.environ.get("DEBUG"):
        print(ffi.string(message).decode(), end="")


@ffi.def_extern()
def verification_callback(args, data):
    tanker_instance = ffi.from_handle(data)
    if tanker_instance.on_unlock_required:
        tanker_instance.on_unlock_required()
    else:
        print("Warning: tanker.on_unlock_required not set, .open will not return")


def c_fut_to_exception(c_fut):
    if tankerlib.tanker_future_has_error(c_fut):
        c_error = tankerlib.tanker_future_get_error(c_fut)
        message = ffi.string(c_error.message).decode("latin-1")
        print("error", message)
        return Error(message)


def ensure_no_error(c_fut):
    exception = c_fut_to_exception(c_fut)
    if exception:
        raise exception


def wait_fut_or_die(c_fut):
    tankerlib.tanker_future_wait(c_fut)
    ensure_no_error(c_fut)


def unwrap_expected(c_expected, c_type):
    # FIXME: witouth this cast we get:
    #  TypeError: initializer for ctype 'struct tanker_future_t *'
    #  must be a pointer to same type, not cdata 'struct tanker_future *'
    c_as_future = ffi.cast("tanker_future_t*", c_expected)
    ensure_no_error(c_as_future)
    p = tankerlib.tanker_future_get_voidptr(c_as_future)
    return ffi.cast(c_type, p)


async def handle_tanker_future(c_fut, handle_result=None):
    fut = asyncio.Future()
    loop = asyncio.get_event_loop()

    @ffi.callback("void*(tanker_future_t*, void*)")
    def then_callback(c_fut, p):
        exception = c_fut_to_exception(c_fut)

        async def set_result():
            if exception:
                fut.set_exception(exception)
            else:
                if handle_result:
                    res = handle_result()
                else:
                    res = None
                fut.set_result(res)

        asyncio.run_coroutine_threadsafe(set_result(), loop)

        return ffi.NULL

    tankerlib.tanker_future_then(c_fut, then_callback, ffi.NULL)
    return await fut


class Status(Enum):
    CLOSED = 0
    OPEN = 1
    USER_CREATION = 2
    DEVICE_CREATION = 3
    CLOSING = 4


class Tanker:
    def __init__(self, *, trustchain_url,
                 trustchain_id, trustchain_private_key,
                 writable_path):
        self.trustchain_id = trustchain_id
        self.trustchain_url = trustchain_url
        self.trustchain_private_key = trustchain_private_key
        self.writable_path = writable_path
        self.user_id = None

        self._set_log_handler()
        self._create_tanker_obj()
        self._set_event_callbacks()
        self.on_unlock_required = None
        self._verification_code = None

    def _set_log_handler(self):
        tankerlib.tanker_set_log_handler(tankerlib.log_handler)

    def _create_tanker_obj(self):
        c_trustchain_url = str_to_c(self.trustchain_url)
        c_trustchain_id = str_to_c(self.trustchain_id)
        c_writable_path = str_to_c(self.writable_path)
        tanker_options = ffi.new(
            "tanker_options_t *",
            {
                "version": 1,
                "trustchain_id": c_trustchain_id,
                "trustchain_url": c_trustchain_url,
                "writable_path": c_writable_path,
            }
        )
        create_fut = tankerlib.tanker_create(tanker_options)
        wait_fut_or_die(create_fut)
        p = tankerlib.tanker_future_get_voidptr(create_fut)
        self.c_tanker = ffi.cast("tanker_t*", p)

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
        wait_fut_or_die(c_future_connect)

    async def open(self, user_id, user_token):
        c_token = str_to_c(user_token)
        c_user_id = str_to_c(user_id)
        c_open_fut = tankerlib.tanker_open(self.c_tanker, c_user_id, c_token)
        await handle_tanker_future(c_open_fut)
        self.user_id = user_id

    async def close(self):
        c_destroy_fut = tankerlib.tanker_destroy(self.c_tanker)
        await handle_tanker_future(c_destroy_fut)

    async def encrypt(self, clear_data, *, share_with=None):
        if share_with:
            nb_recipients_uids = len(share_with)
            c_ids = [str_to_c(x) for x in share_with]
            c_recipients_uids = ffi.new("char*[]", c_ids)
        else:
            c_recipients_uids = ffi.NULL
            nb_recipients_uids = 0
        c_encrypt_options = ffi.new(
            "tanker_encrypt_options_t *",
            {
                "version": 1,
                "recipient_uids": c_recipients_uids,
                "nb_recipient_uids": nb_recipients_uids,
                "recipient_gids": ffi.NULL,
                "nb_recipient_gids": 0,
            }
        )
        c_clear_buffer = bytes_to_c(clear_data)
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
            res = ffi.buffer(c_encrypted_buffer, len(c_encrypted_buffer))
            return res[:]

        return await handle_tanker_future(c_encrypt_fut, encrypt_cb)

    async def decrypt(self, encrypted_data):
        c_encrypted_buffer = encrypted_data
        c_expected_size = tankerlib.tanker_decrypted_size(c_encrypted_buffer, len(c_encrypted_buffer))
        c_size = unwrap_expected(c_expected_size, "uint64_t")
        c_clear_buffer = ffi.new("uint8_t[%i]" % c_size)
        c_decrypt_fut = tankerlib.tanker_decrypt(
            self.c_tanker,
            c_clear_buffer,
            c_encrypted_buffer,
            len(c_encrypted_buffer),
            ffi.NULL
        )

        def decrypt_cb():
            return ffi.string(c_clear_buffer)

        return await handle_tanker_future(c_decrypt_fut, decrypt_cb)

    def generate_user_token(self, user_id):
        c_user_id = str_to_c(user_id)
        c_trustchain_id = str_to_c(self.trustchain_id)
        c_trustchain_private_key = str_to_c(self.trustchain_private_key)
        c_expected = tankerlib.tanker_generate_user_token(
            c_trustchain_id,
            c_trustchain_private_key,
            c_user_id)
        c_token = unwrap_expected(c_expected, "char*")
        return ffi.string(c_token).decode()

    async def unlock_current_device_with_password(self, password):
        c_pwd = str_to_c(password)
        c_accept_fut = tankerlib.tanker_unlock_current_device_with_password(
            self.c_tanker,
            c_pwd
        )
        return await handle_tanker_future(c_accept_fut)

    async def setup_unlock(self, password):
        c_pwd = str_to_c(password)
        c_setup_unlock_fut = tankerlib.tanker_setup_unlock(
            self.c_tanker,
            ffi.NULL,
            c_pwd,
            )
        return await handle_tanker_future(c_setup_unlock_fut)

    @property
    def version(self):
        char_p = tankerlib.tanker_version_string()
        return ffi.string(char_p).decode()


class Admin:

    def __init__(self, url, token):
        self.url = url
        self.token = token
        self._create_admin_obj()
        self._c_trustchain = None

    def _create_admin_obj(self):
        c_url = str_to_c(self.url)
        c_token = str_to_c(self.token)
        admin_fut = tankerlib.tanker_admin_connect(c_url, c_token)
        wait_fut_or_die(admin_fut)
        p = tankerlib.tanker_future_get_voidptr(admin_fut)
        self._c_admin = ffi.cast("tanker_admin_t*", p)
        tankerlib.tanker_future_destroy(admin_fut)

    def create_trustchain(self, name):
        c_name = str_to_c(name)
        trustchain_fut = tankerlib.tanker_admin_create_trustchain(self._c_admin, c_name)
        wait_fut_or_die(trustchain_fut)
        p = tankerlib.tanker_future_get_voidptr(trustchain_fut)
        if self._c_trustchain is not None:
            raise Error("Admin instance already has a trustchain")
        self._c_trustchain = ffi.cast("tanker_trustchain_descriptor_t*", p)
        tankerlib.tanker_future_destroy(trustchain_fut)

    def delete_trustchain(self):
        if self._c_trustchain is None:
            raise Error("Admin instance does not have a trustchain yet")
        delete_fut = tankerlib.tanker_admin_delete_trustchain(self._c_admin, self._c_trustchain.id)
        wait_fut_or_die(delete_fut)
        tankerlib.tanker_future_destroy(delete_fut)
        tankerlib.tanker_admin_trustchain_descriptor_free(self._c_trustchain)
        self._c_trustchain = None


    def _get_trustchain_property(self, prop):
        if self._c_trustchain is None:
            raise Error("Admin instance does not have a trustchain yet")
        attr = getattr(self._c_trustchain, prop)
        return ffi.string(attr).decode()

    @property
    def trustchain_name(self):
        return self._get_trustchain_property("name")

    @property
    def trustchain_public_key(self):
        return self._get_trustchain_property("public_key")

    @property
    def trustchain_private_key(self):
        return self._get_trustchain_property("private_key")

    @property
    def trustchain_id(self):
        return self._get_trustchain_property("id")
