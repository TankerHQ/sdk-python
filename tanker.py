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
def validation_callback(args, data):
    tanker_instance = ffi.from_handle(data)
    c_validation_code = ffi.cast("char*", args)
    validation_code = ffi.string(c_validation_code)
    if tanker_instance.on_waiting_for_validation:
        tanker_instance.on_waiting_for_validation(validation_code)
    else:
        print("Warning: tanker.on_waiting_for_validation not set, .open will not return")


def wait_fut_or_die(c_fut):
    tankerlib.tanker_future_wait(c_fut)
    if tankerlib.tanker_future_has_error(c_fut):
        c_error = tankerlib.tanker_future_get_error(c_fut)
        raise Error(ffi.string(c_error.message).decode("latin-1"))


def unwrap_expected(c_expected, c_type):
    c_as_future = ffi.cast("tanker_future_t*", c_expected)
    if tankerlib.tanker_future_has_error(c_as_future):
        c_error = tankerlib.tanker_future_get_error(c_as_future)
        raise Error(ffi.string(c_error.message).decode("latin-1"))
    p = tankerlib.tanker_future_get_voidptr(c_as_future)
    return ffi.cast(c_type, p)


class Status(Enum):
    CLOSED = 0
    OPEN = 1
    USER_CREATION = 2
    DEVICE_CREATION = 3
    CLOSING = 4


class Tanker:
    def __init__(self, *, trustchain_url="https://api.tanker.io",
                 trustchain_id, trustchain_private_key,
                 writable_path):
        self.trustchain_id = trustchain_id
        self.trustchain_url = trustchain_url
        self.trustchain_private_key = trustchain_private_key
        self.writable_path = writable_path

        self._set_log_handler()
        self._create_tanker_obj()
        self._set_event_callbacks()
        self.on_waiting_for_validation = None

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
            tankerlib.TANKER_EVENT_WAITING_FOR_VALIDATION,
            tankerlib.validation_callback,
            self._userdata,
        )
        wait_fut_or_die(c_future_connect)

    def open(self, user_id, user_token):
        c_token = str_to_c(user_token)
        c_user_id = str_to_c(user_id)
        open_fut = tankerlib.tanker_open(self.c_tanker, c_user_id, c_token)
        wait_fut_or_die(open_fut)

    def close(self):
        c_fut = tankerlib.tanker_destroy(self.c_tanker)
        wait_fut_or_die(c_fut)

    def encrypt(self, clear_data, *, share_with=None):
        if share_with:
            nb_recipients = len(share_with)
            c_ids = [str_to_c(x) for x in share_with]
            c_recipients_uids = ffi.new("char*[]", c_ids)
        else:
            c_recipients_uids = ffi.NULL
            nb_recipients = 0
        c_encrypt_options = ffi.new(
            "tanker_encrypt_options_t *",
            {
                "version": 1,
                "recipient_uids": c_recipients_uids,
                "nb_recipients": nb_recipients
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
        wait_fut_or_die(c_encrypt_fut)
        res = ffi.buffer(c_encrypted_buffer, len(c_encrypted_buffer))
        return res[:]

    def decrypt(self, encrypted_data):
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
        wait_fut_or_die(c_decrypt_fut)
        return ffi.string(c_clear_buffer)

    def generate_user_token(self, user_id):
        c_user_id = str_to_c(user_id)
        c_trustchain_id = str_to_c(self.trustchain_id)
        c_trustchain_private_key = str_to_c(self.trustchain_private_key)
        c_token = tankerlib.tanker_generate_user_token(
            c_trustchain_id,
            c_trustchain_private_key,
            c_user_id
        )
        return ffi.string(c_token).decode()

    def accept_device(self, code):
        c_code = bytes_to_c(code)
        c_accept_fut = tankerlib.tanker_accept_device(
            self.c_tanker,
            c_code
        )
        wait_fut_or_die(c_accept_fut)

    @property
    def version(self):
        char_p = tankerlib.tanker_version_string()
        return ffi.string(char_p).decode()
