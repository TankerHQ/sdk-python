import os


from _tanker import ffi
from _tanker import lib as tankerlib


@ffi.def_extern()
def log_handler(category, level, message):
    if os.environ.get("DEBUG"):
        print(ffi.string(message).decode(), end="")


def str_to_c(text):
    return ffi.new("char[]", text.encode())


def wait_fut_or_die(c_fut):
    tankerlib.tanker_future_wait(c_fut)
    if tankerlib.tanker_future_has_error(c_fut):
        c_message = tankerlib.tanker_future_get_error(c_fut)
        raise Error(ffi.string(c_message))


class Error(Exception):
    pass


class Tanker:
    def __init__(self, *, trustchain_url="https://api.tanker.io",
                 trustchain_id, trustchain_private_key,
                 db_storage_path):
        self.trustchain_id = trustchain_id
        self.trustchain_url = trustchain_url
        self.trustchain_private_key = trustchain_private_key
        self.db_storage_path = db_storage_path

        self._set_log_handler()
        self._create_tanker_obj()

    def _set_log_handler(self):
        tankerlib.tanker_set_log_handler(tankerlib.log_handler)

    def close(self):
        print("destroying tanker ...")
        c_fut = tankerlib.tanker_destroy(self.c_tanker)
        wait_fut_or_die(c_fut)
        self.c_fut = c_fut
        print("tanker destroyed")

    def _create_tanker_obj(self):
        c_trustchain_url = str_to_c(self.trustchain_url)
        c_trustchain_id = str_to_c(self.trustchain_id)
        c_unsafe_trustchain_private_key = str_to_c(self.trustchain_private_key)
        c_db_storage_path = str_to_c(self.db_storage_path)
        self.tanker_options = ffi.new(
            "tanker_options_t *",
            {
                "version": 1,
                "trustchain_id": c_trustchain_id,
                "trustchain_url": c_trustchain_url,
                "unsafe_trustchain_private_key": c_unsafe_trustchain_private_key,
                "db_storage_path": c_db_storage_path,
            }
        )
        create_fut = tankerlib.tanker_create(self.tanker_options)  # keep tanker_options alive
        p = tankerlib.tanker_future_get_voidptr(create_fut)
        self.p = p  # keeping p alive ?
        self.c_tanker = ffi.cast("tanker_t*", p)

    def make_user_token(self, user_id, secret):
        c_user_id = str_to_c(user_id)
        c_secret = str_to_c(secret)
        c_token = tankerlib.tanker_make_user_token(self.c_tanker, c_user_id, c_secret)
        return ffi.string(c_token).decode()

    @property
    def version(self):
        char_p = tankerlib.tanker_version_string()
        return ffi.string(char_p).decode()

    def open(self, user_token):
        c_token = str_to_c(user_token)
        open_fut = tankerlib.tanker_open(self.c_tanker, c_token)
        wait_fut_or_die(open_fut)
        self.open_fut = open_fut
        print("open ok")
