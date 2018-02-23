from _tanker import ffi
from _tanker import lib as tankerlib


@ffi.def_extern()
def log_handler(category, level, message):
    print(ffi.string(message).decode(), end="")


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

    def _create_tanker_obj(self):
        c_trustchain_url = ffi.new("char[]", self.trustchain_url.encode())
        c_trustchain_id = ffi.new("char[]", self.trustchain_id.encode())
        c_unsafe_trustchain_private_key = ffi.new("char[]", self.trustchain_private_key.encode())
        c_db_storage_path = ffi.new("char[]", self.db_storage_path.encode())
        tanker_options = ffi.new(
            "tanker_options_t *",
            {
                "version": 1,
                "trustchain_id": c_trustchain_id,
                "trustchain_url": c_trustchain_url,
                "unsafe_trustchain_private_key": c_unsafe_trustchain_private_key,
                "db_storage_path": c_db_storage_path,
            }
        )
        create_fut = tankerlib.tanker_create(tanker_options)
        tankerlib.tanker_future_wait(create_fut)
        if tankerlib.tanker_future_has_error(create_fut):
            c_message = tankerlib.tanker_future_get_error(create_fut)
            raise Error(ffi.string(c_message).decode())
        p = tankerlib.tanker_future_get_voidptr(create_fut)
        self.c_tanker = ffi.cast("tanker_t*", p)

    def make_user_token(self, user_id, secret):
        c_user_id = ffi.new("char[]", user_id.encode())
        c_secret = ffi.new("char[]", secret.encode())
        c_token = tankerlib.tanker_make_user_token(self.c_tanker, c_user_id, c_secret)
        return ffi.string(c_token).decode()

    @property
    def version(self):
        char_p = tankerlib.tanker_version_string()
        return ffi.string(char_p).decode()

    def open(self, user_token):
        c_token = ffi.new("char[]", user_token.encode())
        open_fut = tankerlib.tanker_open(self.c_tanker, c_token)
        tankerlib.tanker_future_wait(open_fut)
        if tankerlib.tanker_future_has_error(open_fut):
            c_message = tankerlib.tanker_future_get_error(open_fut)
            raise Error(ffi.string(c_message))
