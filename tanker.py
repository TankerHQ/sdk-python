from cffi import FFI
ffi = FFI()

ffi.cdef("""
// async.h
typedef struct tanker_future_t tanker_future_t;
void tanker_future_wait(tanker_future_t* future);
unsigned char tanker_future_has_error(tanker_future_t* future);
char* tanker_future_get_error(tanker_future_t* future);
void* tanker_future_get_voidptr(tanker_future_t* future);

// tanker.h
typedef char b64char;
typedef struct tanker_t tanker_t;
const char* tanker_version_string();
typedef void (*tanker_log_handler_t)(char const* category,
                                     char level,
                                     const char* message);
void tanker_set_log_handler(tanker_log_handler_t handler);
struct tanker_options
{
  uint8_t version;
  b64char const* trustchain_id;
  b64char const* unsafe_trustchain_private_key;
  char const* trustchain_url;
  char const* db_storage_path;
};
typedef struct tanker_options tanker_options_t;
tanker_future_t* tanker_create(const tanker_options_t* options);
tanker_future_t* tanker_open(tanker_t* tanker, const char* user_token);


char* tanker_make_user_token(tanker_t* ctanker,
                             const char* user_id,
                             const char* secret);
""")


@ffi.callback("void(char* const, char, char* const)")
def log_handler(category, level, message):
    # FIXME: message already contains category and level ...
    print(ffi.string(message).decode())


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

        self._init_tanker_lib()
        self._create_tanker_obj()

    def _init_tanker_lib(self):
        self.tanker_lib = ffi.dlopen("libtanker.so")
        self.tanker_lib.tanker_set_log_handler(log_handler)

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
        create_fut = self.tanker_lib.tanker_create(tanker_options)
        self.tanker_lib.tanker_future_wait(create_fut)
        if self.tanker_lib.tanker_future_has_error(create_fut):
            c_message = self.tanker_lib.tanker_future_get_error(create_fut)
            raise Error(ffi.string(c_message).decode())
        p = self.tanker_lib.tanker_future_get_voidptr(create_fut)
        self.c_tanker = ffi.cast("tanker_t*", p)

    def make_user_token(self, user_id, secret):
        c_user_id = ffi.new("char[]", user_id.encode())
        c_secret = ffi.new("char[]", secret.encode())
        c_token = self.tanker_lib.tanker_make_user_token(self.c_tanker, c_user_id, c_secret)
        return ffi.string(c_token).decode()

    @property
    def version(self):
        char_p = self.tanker_lib.tanker_version_string()
        return ffi.string(char_p).decode()

    def open(self, user_token):
        c_token = ffi.new("char[]", user_token.encode())
        open_fut = self.tanker_lib.tanker_open(self.c_tanker, c_token)
        self.tanker_lib.tanker_future_wait(open_fut)
        if self.tanker_lib.tanker_future_has_error(open_fut):
            c_message = self.tanker_lib.tanker_future_get_error(open_fut)
            raise Error(ffi.string(c_message))
