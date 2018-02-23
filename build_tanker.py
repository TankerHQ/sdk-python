import json
import os
import sys

from cffi import FFI
import path

ffibuilder = FFI()


def get_native_build_path():
    res = os.environ.get("TANKER_NATIVE_BUILD_PATH")
    if not res:
        sys.exit("TANKER_NATIVE_BUILD_PATH not set")
    return path.Path(res).abspath()


def find_libs(names, paths):
    for name in names:
        for lib_path in paths:
            candidate = os.path.join(lib_path, "lib" + name + ".a")
            if os.path.exists(candidate):
                yield candidate


def get_deps_libs(native_build_path):
    conaninfo = json.loads(native_build_path.joinpath("conaninfo.json").text())
    for dep_info in conaninfo["dependencies"]:
        print("Proccessing", dep_info["name"])
        libs = dep_info["libs"]
        lib_paths = dep_info["lib_paths"]
        yield from find_libs(libs, lib_paths)


def get_all_static_libs():
    native_build_path = get_native_build_path()
    for lib in ["libtanker", "libtankercore"]:
        yield native_build_path.joinpath("lib", lib + ".a")

    yield from get_deps_libs(native_build_path)


def on_import():
    this_path = path.Path(__file__).parent.abspath()
    native_src_path = this_path.parent.joinpath("Native")
    tanker_include_path = native_src_path.joinpath("sdk-c/include")
    libs = get_all_static_libs()

    ffibuilder.set_source(
        "_tanker",
        """
        #include <tanker.h>

        """,
        libraries=["rt", "dl", "pthread", "stdc++"],
        extra_objects=libs,
        include_dirs=[tanker_include_path],
        language='c++',
    )

    ffibuilder.cdef("""
extern "Python" void log_handler(const char* category, char level, const char* message);

// async
typedef struct tanker_future_t tanker_future_t;
void tanker_future_wait(tanker_future_t* future);
unsigned char tanker_future_has_error(tanker_future_t* future);
char* tanker_future_get_error(tanker_future_t* future);
void* tanker_future_get_voidptr(tanker_future_t* future);

// tanker.h
typedef char b64char;
typedef struct tanker_t tanker_t;
const char* tanker_version_string();
typedef void (*tanker_log_handler_t)(char const* category, char level, const char* message);
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


on_import()
if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
