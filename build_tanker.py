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
    conaninfo = json.loads(native_build_path.joinpath("conanbuildinfo.json").text())
    for dep_info in conaninfo["dependencies"]:
        print("Proccessing", dep_info["name"])
        libs = dep_info["libs"]
        lib_paths = dep_info["lib_paths"]
        yield from find_libs(libs, lib_paths)


def get_all_static_libs():
    native_build_path = get_native_build_path()
    for lib in ["libtanker", "libtankercore", "libtankerusertoken", "libtankercrypto"]:
        yield native_build_path.joinpath("lib", lib + ".a")

    yield from get_deps_libs(native_build_path)


def on_import():
    this_path = path.Path(__file__).parent.abspath()
    src_path = this_path.parent
    native_src_path = src_path.joinpath("Native")
    tanker_include_path = native_src_path.joinpath("modules/sdk-c/include")
    assert tanker_include_path.exists(), "%s does not exist" % tanker_include_path
    libs = list(get_all_static_libs())

    tanker_cffi_source = path.Path("cffi_src.c").text()
    ffibuilder.set_source(
        "_tanker",
        tanker_cffi_source,
        libraries=["rt", "dl", "pthread", "stdc++"],
        extra_objects=libs,
        include_dirs=[tanker_include_path],
        language="c++",
    )

    tanker_cffi_defs = path.Path("cffi_defs.h").text()
    ffibuilder.cdef(tanker_cffi_defs)


on_import()
if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
