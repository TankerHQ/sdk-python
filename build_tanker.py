from typing import Iterator, List
import json
import os
import sys

from cffi import FFI
from path import Path

ffibuilder = FFI()


def get_native_build_path() -> Path:
    res = os.environ.get("TANKER_NATIVE_BUILD_PATH")
    if not res:
        sys.exit("TANKER_NATIVE_BUILD_PATH not set")
    return Path(res).abspath()


def find_libs(names: List[str], paths: List[str]) -> Iterator[Path]:
    for name in names:
        for lib_path in paths:
            candidate = Path(lib_path) / f"lib{name}.a"
            if candidate.exists():
                yield candidate


def get_deps_libs(native_build_path: Path) -> Iterator[Path]:
    conaninfo = json.loads(native_build_path.joinpath("conanbuildinfo.json").text())
    for dep_info in conaninfo["dependencies"]:
        print("Proccessing", dep_info["name"])
        libs = dep_info["libs"]
        lib_paths = dep_info["lib_paths"]
        yield from find_libs(libs, lib_paths)


def get_all_static_libs() -> Iterator[Path]:
    native_build_path = get_native_build_path()
    for lib in ["libctanker", "libtankercore", "libtankeridentity", "libtankercrypto"]:
        yield native_build_path.joinpath("lib", lib + ".a")

    yield from get_deps_libs(native_build_path)


def on_import() -> None:
    this_path = Path(__file__).parent.abspath()
    src_path = this_path.parent
    native_src_path = src_path.joinpath("sdk-native")
    tanker_include_path = native_src_path.joinpath("modules/sdk-c/include")
    assert tanker_include_path.exists(), "%s does not exist" % tanker_include_path
    libs = list(get_all_static_libs())

    tanker_cffi_source = Path("cffi_src.c").text()
    ffibuilder.set_source(
        "_tanker",
        tanker_cffi_source,
        libraries=["dl", "pthread", "stdc++"],
        extra_objects=libs,
        include_dirs=[tanker_include_path],
        language="c++",
    )

    tanker_cffi_defs = Path("cffi_defs.h").text()
    ffibuilder.cdef(tanker_cffi_defs)


on_import()
if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
