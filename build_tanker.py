from typing import Iterator, List
import os
import json
import sys

import cli_ui as ui
from cffi import FFI
from path import Path

tanker_ext = FFI()


def get_lib_name(name):
    if sys.platform == "win32":
        return name + ".lib"
    else:
        return "lib" + name + ".a"


def find_libs(names: List[str], paths: List[str]) -> Iterator[Path]:
    for name in names:
        for lib_path in paths:
            lib_name = get_lib_name(name)
            candidate = Path(lib_path) / lib_name
            if candidate.exists():
                yield candidate


def on_import() -> None:
    path_from_env = os.environ.get("TANKER_PYTHON_SDK_SRC")
    if path_from_env:
        this_path = Path(path_from_env)
    else:
        this_path = Path(__file__).parent.abspath()

    conan_out_path = this_path / "conan" / "out"
    build_info = None
    for d in conan_out_path.dirs():
        conan_info = d / "conanbuildinfo.json"
        if conan_info.exists():
            build_info = conan_info
            break

    if not build_info or not build_info.exists():
        ui.fatal(
            "conanbuildinfo.json not found - cannot configure compilation with tanker/native",
        )

    conaninfo = json.loads(build_info.text())
    libs = list()
    for dep_info in conaninfo["dependencies"]:
        libs_for_dep = dep_info["libs"]
        lib_paths = dep_info["lib_paths"]
        libs.extend(find_libs(libs_for_dep, lib_paths))

    all_deps = conaninfo["dependencies"]
    tanker_packages = [x for x in all_deps if x["name"] == "tanker"]
    n = len(tanker_packages)
    assert n == 1, "expecting one package named 'tanker', got %i" % n
    tanker_package = tanker_packages[0]
    includes = tanker_package["include_paths"]

    tanker_cffi_source = (this_path / "cffi_src.c").text()

    if sys.platform == "win32":
        system_libs = ["crypt32"]
        symbols_file = "exported_symbols.def"
        exported_symbols_flags = ["/DEF:%s" % (this_path / symbols_file)]
    elif sys.platform == "linux":
        system_libs = ["dl", "pthread", "stdc++"]
        symbols_file = "exported_symbols.ld"
        exported_symbols_flags = [
            "-Wl,--version-script=%s" % (this_path / symbols_file)
        ]
        system_libs = ["dl", "pthread", "stdc++"]
    else:
        symbols_file = "exported_symbols.sym"
        exported_symbols_flags = [
            "-exported_symbols_list",
            "%s" % (this_path / symbols_file),
        ]
        # macOS system libs + compiler flags are already in the env
        # thanks to the virtualenv generated by conan in setup.py
        system_libs = []

    tanker_ext.set_source(
        "_tanker",
        tanker_cffi_source,
        libraries=system_libs,
        extra_objects=libs,
        include_dirs=includes,
        language="c",
        extra_link_args=exported_symbols_flags,
    )

    tanker_cffi_defs = (this_path / "cffi_defs.h").text()
    tanker_ext.cdef(tanker_cffi_defs)


on_import()


if __name__ == "__main__":
    tanker_ext.compile(verbose=True)
