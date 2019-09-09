from typing import Iterator, List
import json
import sys

import cli_ui as ui
from cffi import FFI
from path import Path

tanker_ext = FFI()
admin_ext = FFI()


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
    this_path = Path(__file__).parent.abspath()
    conan_out = this_path / "conan" / "out"
    build_info = conan_out / "conanbuildinfo.json"
    if not build_info.exists():
        ui.warning("%s does not exist" % build_info)
        ui.warning("building dummy Python extension")
        tanker_ext.set_source("_tanker", "")
        tanker_ext.cdef("")
        admin_ext.set_source("_tanker_admin", "")
        admin_ext.cdef("")
        return

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

    tanker_cffi_source = Path("cffi_src.c").text()
    admin_cffi_source = Path("cffi_admin_src.c").text()

    if sys.platform == "win32":
        system_libs = ["crypt32"]
    else:
        system_libs = ["dl", "pthread", "stdc++"]
    tanker_ext.set_source(
        "_tanker",
        tanker_cffi_source,
        libraries=system_libs,
        extra_objects=libs,
        include_dirs=includes,
        language="c",
    )
    admin_ext.set_source(
        "_tanker_admin",
        admin_cffi_source,
        libraries=system_libs,
        extra_objects=libs,
        include_dirs=includes,
        language="c",
    )

    tanker_cffi_defs = Path("cffi_defs.h").text()
    tanker_ext.cdef(tanker_cffi_defs)
    admin_cffi_defs = Path("cffi_admin_defs.h").text()
    admin_ext.cdef(admin_cffi_defs)


on_import()
if __name__ == "__main__":
    tanker_ext.compile(verbose=True)
    admin_ext.compile(verbose=True)
