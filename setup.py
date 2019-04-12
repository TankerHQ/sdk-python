import sys
import distutils.cmd
from setuptools import setup, find_packages

import cli_ui as ui
from conans.client.command import main as main_conan
from path import Path

if sys.version_info.major < 3:
    sys.exit("Error: Please upgrade to Python3")


def get_long_description() -> str:
    with open("README.rst") as fp:
        return fp.read()


class NativeCommand(distutils.cmd.Command):
    descripton = "Handle sdk-native dependency"
    user_options = [
        ("release", None, "build in release"),
        ("deployed", None, "use deployed version"),
        ("profile=", None, "name of the conan profile"),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.conan_path = Path(".") / "conan"
        self.conan_out_path = self.conan_path / "out"

    def run_conan(self, *args: str) -> None:
        ui.info_3("conan", *args)
        try:
            main_conan(args)
        except SystemExit as e:
            if e.code != 0:
                sys.exit("conan failed")

    def initialize_options(self):
        self.release = False
        self.deployed = False
        self.profile = "default"

    def finalize_options(self):
        pass

    def run(self):
        if not self.deployed:
            self.build_from_sources()
        self.run_conan_install()

    def run_conan_install(self):
        ui.info_1("Running conan install")
        # fmt: off
        cmd = [
            "install", self.conan_path,
            "--update",
            "--profile", self.profile,
            "--build", "missing",
            "--install-folder", self.conan_out_path,
        ]
        # fmt: on
        if not self.deployed:
            cmd.extend(["--options", "native_from_sources=True"])
        self.run_conan(*cmd)

    def build_from_sources(self):
        ui.info_1("Building Native SDK from sources")
        native_src_path = (Path("..") / "sdk-native").abspath()
        # fmt: off
        self.run_conan(
            "create",
            "--update",
            "--build", "missing",
            "--profile", self.profile,
            native_src_path,
            "tanker/testing"
        )
        # fmt: on


setup(
    name="tankersdk",
    version="dev",
    description="End to end encryption",
    long_description=get_long_description(),
    url="https://tanker.io",
    author="Kontrol SAS",
    packages=find_packages(),
    setup_requires=[
        # To run build_tanker.py
        "cffi>=1.12",
        "path.py",
    ],
    cffi_modules=["build_tanker.py:ffibuilder"],
    cmdclass={"native": NativeCommand},
    install_requires=["attrs", "cffi>=1.12", "tankersdk_identity"],
    extras_require={
        "dev": [
            # For run-ci.py
            "ci",
            "requests",
            # Linters
            "black",
            "flake8",
            "flake8-docstrings",
            "mypy",
            # Tests
            "pytest",
            "pytest-cov",
            "faker",
            "path.py",
            "pytest-asyncio",
            # Documentation
            "sphinx",
            "ghp-import",
            "sphinxcontrib-trio",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
)
