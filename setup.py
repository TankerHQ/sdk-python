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
        ("tanker-conan-ref=", None, "tanker package to use"),
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
        self.tanker_conan_ref = "tanker/dev@tanker/dev"
        self.profile = "default"

    def finalize_options(self):
        pass

    def run(self):
        ui.info_1("Running conan install")
        # fmt: off
        cmd = [
            "install", self.tanker_conan_ref,
            "--update",
            "--profile", self.profile,
            "--build", "missing",
            "--install-folder", self.conan_out_path,
            "--generator=json",
        ]
        # fmt: on
        self.run_conan(*cmd)


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
    install_requires=["attrs", "cffi>=1.12", "typing-extensions"],
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
            "tankersdk_identity",
            # Documentation
            "sphinx",
            "ghp-import",
            "sphinxcontrib-trio",
            # Build
            "wheel",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
)
