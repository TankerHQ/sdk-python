import sys
from setuptools import setup

if sys.version_info.major < 3:
    sys.exit("Error: Please upgrade to Python3")


def get_long_description() -> str:
    with open("README.rst") as fp:
        return fp.read()


if sys.platform == "win32":
    cffi_modules = list()
else:
    cffi_modules = ["build_tanker.py:ffibuilder"]


setup(
    name="tankersdk",
    version="1.10.0b3",
    description="End to end encryption",
    long_description=get_long_description(),
    url="https://tanker.io",
    author="Kontrol SAS",
    packages=["tankersdk.core"],
    setup_requires=[
        # To run build_tanker.py
        "cffi>=1.12",
        "path.py"
    ],
    cffi_modules=cffi_modules,
    install_requires=[
        "attrs",
        "cffi>=1.12",
    ],
    extras_require={
        "dev": [
            # For run-ci.py
            "ci",

            # Linters
            "black",
            "flake8",
            "flake8-docstrings",
            "mypy",

            # Tests
            "pytest",
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
