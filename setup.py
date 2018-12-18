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
    version="dev",
    description="End to end encryption",
    long_description=get_long_description(),
    url="https://tanker.io",
    author="Kontrol SAS",
    packages=["tankersdk.core"],
    setup_requires=["cffi>=1.0.0", "path.py"],
    cffi_modules=cffi_modules,
    install_requires=["attrs", "cffi==1.11.5-tanker1", "trio", "path.py"],
    extras_require={
        "dev": [
            "wheel",
            "ci",
            "black",
            "pytest",
            "faker",
            "pytest-asyncio",
            "flake8",
            "mypy",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
    ],
)
