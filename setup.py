import sys
from setuptools import setup, find_packages

if sys.version_info.major < 3:
    sys.exit("Error: Please upgrade to Python3")


def get_long_description() -> str:
    with open("README.rst") as fp:
        return fp.read()


setup(
    name="tankersdk",
    version="dev",
    description="End to end encryption",
    long_description=get_long_description(),
    url="https://tanker.io",
    author="Kontrol SAS",
    packages=find_packages(),
    cffi_modules=["build_tanker.py:tanker_ext", "build_tanker.py:admin_ext"],
)
