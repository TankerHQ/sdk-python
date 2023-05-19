from setuptools import setup

setup(
    cffi_modules="build_tanker.py:tanker_ext",
)
