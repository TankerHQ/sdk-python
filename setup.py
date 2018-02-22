import sys
from setuptools import setup, find_packages

if sys.version_info.major < 3:
    sys.exit("Error: Please upgrade to Python3")


def get_long_description():
    with open("README.rst") as fp:
        return fp.read()


setup(name="tanker",
      version="1.4.0",
      description="End to end encryption",
      long_description=get_long_description(),
      url="https://tanker.io",
      author="Kontrol SAS",
      packages=find_packages(),
      install_requires=["cffi>=1.0.0"],
      classifiers=[
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
      ],
      )
