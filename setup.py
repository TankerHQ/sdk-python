import sys
from setuptools import setup

if sys.version_info.major < 3:
    sys.exit("Error: Please upgrade to Python3")


def get_long_description():
    with open("README.rst") as fp:
        return fp.read()


setup(name="tankersdk",
      version="1.9.0.alpha1",
      description="End to end encryption",
      long_description=get_long_description(),
      url="https://tanker.io",
      author="Kontrol SAS",
      packages=["tankersdk.core"],
      setup_requires=[
          "cffi>=1.0.0",
          "path.py"
      ],
      cffi_modules=["build_tanker.py:ffibuilder"],
      install_requires=[
          "cffi==1.11.6",
          "trio",
          "sanic",
          "path.py",
      ],
      extras_require={
          "dev": [
              "wheel",
              "ci",
              "pytest",
              "faker",
              "pytest-asyncio",
          ]
      },
      classifiers=[
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
      ],
      )
