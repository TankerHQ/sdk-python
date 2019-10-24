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
    setup_requires=[
        # To run build_tanker.py
        "cffi>=1.12",
        "path.py",
    ],
    cffi_modules=["build_tanker.py:tanker_ext", "build_tanker.py:admin_ext"],
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
