import argparse
import os
import sys

from path import Path
from enum import Enum

import tankerci
import tankerci.bump
import tankerci.conan
import tankerci.git

DEPLOYED_TANKER = "tanker/2.5.0@tanker/stable"
LOCAL_TANKER = "tanker/dev@tanker/dev"


class TankerSource(Enum):
    LOCAL = "local"
    SAME_AS_BRANCH = "same-as-branch"
    DEPLOYED = "deployed"


class Builder:
    def __init__(self, src_path: Path, profile: str):
        self.profile = profile
        self.src_path = src_path

    def build(self) -> None:
        # Note: this re-installs the root package, which was skipped
        # when using poetry install --no-root in the .gitlab-ci.yml
        # This is because we need to run some conan commands before the
        # code in build.py can run
        tankerci.run("poetry", "install", cwd=self.src_path)

    def test(self) -> None:
        env = os.environ.copy()
        env["TANKER_SDK_DEBUG"] = "1"
        # fmt: off
        tankerci.run(
            "poetry", "run", "pytest",
            "--verbose",
            "--capture=no",
            "--cov=tankersdk",
            "--cov-report", "html",
            "--numprocesses", "auto",
            env=env,
            cwd=self.src_path,
        )
        # fmt: on
        coverage_dir = self.src_path / "htmlcov"
        dest_dir = Path.getcwd() / "coverage"
        dest_dir.rmtree_p()
        coverage_dir.copytree(dest_dir)

    def deploy(self) -> None:
        tag = os.environ.get("CI_COMMIT_TAG")
        if tag is None:
            raise Exception("No tag found, cannot deploy")
        with self.src_path:
            version = tankerci.bump.version_from_git_tag(tag)
            tankerci.bump.bump_files(version)
        dist_path = self.src_path / "dist"
        dist_path.rmtree_p()

        env = os.environ.copy()
        env["TANKER_PYTHON_SDK_SRC"] = self.src_path
        # Note: poetry generates a temporary directory,
        # change the working directory there, creates a `setup.py`
        # from scratch (calling `build.py`) and runs it.
        # In the process, all the conan files generated in the
        # sources gets lost. We set this environment variable
        # so that they can be found even when the working directory
        # changes, and we make sure *all* paths used in build_tanker.py
        # are absolute
        tankerci.run("poetry", "build", env=env)
        wheels = dist_path.files("tankersdk-*.whl")
        if len(wheels) != 1:
            raise Exception("multiple wheels found: {}".format(wheels))
        wheel_path = wheels[0]
        tankerci.run("scp", wheel_path, "pypi@tanker.local:packages")


def build(tanker_source: TankerSource, profile: str) -> Builder:
    src_path = Path.getcwd()
    tanker_conan_ref = LOCAL_TANKER
    tanker_conan_extra_flags = ["--build=tanker"]

    if tanker_source == TankerSource.DEPLOYED:
        tanker_conan_ref = DEPLOYED_TANKER
        tanker_conan_extra_flags = []
    elif tanker_source == TankerSource.LOCAL:
        tankerci.conan.export(
            src_path=Path.getcwd().parent / "sdk-native", ref_or_channel="tanker/dev"
        )
    elif tanker_source == TankerSource.SAME_AS_BRANCH:
        workspace = tankerci.git.prepare_sources(repos=["sdk-native", "sdk-python"])
        src_path = workspace / "sdk-python"
        tankerci.conan.export(
            src_path=workspace / "sdk-native", ref_or_channel="tanker/dev"
        )

    conan_out_path = src_path / "conan" / "out"
    # fmt: off
    tankerci.conan.run(
        "install", tanker_conan_ref,
        *tanker_conan_extra_flags,
        "--update",
        "--profile", profile,
        "--install-folder", conan_out_path,
        "--generator=json",
    )
    # fmt: on

    builder = Builder(src_path, profile)
    builder.build()
    return builder


def build_and_check(args) -> None:
    builder = build(args.tanker_source, args.profile)
    builder.test()


def deploy(profile: str) -> None:
    builder = build("deployed", profile)
    builder.deploy()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--isolate-conan-user-home",
        action="store_true",
        dest="home_isolation",
        default=False,
    )

    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    build_and_check_parser = subparsers.add_parser("build-and-check")
    build_and_check_parser.add_argument(
        "--use-tanker",
        type=TankerSource,
        default=TankerSource.LOCAL,
        dest="tanker_source",
    )
    build_and_check_parser.add_argument("--profile", default="default")

    deploy_parser = subparsers.add_parser("deploy")
    deploy_parser.add_argument("--profile", required=True)

    subparsers.add_parser("mirror")

    args = parser.parse_args()
    if args.home_isolation:
        tankerci.conan.set_home_isolation()
        tankerci.conan.update_config()

    command = args.command

    if not command:
        parser.print_help()
        sys.exit(1)

    if command == "mirror":
        tankerci.git.mirror(github_url="git@github.com:TankerHQ/sdk-python")
        return

    if command == "build-and-check":
        build_and_check(args)
    elif command == "deploy":
        deploy(args.profile)


if __name__ == "__main__":
    main()
