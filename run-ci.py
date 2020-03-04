import argparse
import os
import sys

from path import Path

import ci
import ci.bump
import ci.conan
import ci.git
import ci.tanker_configs

DEPLOYED_TANKER = "tanker/2.2.2@tanker/stable"
LOCAL_TANKER = "tanker/dev@tanker/dev"


class Builder:
    def __init__(self, src_path: Path, profile: str):
        self.profile = profile
        self.src_path = src_path

    def build(self) -> None:
        # Note: this re-installs the root package, which was skipped
        # when using poetry install --no-root in the .gitlab-ci.yml
        # This is because we need to run some conan commands before the
        # code in build.py can run
        ci.run(
            "poetry",
            "run",
            "python",
            "setup.py",
            "develop",
            "--no-deps",
            cwd=self.src_path,
        )

    def test(self) -> None:
        ci.run("poetry", "run", "python", "lint.py", cwd=self.src_path)

        env = os.environ.copy()
        env["TANKER_CONFIG_NAME"] = "dev"
        env["TANKER_CONFIG_FILEPATH"] = ci.tanker_configs.get_path()
        env["TANKER_SDK_DEBUG"] = "1"
        # fmt: off
        ci.run(
            "poetry", "run", "pytest",
            "--verbose",
            "--capture=no",
            "--cov=tankersdk",
            "--cov-report", "html",
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
            version = ci.bump.version_from_git_tag(tag)
            ci.bump.bump_files(version)
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
        ci.run("poetry", "build", env=env)
        wheels = dist_path.files("tankersdk-*.whl")
        if len(wheels) != 1:
            raise Exception("multiple wheels found: {}".format(wheels))
        wheel_path = wheels[0]
        ci.run("scp", wheel_path, "pypi@tanker.local:packages")


def build(use_tanker: str, profile: str):
    src_path = Path.getcwd()
    tanker_conan_ref = LOCAL_TANKER

    if use_tanker == "deployed":
        tanker_conan_ref = DEPLOYED_TANKER
    elif use_tanker == "local":
        ci.conan.export(
            src_path=Path.getcwd().parent / "sdk-native", ref_or_channel="tanker/dev"
        )
    elif use_tanker == "same-as-branch":
        workspace = ci.git.prepare_sources(repos=["sdk-native", "sdk-python"])
        src_path = workspace / "sdk-python"
        ci.conan.export(src_path=workspace / "sdk-native", ref_or_channel="tanker/dev")
    else:
        sys.exit()

    conan_out_path = src_path / "conan" / "out"
    # fmt: off
    ci.conan.run(
        "install", tanker_conan_ref,
        "--update",
        "--profile", profile,
        "--install-folder", conan_out_path,
        "--generator=json",
    )
    # fmt: on

    builder = Builder(src_path, profile)
    builder.build()
    return builder


def build_and_check(args):
    builder = build(args.use_tanker, args.profile)
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
        "--use-tanker", choices=["deployed", "local", "same-as-branch"], default="local"
    )
    build_and_check_parser.add_argument("--profile", default="default")

    deploy_parser = subparsers.add_parser("deploy")
    deploy_parser.add_argument("--profile", required=True)

    subparsers.add_parser("mirror")

    args = parser.parse_args()
    if args.home_isolation:
        ci.conan.set_home_isolation()

    command = args.command

    if not command:
        parser.print_help()
        sys.exit(1)

    if command == "mirror":
        ci.git.mirror(github_url="git@github.com:TankerHQ/sdk-python")
        return

    if command == "build-and-check":
        build_and_check(args)
    elif command == "deploy":
        deploy(args.profile)


if __name__ == "__main__":
    main()
