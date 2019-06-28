import argparse
import os
import sys

from path import Path

import ci
import ci.bump
import ci.conan
import ci.git
import ci.dmenv
import ci.tanker_configs

DEPLOYED_TANKER = "tanker/2.0.0@tanker/stable"
LOCAL_TANKER = "tanker/dev@tanker/dev"


class Builder:
    def __init__(self, src_path: Path, tanker_conan_ref: str, profile: str):
        self.profile = profile
        self.src_path = src_path
        self.tanker_conan_ref = tanker_conan_ref

    def _run_setup_py(self, *args: str) -> None:
        ci.dmenv.run("python", "setup.py", *args, cwd=self.src_path)

    def build(self) -> None:
        self._run_setup_py("native", "--tanker-conan-ref",
                           self.tanker_conan_ref, "--profile", self.profile)
        self._run_setup_py("clean", "build", "develop")

    def test(self) -> None:
        ci.dmenv.run("python", "lint.py", cwd=self.src_path)

        env = os.environ.copy()
        env["TANKER_CONFIG_NAME"] = "dev"
        env["TANKER_CONFIG_FILEPATH"] = ci.tanker_configs.get_path()
        env["TANKER_SDK_DEBUG"] = "1"
        ci.dmenv.run(
            "pytest",
            "--verbose",
            "--capture=no",
            "--cov=tankersdk",
            "--cov-report",
            "html",
            env=env,
            cwd=self.src_path,
        )
        coverage_dir = self.src_path / "htmlcov"
        dest_dir = self.src_path / "coverage"
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

        ci.dmenv.run("python", "setup.py", "bdist_wheel", cwd=self.src_path)
        wheels = dist_path.files("tankersdk-*.whl")
        if len(wheels) != 1:
            raise Exception("multiple wheels found: {}".format(wheels))
        wheel_path = wheels[0]
        if sys.platform == "win32":
            wheel_path = wheel_path.lower()
            wheel_path = wheel_path.replace(os.path.sep, "/")
            wheel_path = wheel_path.replace("c:/", "/c/")
        ci.run("scp", wheel_path, "pypi@tanker.local:packages")


def build(use_tanker: str, profile: str):
    src_path = Path.getcwd()
    tanker_conan_ref = LOCAL_TANKER

    if use_tanker == "deployed":
        tanker_conan_ref = DEPLOYED_TANKER
    elif use_tanker == "local":
        ci.conan.export(src_path=Path.getcwd().parent / "sdk-native", ref_or_channel="tanker/dev")
    elif use_tanker == "same-as-branch":
        workspace = ci.git.prepare_sources(repos=["sdk-native", "sdk-python"])
        src_path = workspace / "sdk-python"
        ci.conan.export(src_path=workspace / "sdk-native", ref_or_channel="tanker/dev")
    else:
        sys.exit()

    builder = Builder(src_path, tanker_conan_ref, profile)
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
    build_and_check_parser.add_argument("--use-tanker",
                                        choices=['deployed', 'local', 'same-as-branch'],
                                        default='local')
    build_and_check_parser.add_argument("--profile", required=True)

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
