import argparse
import os
import sys

from path import Path

import ci
import ci.cpp
import ci.dmenv
import ci.git
import ci.tanker_configs


def run_setup_py(src_path: Path, profile: str, *args: str) -> None:
    env = os.environ.copy()
    env["TANKER_NATIVE_BUILD_PATH"] = f"../sdk-native/build/{profile}/x86_64/Release"
    ci.dmenv.run("python", "setup.py", *args, env=env, cwd=src_path)


def build(workspace: Path, *, profile: str) -> None:
    ci.cpp.update_conan_config(sys.platform)
    with workspace / "sdk-native":
        builder = ci.cpp.Builder(profile=profile, coverage=False)
        builder.install_deps()
        builder.build()

    python_src_path = workspace / "sdk-python"
    run_setup_py(python_src_path, profile, "clean", "develop")


def check(python_src_path: Path) -> None:
    with python_src_path:
        ci.dmenv.run("black", "--check", "tankersdk")
        env = os.environ.copy()
        env["TANKER_CONFIG_NAME"] = "dev"
        env["TANKER_CONFIG_FILEPATH"] = ci.tanker_configs.get_path()
        env["MYPYPATH"] = python_src_path / "stubs"
        ci.dmenv.run(
            "mypy", "--strict", "--ignore-missing-imports",
            "tankersdk", "test", "demo.py",
            env=env
        )
        ci.dmenv.run("flake8", ".", env=env)
        ci.dmenv.run("pytest", "--verbose", "--capture=no", env=env)


def deploy(python_src_path: Path, *, profile: str, git_tag: str) -> None:
    with python_src_path:
        version = ci.bump.version_from_git_tag(git_tag)
        ci.bump.bump_files(version)
    dist_path = python_src_path / "dist"
    dist_path.rmtree_p()
    run_setup_py(python_src_path, profile, "bdist_wheel")
    wheels = dist_path.files("tankersdk-*.whl")
    if len(wheels) != 1:
        raise Exception("multiple wheels found: {}".format(wheels))
    wheel_path = wheels[0]
    if sys.platform == "win32":
        wheel_path = wheel_path.lower()
        wheel_path = wheel_path.replace(os.path.sep, "/")
        wheel_path = wheel_path.replace("c:/", "/c/")
    ci.run("scp", wheel_path, "pypi@tanker.local:packages")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--profile", required=True)

    deploy_parser = subparsers.add_parser("deploy")
    deploy_parser.add_argument("--git-tag", required=True)
    deploy_parser.add_argument("--profile", required=True)

    subparsers.add_parser("mirror")

    args = parser.parse_args()

    command = args.command

    if not command:
        parser.print_help()
        sys.exit(1)

    if command == "mirror":
        ci.git.mirror(github_url="git@github.com:TankerHQ/sdk-python")
        return

    profile = args.profile
    workspace = ci.git.prepare_sources(repos=["sdk-native", "sdk-python"], clean=False)
    python_src_path = workspace / "sdk-python"
    ci.dmenv.install(cwd=python_src_path, develop=False)

    if profile != "windows":
        build(workspace, profile=profile)

    if command == "check":
        check(python_src_path)
    elif command == "deploy":
        git_tag = args.git_tag
        deploy(python_src_path, profile=profile, git_tag=git_tag)


if __name__ == "__main__":
    main()
