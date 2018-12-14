from typing import List
import argparse
import os

from path import Path

import ci
import ci.cpp
import ci.dmenv
import ci.git


def run_setup_py(src_path: Path, profile: str, *args: str) -> None:
    env = os.environ.copy()
    env["TANKER_NATIVE_BUILD_PATH"] = f"../sdk-native/build/{profile}/x86_64/Release"
    ci.dmenv.run("python", "setup.py", *args, env=env, cwd=src_path)


def build(*, workspace: Path, src: str, profile: str) -> None:
    ci.git.prepare_sources(
        workspace=workspace, repos=["python", "sdk-native"], submodule=False, clean=True
    )
    with workspace / "sdk-native":
        builder = ci.cpp.Builder(profile=profile, bindings=True, coverage=False)
        builder.install_deps()
        builder.build()

    python_src_path = workspace / "python"
    ci.dmenv.install(cwd=python_src_path, develop=False)
    run_setup_py(python_src_path, profile, "develop")


def check(*, cwd: Path) -> None:
    ci.dmenv.run("pytest", "--verbose", "--capture=no", cwd=cwd)
    env = os.environ.copy()
    env["MYPYPATH"] = cwd / "stubs"
    ci.dmenv.run(
        "mypy", "--strict", "--ignore-missing-imports", "tankersdk", "test", cwd=cwd, env=env,
    )
    ci.dmenv.run("flake8", ".")


def deploy(*, cwd: Path, profile: str) -> None:
    run_setup_py(cwd, profile, "bdist_wheel")
    build_dir = cwd / "dist"
    wheels = build_dir.files("tankersdk-*.whl")
    if len(wheels) != 1:
        raise Exception("multiple wheels found: {}".format(wheels))
    wheel = wheels[0]
    ci.run("scp", wheel, "pypi@10.100.0.1:packages")


def runner(steps: List[str], profile: str) -> None:
    workspace = Path("~/work").expanduser()
    src = Path.abspath(Path(__file__)).parent
    python_repo = workspace / "python"
    build(workspace=workspace, src=src, profile=profile)
    if "check" in steps:
        check(cwd=python_repo)
    if "deploy" in steps:
        deploy(cwd=python_repo, profile=profile)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("steps", nargs="+", choices=["check", "deploy"])
    parser.add_argument("--runner", required=True)
    args = parser.parse_args()
    if args.runner == "linux":
        profile = "gcc8"
    elif args.runner == "macos":
        profile = "macos"
    runner(args.steps, profile)


if __name__ == "__main__":
    main()
