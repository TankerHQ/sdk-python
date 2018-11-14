import argparse
import os

from path import Path

import ci
import ci.cpp
import ci.dmenv
import ci.git


def run_setup_py(src_path, *args):
    env = os.environ.copy()
    env["TANKER_NATIVE_BUILD_PATH"] = "../Native/build/gcc8/x86_64/Release"
    ci.dmenv.run("python", "setup.py", *args, env=env, cwd=src_path)


def build(*, workspace, src):
    ci.git.prepare_sources(
        workspace=workspace, repos=["python", "Native"], submodule=False, clean=True
    )
    with workspace / "Native":
        builder = ci.cpp.Builder(profile="gcc8", bindings=True, coverage=False)
        builder.install_deps()
        builder.build()

    python_src_path = workspace / "python"
    ci.dmenv.install(cwd=python_src_path, develop=False)
    run_setup_py(python_src_path, "develop")


def test(*, cwd):
    ci.dmenv.run("pytest", "-s", cwd=cwd)


def deploy(*, cwd):
    run_setup_py(cwd, "bdist_wheel")
    build_dir = cwd / "dist"
    wheels = build_dir.files("tankersdk-*.whl")
    if len(wheels) != 1:
        raise Exception("multiple wheels found: {}".format(wheels))
    wheel = wheels[0]
    ci.run("scp", wheel, "pypi@10.100.0.1:packages")


def runner(steps):
    workspace = Path("~/work").expanduser()
    src = Path.abspath(Path(__file__)).parent
    python_repo = workspace / "python"
    build(workspace=workspace, src=src)
    if "test" in steps:
        test(cwd=python_repo)
    if "deploy" in steps:
        deploy(cwd=python_repo)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("steps", nargs="+", choices=["test", "deploy"])
    args = parser.parse_args()
    runner(args.steps)


if __name__ == "__main__":
    main()
