import argparse
import os

from path import Path

import ci


def build(*, workspace, src):
    ci.prepare_sources(
        workspace=workspace,
        repos=["python", "Native"],
        src=src,
        submodule=False,
        clean=True,
        )
    cwd = workspace / "Native"
    ci.pipenv_install(cwd=cwd)
    ci.pipenv_run("python", "ci/cpp.py", "update-conan-config", "--platform", "linux", cwd=cwd)
    ci.pipenv_run("python", "ci/cpp.py", "build-and-test", "--profile", "gcc8", "--bindings", cwd=cwd)
    cwd = workspace / "python"
    env = os.environ.copy()
    env["TANKER_NATIVE_BUILD_PATH"] = "../Native/build/gcc8/x86_64/Release"
    ci.pipenv_install(cwd=cwd)
    ci.pipenv_run("python", "setup.py", "clean", "develop", cwd=cwd, env=env)


def test(*, cwd):
    ci.pipenv_install("--dev", cwd=cwd)
    ci.pipenv_run("pytest", "-s", cwd=cwd)


def deploy(*, cwd):
    ci.pipenv_run("python", "setup.py", "bdist_wheel", cwd=cwd)
    build_dir = cwd / "dist"
    wheels = build_dir.files("tankersdk-*.whl")
    if len(wheels) != 1:
        raise Exception("multiple wheels found: {}".format(wheels))
    pypi_dir = Path("/opt/pypi")
    Path(wheels[0]).copy(pypi_dir)


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
