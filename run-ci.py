import argparse
import os
import sys

from path import Path
from typing import List, Optional  # noqa

import tankerci
import tankerci.bump
import tankerci.conan
from tankerci.conan import TankerSource
import tankerci.git
import tankerci.gitlab


def prepare(
    tanker_source: TankerSource,
    profile: str,
    update: bool,
    tanker_ref: Optional[str] = None,
) -> None:
    tanker_deployed_ref = tanker_ref
    if tanker_source == TankerSource.DEPLOYED and not tanker_ref:
        tanker_deployed_ref = "tanker/latest-stable@"
    tankerci.conan.install_tanker_source(
        tanker_source,
        output_path=Path("conan") / "out",
        profiles=[profile],
        update=update,
        tanker_deployed_ref=tanker_deployed_ref,
    )


def build() -> None:
    tankerci.run("poetry", "install", cwd=Path.getcwd())


def test() -> None:
    env = os.environ.copy()
    env["TANKER_SDK_DEBUG"] = "1"
    src_path = Path.getcwd()
    # fmt: off
    tankerci.run(
        "poetry", "run", "pytest",
        "--verbose",
        "--capture=no",
        "--cov=tankersdk",
        "--cov-report", "html",
        "--numprocesses", "auto",
        env=env,
        cwd=src_path,
    )
    # fmt: on
    coverage_dir = src_path / "htmlcov"
    dest_dir = Path.getcwd() / "coverage"
    dest_dir.rmtree_p()
    coverage_dir.copytree(dest_dir)


def build_and_test(
    tanker_source: TankerSource, profile: str, tanker_ref: Optional[str] = None
) -> None:
    prepare(tanker_source, profile, False, tanker_ref)
    build()
    test()


def build_wheel(profile: str, version: str, tanker_ref: str) -> None:
    prepare(TankerSource.DEPLOYED, profile, False, tanker_ref)
    build()
    src_path = Path.getcwd()
    # tankerci.bump.bump_files(version)
    dist_path = src_path / "dist"
    dist_path.rmtree_p()

    env = os.environ.copy()
    env["TANKER_PYTHON_SDK_SRC"] = src_path
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


def deploy() -> None:
    env = os.environ.copy()
    env["TWINE_PASSWORD"] = env["GITLAB_TOKEN"]
    env["TWINE_USERNAME"] = env["GITLAB_USERNAME"]
    repository = env["POETRY_REPOSITORIES_GITLAB_URL"]

    wheels_path = Path.getcwd() / "dist"
    for wheel in wheels_path.files("tankersdk-*.whl"):
        tankerci.run(
            "poetry",
            "run",
            "twine",
            "upload",
            "--repository-url",
            repository,
            wheel,
            env=env,
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--isolate-conan-user-home",
        action="store_true",
        dest="home_isolation",
        default=False,
    )

    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    build_and_test_parser = subparsers.add_parser("build-and-test")
    build_and_test_parser.add_argument(
        "--use-tanker",
        type=TankerSource,
        default=TankerSource.EDITABLE,
        dest="tanker_source",
    )
    build_and_test_parser.add_argument("--profile", default="default")
    build_and_test_parser.add_argument("--tanker-ref")

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument(
        "--use-tanker",
        type=TankerSource,
        default=TankerSource.EDITABLE,
        dest="tanker_source",
    )
    prepare_parser.add_argument("--profile", default="default")
    prepare_parser.add_argument("--tanker-ref")
    prepare_parser.add_argument(
        "--update", action="store_true", default=False, dest="update",
    )

    reset_branch_parser = subparsers.add_parser("reset-branch")
    reset_branch_parser.add_argument("branch")

    download_artifacts_parser = subparsers.add_parser("download-artifacts")
    download_artifacts_parser.add_argument("--project-id", required=True)
    download_artifacts_parser.add_argument("--pipeline-id", required=True)
    download_artifacts_parser.add_argument("--job-name", required=True)

    build_wheel_parser = subparsers.add_parser("build-wheel")
    build_wheel_parser.add_argument("--profile", required=True)
    build_wheel_parser.add_argument("--version", required=True)
    build_wheel_parser.add_argument("--tanker-ref", required=True)

    subparsers.add_parser("deploy")
    subparsers.add_parser("mirror")

    args = parser.parse_args()
    if args.home_isolation:
        tankerci.conan.set_home_isolation()
        tankerci.conan.update_config()

    command = args.command

    if command == "mirror":
        tankerci.git.mirror(github_url="git@github.com:TankerHQ/sdk-python")
    elif command == "build-wheel":
        build_wheel(args.profile, args.version, args.tanker_ref)
    elif command == "prepare":
        prepare(args.tanker_source, args.profile, args.update, args.tanker_ref)
    elif command == "build-and-test":
        build_and_test(args.tanker_source, args.profile, args.tanker_ref)
    elif command == "deploy":
        deploy()
    elif command == "reset-branch":
        fallback = os.environ["CI_COMMIT_REF_NAME"]
        ref = tankerci.git.find_ref(
            Path.getcwd(), [f"origin/{args.branch}", f"origin/{fallback}"]
        )
        tankerci.git.reset(Path.getcwd(), ref)
    elif command == "download-artifacts":
        tankerci.gitlab.download_artifacts(
            project_id=args.project_id,
            pipeline_id=args.pipeline_id,
            job_name=args.job_name,
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
