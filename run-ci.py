import argparse
import os
from pathlib import Path
import sys
import shutil
from typing import List, Optional  # noqa

import tankerci
import tankerci.bump
import tankerci.conan
from tankerci.conan import TankerSource
import tankerci.git
import tankerci.gitlab

PUBLIC_REPOSITORY_URL = "https://gitlab.com/api/v4/projects/20920099/packages/pypi"


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
    tankerci.run("poetry", "install", cwd=Path.cwd())


def test() -> None:
    env = os.environ.copy()
    env["TANKER_SDK_DEBUG"] = "1"
    src_path = Path.cwd()
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
    dest_dir = Path.cwd() / "coverage"
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    shutil.copytree(coverage_dir, dest_dir)


def build_and_test(
    tanker_source: TankerSource, profile: str, tanker_ref: Optional[str] = None
) -> None:
    prepare(tanker_source, profile, False, tanker_ref)
    build()
    test()


def build_wheel(profile: str, version: str, tanker_ref: str) -> None:
    prepare(TankerSource.DEPLOYED, profile, False, tanker_ref)
    build()
    src_path = Path.cwd()
    tankerci.bump.bump_files(version)
    dist_path = src_path / "dist"
    if dist_path.exists():
        shutil.rmtree(dist_path)

    env = os.environ.copy()
    env["TANKER_PYTHON_SDK_SRC"] = str(src_path)
    # Note: poetry generates a temporary directory,
    # change the working directory there, creates a `setup.py`
    # from scratch (calling `build.py`) and runs it.
    # In the process, all the conan files generated in the
    # sources gets lost. We set this environment variable
    # so that they can be found even when the working directory
    # changes, and we make sure *all* paths used in build_tanker.py
    # are absolute
    tankerci.run("poetry", "build", env=env)
    wheels = list(dist_path.glob("tankersdk-*.whl"))
    if len(wheels) != 1:
        raise Exception("multiple wheels found: {}".format(wheels))


def deploy() -> None:
    env = os.environ.copy()
    env["TWINE_PASSWORD"] = env["GITLAB_TOKEN"]
    env["TWINE_USERNAME"] = env["GITLAB_USERNAME"]

    wheels_path = Path.cwd() / "dist"
    for wheel in wheels_path.glob("tankersdk-*.whl"):
        # fmt: off
        tankerci.run(
            "poetry", "run",
            "twine", "upload", str(wheel), "--repository-url", PUBLIC_REPOSITORY_URL,
            env=env,
        )
        # fmt: on


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
    command = args.command

    if args.home_isolation:
        tankerci.conan.set_home_isolation()
        tankerci.conan.update_config()
        if command in ("build-wheel", "build-and-test"):
            # Because of GitLab issue https://gitlab.com/gitlab-org/gitlab/-/issues/254323
            # the downstream deploy jobs will be triggered even if upstream has failed
            # By removing the cache we ensure that we do not use a
            # previously built (and potentially broken) release candidate to deploy a binding
            tankerci.conan.run("remove", "tanker/*", "--force")

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
            Path.cwd(), [f"origin/{args.branch}", f"origin/{fallback}"]
        )
        tankerci.git.reset(Path.cwd(), ref)
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
