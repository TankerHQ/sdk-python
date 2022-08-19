import argparse
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import List, Optional  # noqa

import tankerci
import tankerci.bump
import tankerci.conan
import tankerci.gitlab
from tankerci.conan import Profile, TankerSource

PUBLIC_REPOSITORY_URL = "https://gitlab.com/api/v4/projects/20920099/packages/pypi"

build_profiles = {
    "linux-x86_64": "linux-x86_64",
    "darwin-x86_64": "macos-x86_64",
    "darwin-arm64": "macos-armv8",
    "win32-x86_64": "windows-x86_64",
}


def machine() -> str:
    machine = platform.machine().lower()
    if machine == "amd64":
        return "x86_64"
    return machine


def get_build_profile() -> Profile:
    arch = machine()
    return Profile(build_profiles[f"{sys.platform}-{arch}"])


def prepare(
    tanker_source: TankerSource,
    profile: Profile,
    update: bool,
    tanker_ref: Optional[str] = None,
) -> None:
    tanker_deployed_ref = tanker_ref
    if tanker_source == TankerSource.DEPLOYED and not tanker_ref:
        tanker_deployed_ref = "tanker/latest-stable@"
    tankerci.conan.install_tanker_source(
        tanker_source,
        output_path=Path("conan") / "out",
        host_profiles=[profile],
        build_profile=get_build_profile(),
        update=update,
        tanker_deployed_ref=tanker_deployed_ref,
    )


def build_wheel(profile: Profile, version: str, tanker_ref: str) -> None:
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


def run_test() -> None:
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


def build(
    profile: Profile, release_version: Optional[str], tanker_ref: str, test: bool
) -> None:
    tankerci.run("poetry", "install", cwd=Path.cwd())
    if release_version:
        build_wheel(profile, release_version, tanker_ref)
    if test:
        run_test()


def deploy() -> None:
    env = os.environ.copy()
    env["TWINE_PASSWORD"] = env["GITLAB_TOKEN"]
    env["TWINE_USERNAME"] = env["GITLAB_USERNAME"]

    wheels_path = Path.cwd() / "dist"
    wheels = list(wheels_path.glob("tankersdk-*.whl"))
    if len(wheels) == 0:
        raise Exception("no wheel found")
    for wheel in wheels:
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

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--profile", default="default", nargs="+")
    build_parser.add_argument("--tanker-ref")
    build_parser.add_argument("--test", action="store_true")
    build_parser.add_argument("--release")
    build_parser.add_argument("--remote", default="artifactory")

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument(
        "--use-tanker",
        type=TankerSource,
        default=TankerSource.EDITABLE,
        dest="tanker_source",
    )
    prepare_parser.add_argument("--profile", default="default", nargs="+")
    prepare_parser.add_argument("--tanker-ref")
    prepare_parser.add_argument(
        "--update",
        action="store_true",
        default=False,
        dest="update",
    )
    prepare_parser.add_argument("--remote", default="artifactory")

    download_artifacts_parser = subparsers.add_parser("download-artifacts")
    download_artifacts_parser.add_argument("--project-id", required=True)
    download_artifacts_parser.add_argument("--pipeline-id", required=True)
    download_artifacts_parser.add_argument("--job-name", required=True)

    subparsers.add_parser("deploy")

    args = parser.parse_args()
    command = args.command

    user_home = None
    if args.home_isolation:
        user_home = Path.cwd() / ".cache" / "conan" / args.remote
        if command == "prepare":
            # Because of GitLab issue https://gitlab.com/gitlab-org/gitlab/-/issues/254323
            # the downstream deploy jobs will be triggered even if upstream has failed
            # By removing the cache we ensure that we do not use a
            # previously built (and potentially broken) release candidate to deploy a binding
            tankerci.conan.run("remove", "tanker/*", "--force")

    if command == "build":
        with tankerci.conan.ConanContextManager([args.remote], conan_home=user_home):
            build(Profile(args.profile), args.release, args.tanker_ref, args.test)
    elif command == "prepare":
        with tankerci.conan.ConanContextManager([args.remote], conan_home=user_home):
            prepare(
                args.tanker_source, Profile(args.profile), args.update, args.tanker_ref
            )
    elif command == "deploy":
        deploy()
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
