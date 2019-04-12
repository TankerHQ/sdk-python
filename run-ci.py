import argparse
import os
import sys

from path import Path
import requests

import ci.cpp
import ci.git
import ci.sdk_python


def trigger_check(*, native_from_sources):
    ci_job_token = os.environ["CI_JOB_TOKEN"]
    project_id = os.environ["CI_PROJECT_ID"]
    ref = os.environ["CI_COMMIT_REF_NAME"]
    response = requests.post(
        f"http://tanker.local:8000/api/v4/projects/{project_id}/trigger/pipeline",
        data={
            "token": ci_job_token,
            "ref": ref,
            "variables[NATIVE_FROM_SOURCES]": str(native_from_sources),
        },
    )
    response.raise_for_status()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--isolate-conan-user-home",
        action="store_true",
        dest="home_isolation",
        default=False,
    )

    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    trigger_parser = subparsers.add_parser("trigger")
    trigger_parser.add_argument("--native-from-sources", action="store_true")

    subparsers.add_parser("mirror")

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--profile", required=True)

    deploy_parser = subparsers.add_parser("deploy")
    deploy_parser.add_argument("--profile", required=True)

    args = parser.parse_args()
    if args.home_isolation:
        ci.cpp.set_home_isolation()

    command = args.command

    if not command:
        parser.print_help()
        sys.exit(1)

    if command == "mirror":
        ci.git.mirror(github_url="git@github.com:TankerHQ/sdk-python")
        return

    if command == "trigger":
        native_from_sources = args.native_from_sources
        trigger_check(native_from_sources=native_from_sources)
        return

    profile = args.profile
    native_from_sources = os.environ["NATIVE_FROM_SOURCES"] == "True"
    if native_from_sources:
        workspace = ci.git.prepare_sources(repos=["sdk-native", "sdk-python"])
        python_src_path = workspace / "sdk-python"
    else:
        python_src_path = Path(".")

    python_ci = ci.sdk_python.CI(
        python_src_path, native_from_sources=native_from_sources, profile=profile
    )
    python_ci.build()
    if command == "check":
        python_ci.check()
    elif command == "deploy":
        python_ci.deploy()


if __name__ == "__main__":
    main()
