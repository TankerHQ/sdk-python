import argparse
import sys


import ci.cpp
import ci.git
import ci.sdk_python


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--isolate-conan-user-home",
        action="store_true",
        dest="home_isolation",
        default=False
    )
    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--profile", required=True)

    deploy_parser = subparsers.add_parser("deploy")
    deploy_parser.add_argument("--profile", required=True)

    subparsers.add_parser("mirror")

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

    builder = ci.sdk_python.Builder(profile=args.profile)

    if args.profile != "windows":
        builder.build()

    if command == "check":
        builder.lint()
        builder.check()
    elif command == "deploy":
        builder.deploy()


if __name__ == "__main__":
    main()
