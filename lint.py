import os
import subprocess
import sys

import ci
import ci.tanker_configs
import cli_ui as ui


class Check:
    def __init__(self, name, cmd, env=None):
        self.name = name
        self.cmd = ["dmenv", "run", "--", *cmd]
        self.ok = False
        self.env = env

    def run(self):
        ui.info_2(self.name)
        rc = subprocess.call(self.cmd, env=self.env)
        self.ok = rc == 0


def init_checks():
    res = list()

    def append_check(name, *cmd, env=None):
        res.append(Check(name, cmd, env=env))

    env = os.environ.copy()
    env["TANKER_CONFIG_NAME"] = "dev"
    env["TANKER_CONFIG_FILEPATH"] = ci.tanker_configs.get_path()
    env["MYPYPATH"] = "stubs"

    # fmt: off
    append_check(
        "black",
        "black", "--check", "tankersdk"
    )
    append_check(
        "mypy",
        "mypy", "--strict", "--ignore-missing-imports",
        "tankersdk", "test",
        env=env
    )
    append_check(
        "flake8",
        "flake8", ".",
        env=env
    )
    # fmt: on
    return res


def main():
    ui.info_1("Start checking project")
    all_checks = init_checks()
    check_list = sys.argv[1:]
    checks = all_checks
    if check_list:
        checks = [c for c in checks if c.name in check_list]
    for check in checks:
        check.run()
    failed_checks = [check for check in checks if not check.ok]
    if not failed_checks:
        ui.info(ui.check, "All checks have passed")
        return
    for check in failed_checks:
        ui.error(check.name, "failed")
    sys.exit(1)


if __name__ == "__main__":
    main()
