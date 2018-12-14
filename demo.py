from typing import Any, Dict
import argparse
import asyncio
import json
import requests
import sys

from path import Path
from tankersdk.core import Tanker


SERVER_URL = "http://127.0.0.1:8080"


def load_config(cfg_path: Path) -> Dict[str, str]:
    return json.loads(cfg_path.text())  # type: ignore


def do_request(method: str, segment: str, **kwargs: Any) -> requests.Response:
    return requests.request(method, f"{SERVER_URL}/{segment}", **kwargs)


async def open_session(email: str, password: str, signup: bool = False) -> Tanker:
    storage_path = Path("~/.local/share/tanker").expanduser() / email
    storage_path.makedirs_p()

    config = do_request("get", "config").json()
    tanker = Tanker(
        config["trustchainId"], trustchain_url=config["url"], writable_path=storage_path
    )

    if signup:
        res = do_request("post", "signup", json={"email": email, "password": password})
        if not res.ok:
            sys.exit(f"Could not signup: {res.text}")
    else:
        res = do_request("post", "login", json={"email": email, "password": password})
        if not res.ok:
            sys.exit(f"Could not login: {res.text}")

    token = res.json()["token"]
    user_id = res.json()["id"]
    await tanker.open(user_id, token)
    return tanker


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("email")
    parser.add_argument("--signup", action="store_true")
    parser.add_argument("--password", required=True)

    subparsers = parser.add_subparsers(title="subcommands", dest="command")
    encrypt_parser = subparsers.add_parser("encrypt")
    encrypt_parser.add_argument("-o", "--output", required=True)

    decrypt_parser = subparsers.add_parser("decrypt")
    decrypt_parser.add_argument("input")

    args = parser.parse_args()
    email = args.email
    password = args.password
    signup = args.signup
    command = args.command

    if not command:
        parser.print_help()
        sys.exit(1)

    print("Opening session ...")
    tanker = await open_session(email, password=password, signup=signup)
    print("Done!")

    if args.command == "encrypt":
        message = input("Please enter your message below:\n")
        input_bytes = message.encode()
        encrypted = await tanker.encrypt(input_bytes)
        output_path = Path(args.output)
        output_path.write_bytes(encrypted)
        print("Encrypted data written to", output_path)
    elif args.command == "decrypt":
        print("Decryting", args.input, "...")
        input_path = Path(args.input)
        encrypted = input_path.bytes()
        clear = await tanker.decrypt(encrypted)
        print(clear.decode())

    await tanker.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
