from typing import Any, List
import argparse
import asyncio
import requests
import sys

from path import Path
from tankersdk import Tanker


SERVER_URL = "http://127.0.0.1:8080"


def do_request(
    session: requests.Session, method: str, segment: str, **kwargs: Any
) -> requests.Response:
    full_url = f"{SERVER_URL}/{segment}"
    func = getattr(session, method)
    return func(full_url, **kwargs)  # type: ignore


async def open_tanker_session(
    requests_session: requests.Session, email: str, password: str, signup: bool = False
) -> Tanker:
    storage_path = Path("~/.local/share/tanker").expanduser() / email
    storage_path.makedirs_p()

    config = do_request(requests_session, "get", "config").json()
    config.setdefault("url", "https://api.tanker.io")
    tanker = Tanker(
        config["trustchainId"], trustchain_url=config["url"], writable_path=storage_path
    )

    if signup:
        res = do_request(
            requests_session,
            "post",
            "signup",
            json={"email": email, "password": password},
        )
        if not res.ok:
            sys.exit(f"Could not signup: {res.text}")

        identity = res.json()["identity"]
        await tanker.sign_up(identity)
    else:
        res = do_request(
            requests_session,
            "post",
            "login",
            json={"email": email, "password": password},
        )
        if not res.ok:
            sys.exit(f"Could not login: {res.text}")

        identity = res.json()["identity"]
        await tanker.sign_in(identity)

    return tanker


def get_user_ids(requests_session: requests.Session, emails: List[str]) -> List[str]:
    all_users = do_request(requests_session, "get", "users").json()
    by_email = dict([(x["email"], x["id"]) for x in all_users])
    return [by_email[x] for x in emails]


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("email")
    parser.add_argument("--password", required=True)

    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    subparsers.add_parser("signup")

    encrypt_parser = subparsers.add_parser("encrypt")
    encrypt_parser.add_argument("-i", "--input", required=True)
    encrypt_parser.add_argument("-o", "--output", required=True)
    encrypt_parser.add_argument("--user", action="append", dest="users")

    decrypt_parser = subparsers.add_parser("decrypt")
    decrypt_parser.add_argument("-i", "--input", required=True)
    decrypt_parser.add_argument("-o", "--output", required=True)

    args = parser.parse_args()
    email = args.email
    password = args.password
    command = args.command

    if not command:
        parser.print_help()
        sys.exit(1)

    requests_session = requests.Session()

    if args.command == "signup":
        print("Creating new user")
        await open_tanker_session(
            requests_session, email, password=password, signup=True
        )
        print("OK")
        return

    print("Opening new session")
    tanker = await open_tanker_session(
        requests_session, email, password=password, signup=False
    )
    print("Done!")

    if args.command == "encrypt":
        user_emails = args.users or list()
        user_ids = get_user_ids(requests_session, user_emails)
        input_path = Path(args.input)
        input_bytes = input_path.bytes()
        print("Encrypting", args.input, "...")
        encrypted = await tanker.encrypt(input_bytes, share_with_users=user_ids)
        output_path = Path(args.output)
        output_path.write_bytes(encrypted)
        print("Encrypted data written to", output_path)
    elif args.command == "decrypt":
        print("Decrypting", args.input, "...")
        input_path = Path(args.input)
        encrypted = input_path.bytes()
        clear = await tanker.decrypt(encrypted)
        output_path = Path(args.output)
        output_path.write_bytes(clear)
        print("Decrypted data written to", output_path)

    await tanker.sign_out()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
