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


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("email")
    parser.add_argument("--signup", action="store_true")
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    email = args.email
    password = args.password
    signup = args.signup

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

    message = b"I love you"
    encrypted = await tanker.encrypt(message)
    decrypted = await tanker.decrypt(encrypted)

    if message == decrypted:
        print("ok")
    else:
        print(encrypted, "!=", decrypted)
    await tanker.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
