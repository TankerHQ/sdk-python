from typing import Dict
import argparse
import asyncio
import json

from path import Path
from tankersdk.core import Tanker


def load_config(cfg_path: Path) -> Dict[str, str]:
    return json.loads(cfg_path.text())  # type: ignore


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("user_id")
    parser.add_argument("-c", "--config", required=True, type=Path)
    parser.add_argument("--storage-path", default="")
    args = parser.parse_args()
    user_id = args.user_id
    storage_path = args.storage_path
    trustchain_config = load_config(args.config)

    tanker = Tanker(
        trustchain_config["trustchainId"],
        trustchain_url=trustchain_config.get("url"),
        writable_path=storage_path,
    )
    token = tanker.generate_user_token(
        trustchain_config["trustchainPrivateKey"], user_id
    )

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
