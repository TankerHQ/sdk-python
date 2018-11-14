import argparse
import asyncio

from tanker import Tanker


TRUSTCHAIN_URL = "https://dev-api.tanker.io"
TRUSTCHAIN_ID = "Lj93QRsF4aadPoT/abm/ZUS1YqC5StX+B326stEeiT8="
TRUSTCHAIN_PRIVATE_KEY = "TZEIID4mTQta0xtLSNzh/mejX1SOjLb4l8tLCbORHpk29v9yEMS7uk0s9GlbPtuqn5+morIna1Op2F8Y6uTl2Q=="  # noqa




async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("user_id")
    parser.add_argument("--storage-path", default="")
    args = parser.parse_args()
    user_id = args.user_id
    storage_path = args.storage_path

    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path=storage_path,
    )
    token = tanker.generate_user_token(user_id)

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
