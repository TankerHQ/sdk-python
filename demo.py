import argparse

from tanker import Tanker


TRUSTCHAIN_URL = "https://dev-api.tanker.io"
TRUSTCHAIN_ID = "Lj93QRsF4aadPoT/abm/ZUS1YqC5StX+B326stEeiT8="
TRUSTCHAIN_PRIVATE_KEY = "TZEIID4mTQta0xtLSNzh/mejX1SOjLb4l8tLCbORHpk29v9yEMS7uk0s9GlbPtuqn5+morIna1Op2F8Y6uTl2Q=="  # noqa


def on_waiting_for_validation(code):
    print("Please add device with the following code", code)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("user_id")
    parser.add_argument("--storage-path", default="")
    parser.add_argument("--validation-code")
    args = parser.parse_args()
    user_id = args.user_id
    validation_code = args.validation_code
    storage_path = args.storage_path

    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path=storage_path
    )
    tanker.on_waiting_for_validation = on_waiting_for_validation
    token = tanker.generate_user_token(user_id)

    tanker.open(user_id, token)
    if validation_code:
        tanker.accept_device(validation_code.encode())

    message = b"I love you"
    encrypted = tanker.encrypt(message)
    decrypted = tanker.decrypt(encrypted)

    if message == decrypted:
        print("ok")
    else:
        print(encrypted, "!=", decrypted)
    tanker.close()


if __name__ == "__main__":
    main()
