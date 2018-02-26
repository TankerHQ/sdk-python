import base64
import json
import os
import struct

import pysodium

BLOCK_HASH_SIZE = 32
CHECK_HASH_BLOCK_SIZE = 16
USER_SECRET_SIZE = 32


def generate_user_token(trustchain_id, trustchain_private_key, user_id):
    trustchain_id_buf = base64.b64decode(trustchain_id)
    private_key_buf = base64.b64decode(trustchain_private_key)

    user_id_buff = user_id.encode() + trustchain_id_buf
    user_id = pysodium.crypto_generichash(user_id_buff, outlen=BLOCK_HASH_SIZE)

    e_public_key, e_secret_key = pysodium.crypto_sign_keypair()
    to_sign = e_public_key + user_id
    delegation_signature = pysodium.crypto_sign_detached(to_sign, private_key_buf)
    # FIXME: use secrets for Python >= 3.6
    random_buf = os.urandom(USER_SECRET_SIZE - 1)
    hashed = pysodium.crypto_generichash(random_buf + user_id, outlen=CHECK_HASH_BLOCK_SIZE)
    user_secret = random_buf + bytearray([hashed[0]])

    user_token = {
        "ephemeral_private_signature_key": base64.b64encode(e_secret_key).decode(),
        "ephemeral_public_signature_key": base64.b64encode(e_public_key).decode(),
        "user_id": base64.b64encode(user_id).decode(),
        "delegation_signature": base64.b64encode(delegation_signature).decode(),
        "user_secret": base64.b64encode(user_secret).decode(),
    }

    as_json = json.dumps(user_token)
    return base64.b64encode(as_json.encode()).decode()
