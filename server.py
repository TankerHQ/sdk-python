import flask
import path
import json

import tankersdk.usertoken

app = flask.Flask(__name__)
app.debug = True


def load_config():
    top_path = path.Path(".").abspath().parent
    return json.loads(top_path.joinpath("server-config.json").text())


@app.route("/")
def handle_request():
    request_args = flask.request.args
    user_id = request_args["userId"]
    password = request_args["password"]

    # Request must be authenticated
    if password != "password" + user_id:
        return "Authentication error", 401

    print("New request:", user_id)

    db_path = path.Path(user_id).with_suffix(".txt")
    if db_path.exists():
        print("Serving existing token")
        return db_path.text()
    else:
        print("Creating new user token")
        config = load_config()
        trustchain_id = config["trustchainId"]
        trustchain_private_key = config["trustchainPrivateKey"]
        user_token = tankersdk.usertoken.generate_user_token(
            trustchain_id, trustchain_private_key, user_id
        )
        db_path.write_text(user_token)
        return user_token
