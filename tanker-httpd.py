import asyncio
import sanic
from faker import Faker

TRUSTCHAIN_URL = "https://dev-api.tanker.io"
TRUSTCHAIN_ID = "AwRG5DLBtZUf3nwKKBnPI/Ijkt6SEN+oxjXHMotvKE8="
TRUSTCHAIN_PRIVATE_KEY = "Lfqexr+88qJuSyOaPXOwOXohKRpXvtPHreGydG5DYP+xmhAiKnmfuZQqtfOjbIfyh2hykzM9Bog+RO3Nh5OSdA=="  # noqa
fake = Faker()
USER_ID = user_id = fake.email()

from tankersdk.core import Tanker
from tankersdk.core import Status as TankerStatus

app = sanic.Sanic(__name__)

g_tanker = None

async def ensure_open_tanker():
    if g_tanker.status != TankerStatus.OPEN:
        print("trying to open")
        token = g_tanker.generate_user_token(USER_ID)
        await g_tanker.open(USER_ID, token)
        print("tanker is open")


@app.route("/")
def index(request):
    return "welcome: using tanker version %s" % g_tanker.version

@app.route("/healthz")
def healthz(request):
    return "tanker-httpd python healthy"

@app.route("/v1/encrypt", methods=["POST"])
async def encrypt(request):
    await ensure_open_tanker()
    encrypted = await g_tanker.encrypt(request.body)
    return sanic.response.raw(encrypted)

@app.route("/v1/decrypt", methods=["POST"])
async def decrypt(request):
    await ensure_open_tanker()
    decrypted = await g_tanker.decrypt(request.body)
    return sanic.response.raw(decrypted)

def main():
    tanker = Tanker(
        trustchain_url=TRUSTCHAIN_URL,
        trustchain_id=TRUSTCHAIN_ID,
        trustchain_private_key=TRUSTCHAIN_PRIVATE_KEY,
        writable_path="/home/dmerej/.local/share/tanker/python",
    )
    global g_tanker
    g_tanker= tanker
    app.run(host="127.0.0.1", port=1234)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
