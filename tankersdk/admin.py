import attr

from _tanker import ffi
from _tanker import lib as tankerlib

from .ffi_helpers import str_to_c_string, c_string_to_str, wait_fut_or_raise


@attr.s
class App:
    name = attr.ib()  # type: str
    id = attr.ib()  # type: str
    private_key = attr.ib()  # type: str
    public_key = attr.ib()  # type: str


class Admin:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self._create_admin_obj()

    def _create_admin_obj(self) -> None:
        c_url = str_to_c_string(self.url)
        c_token = str_to_c_string(self.token)
        admin_fut = tankerlib.tanker_admin_connect(c_url, c_token)
        wait_fut_or_raise(admin_fut)
        c_voidp = tankerlib.tanker_future_get_voidptr(admin_fut)
        self._c_admin = ffi.cast("tanker_admin_t*", c_voidp)
        tankerlib.tanker_future_destroy(admin_fut)

    def create_app(self, name: str) -> App:
        c_name = str_to_c_string(name)
        app_fut = tankerlib.tanker_admin_create_app(self._c_admin, c_name)
        wait_fut_or_raise(app_fut)
        c_voidp = tankerlib.tanker_future_get_voidptr(app_fut)
        c_app = ffi.cast("tanker_app_descriptor_t*", c_voidp)
        app = App(
            name=name,
            id=c_string_to_str(c_app.id),
            public_key=c_string_to_str(c_app.public_key),
            private_key=c_string_to_str(c_app.private_key),
        )
        tankerlib.tanker_admin_app_descriptor_free(c_app)
        tankerlib.tanker_future_destroy(app_fut)
        return app

    def delete_app(self, app_id: str) -> None:
        delete_fut = tankerlib.tanker_admin_delete_app(
            self._c_admin, str_to_c_string(app_id)
        )
        wait_fut_or_raise(delete_fut)
        tankerlib.tanker_future_destroy(delete_fut)

    def get_verification_code(self, app_id: str, email: str) -> str:
        get_verif_fut = tankerlib.tanker_admin_get_verification_code(
            self._c_admin, str_to_c_string(app_id), str_to_c_string(email)
        )
        wait_fut_or_raise(get_verif_fut)
        c_voidp = tankerlib.tanker_future_get_voidptr(get_verif_fut)
        c_str = ffi.cast("char*", c_voidp)
        tankerlib.tanker_future_destroy(get_verif_fut)
        return c_string_to_str(c_str)

    def __del__(self) -> None:
        tankerlib.tanker_admin_destroy(self._c_admin)
