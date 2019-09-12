import attr

from _tanker_admin import lib
from _tanker_admin import ffi

from .ffi_helpers import FFIHelpers


ffihelpers = FFIHelpers(ffi, lib)


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
        c_url = ffihelpers.str_to_c_string(self.url)
        c_token = ffihelpers.str_to_c_string(self.token)
        admin_fut = lib.tanker_admin_connect(c_url, c_token)
        ffihelpers.wait_fut_or_raise(admin_fut)
        c_voidp = lib.tanker_future_get_voidptr(admin_fut)
        self._c_admin = ffi.cast("tanker_admin_t*", c_voidp)
        lib.tanker_future_destroy(admin_fut)

    def create_app(self, name: str) -> App:
        c_name = ffihelpers.str_to_c_string(name)
        app_fut = lib.tanker_admin_create_app(self._c_admin, c_name)
        ffihelpers.wait_fut_or_raise(app_fut)
        c_voidp = lib.tanker_future_get_voidptr(app_fut)
        c_app = ffi.cast("tanker_app_descriptor_t*", c_voidp)
        app = App(
            name=name,
            id=ffihelpers.c_string_to_str(c_app.id),
            public_key=ffihelpers.c_string_to_str(c_app.public_key),
            private_key=ffihelpers.c_string_to_str(c_app.private_key),
        )
        lib.tanker_admin_app_descriptor_free(c_app)
        lib.tanker_future_destroy(app_fut)
        return app

    def delete_app(self, app_id: str) -> None:
        delete_fut = lib.tanker_admin_delete_app(
            self._c_admin, ffihelpers.str_to_c_string(app_id)
        )
        ffihelpers.wait_fut_or_raise(delete_fut)
        lib.tanker_future_destroy(delete_fut)

    def get_verification_code(self, app_id: str, email: str) -> str:
        get_verif_fut = lib.tanker_admin_get_verification_code(
            self._c_admin,
            ffihelpers.str_to_c_string(app_id),
            ffihelpers.str_to_c_string(email),
        )
        ffihelpers.wait_fut_or_raise(get_verif_fut)
        c_voidp = lib.tanker_future_get_voidptr(get_verif_fut)
        c_str = ffi.cast("char*", c_voidp)
        lib.tanker_future_destroy(get_verif_fut)
        return ffihelpers.c_string_to_str(c_str)

    def __del__(self) -> None:
        lib.tanker_admin_destroy(self._c_admin)
