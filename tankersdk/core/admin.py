import attr

from _tanker import ffi
from _tanker import lib as tankerlib

from .ffi_helpers import str_to_c_string, c_string_to_str, wait_fut_or_raise


@attr.s
class Trustchain:
    name = attr.ib()
    id = attr.ib()
    private_key = attr.ib()
    public_key = attr.ib()


class Admin:
    def __init__(self, url, token):
        self.url = url
        self.token = token
        self._create_admin_obj()

    def _create_admin_obj(self):
        c_url = str_to_c_string(self.url)
        c_token = str_to_c_string(self.token)
        admin_fut = tankerlib.tanker_admin_connect(c_url, c_token)
        wait_fut_or_raise(admin_fut)
        c_voidp = tankerlib.tanker_future_get_voidptr(admin_fut)
        self._c_admin = ffi.cast("tanker_admin_t*", c_voidp)
        tankerlib.tanker_future_destroy(admin_fut)

    def create_trustchain(self, name):
        c_name = str_to_c_string(name)
        trustchain_fut = tankerlib.tanker_admin_create_trustchain(self._c_admin, c_name)
        wait_fut_or_raise(trustchain_fut)
        c_voidp = tankerlib.tanker_future_get_voidptr(trustchain_fut)
        c_trustchain = ffi.cast("tanker_trustchain_descriptor_t*", c_voidp)
        trustchain = Trustchain(
            name=name,
            id=c_string_to_str(c_trustchain.id),
            public_key=c_string_to_str(c_trustchain.public_key),
            private_key=c_string_to_str(c_trustchain.private_key),
        )
        tankerlib.tanker_admin_trustchain_descriptor_free(c_trustchain)
        tankerlib.tanker_future_destroy(trustchain_fut)
        return trustchain

    def delete_trustchain(self, trustchain_id):
        delete_fut = tankerlib.tanker_admin_delete_trustchain(
            self._c_admin, str_to_c_string(trustchain_id)
        )
        wait_fut_or_raise(delete_fut)
        tankerlib.tanker_future_destroy(delete_fut)