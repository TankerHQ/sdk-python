# tanker_init() must be called once and before any session is created,
# so do it here at import time

from typing import cast

from _tanker import ffi
from _tanker import lib as tankerlib

from .error import Error, ErrorCode  # noqa

# fmt: off
from .tanker import (  # noqa
    Tanker,

    prehash_password,

    AttachResult,
    Status,
    VerificationMethodType,
    Stream,

    Verification,
    EmailVerification,
    PassphraseVerification,
    OidcIdTokenVerification,
    VerificationKeyVerification,

    VerificationMethod,
    EmailVerificationMethod,
    PassphraseVerificationMethod,
    OidcIdTokenVerificationMethod,
    VerificationKeyVerificationMethod,
)
# fmt: on
from .version import __version__  # noqa


tankerlib.tanker_init()


def native_version() -> str:
    c_native_version = tankerlib.tanker_version_string()
    native_version = cast(bytes, ffi.string(c_native_version))
    return native_version.decode()
