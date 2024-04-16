# tanker_init() must be called once and before any session is created,
# so do it here at import time

from typing import cast

from _tanker import ffi
from _tanker import lib as tankerlib

from .error import Error, ErrorCode  # noqa

# fmt: off
from .tanker import (  # noqa
    AttachResult,
    E2ePassphraseVerification,
    E2ePassphraseVerificationMethod,
    EmailVerification,
    EmailVerificationMethod,
    EncryptionOptions,
    OidcAuthorizationCodeVerification,
    OidcIdTokenVerification,
    OidcIdTokenVerificationMethod,
    Padding,
    PassphraseVerification,
    PassphraseVerificationMethod,
    PhoneNumberVerification,
    PhoneNumberVerificationMethod,
    PreverifiedEmailVerification,
    PreverifiedEmailVerificationMethod,
    PreverifiedOIDCVerification,
    PreverifiedPhoneNumberVerification,
    PreverifiedPhoneNumberVerificationMethod,
    SharingOptions,
    Status,
    Stream,
    Tanker,
    Verification,
    VerificationKeyVerification,
    VerificationKeyVerificationMethod,
    VerificationMethod,
    VerificationMethodType,
    VerificationOptions,
    prehash_password,
)

# fmt: on
from .version import __version__  # noqa

tankerlib.tanker_init()


def native_version() -> str:
    c_native_version = tankerlib.tanker_version_string()
    native_version = cast(bytes, ffi.string(c_native_version))
    return native_version.decode()
