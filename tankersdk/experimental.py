from _tanker import lib as tankerlib

from .tanker import OidcAuthorizationCodeVerification, Tanker, ffihelpers


async def authenticate_with_idp(
    tanker: Tanker, provider_id: str, cookie: str
) -> OidcAuthorizationCodeVerification:
    c_provider_id = ffihelpers.str_to_c_string(provider_id)
    c_cookie = ffihelpers.str_to_c_string(cookie)
    c_expected_verification = tankerlib.tanker_authenticate_with_idp(
        tanker.c_tanker, c_provider_id, c_cookie
    )

    c_verification = ffihelpers.unwrap_expected(
        c_expected_verification, "tanker_oidc_authorization_code_verification_t*"
    )
    c_authorization_code = c_verification.authorization_code
    c_state = c_verification.state

    authorization_code = ffihelpers.c_string_to_str(c_authorization_code)
    state = ffihelpers.c_string_to_str(c_state)

    tankerlib.tanker_free_authenticate_with_idp_result(c_verification)
    return OidcAuthorizationCodeVerification(provider_id, authorization_code, state)
