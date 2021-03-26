from enum import Enum


class ErrorCode(Enum):
    INVALID_ARGUMENT = 1
    INTERNAL_ERROR = 2
    NETWORK_ERROR = 3
    PRECONDITION_FAILED = 4
    OPERATION_CANCELED = 5

    DECRYPTION_FAILED = 6

    GROUP_TOO_BIG = 7

    INVALID_VERIFICATION = 8

    TOO_MANY_ATTEMPTS = 9
    EXPIRED_VERIFICATION = 10

    IO_ERROR = 11
    DEVICE_REVOKED = 12

    CONFLICT = 13
    UPGRADE_REQUIRED = 14


class Error(Exception):
    def __init__(self, message: str, code: ErrorCode):
        super().__init__(message)
        self.code = code


class InvalidArgument(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.INVALID_ARGUMENT)


class InternalError(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.INTERNAL_ERROR)


class NetworkError(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.NETWORK_ERROR)


class PreconditionFailed(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.PRECONDITION_FAILED)


class OperationCanceled(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.OPERATION_CANCELED)


class DecryptionFailed(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.DECRYPTION_FAILED)


class GroupTooBig(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.GROUP_TOO_BIG)


class InvalidVerification(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.INVALID_VERIFICATION)


class TooManyAttempts(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.TOO_MANY_ATTEMPTS)


class ExpiredVerification(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.EXPIRED_VERIFICATION)


class DeviceRevoked(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.DEVICE_REVOKED)


class Conflict(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.CONFLICT)


class UpgradeRequired(Error):
    def __init__(self, message: str):
        super().__init__(message, ErrorCode.UPGRADE_REQUIRED)


def make_error(message: str, code: ErrorCode) -> Error:
    error_map = {
        ErrorCode.INVALID_ARGUMENT: InvalidArgument,
        ErrorCode.INTERNAL_ERROR: InternalError,
        ErrorCode.NETWORK_ERROR: NetworkError,
        ErrorCode.PRECONDITION_FAILED: PreconditionFailed,
        ErrorCode.OPERATION_CANCELED: OperationCanceled,
        ErrorCode.DECRYPTION_FAILED: DecryptionFailed,
        ErrorCode.GROUP_TOO_BIG: GroupTooBig,
        ErrorCode.INVALID_VERIFICATION: InvalidVerification,
        ErrorCode.TOO_MANY_ATTEMPTS: TooManyAttempts,
        ErrorCode.EXPIRED_VERIFICATION: ExpiredVerification,
        ErrorCode.DEVICE_REVOKED: DeviceRevoked,
        ErrorCode.CONFLICT: Conflict,
        ErrorCode.UPGRADE_REQUIRED: UpgradeRequired,
    }
    constructor = error_map.get(code, None)
    if not constructor:
        return InternalError(f"unknown error: {code}: {message}")
    return constructor(message)
