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


class Error(Exception):
    def __init__(self, message: str, code: ErrorCode):
        super().__init__(message)
        self.code = code
