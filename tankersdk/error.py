from enum import Enum


class ErrorCode(Enum):
    NO_ERROR = 0
    OTHER = 1
    INVALID_TANKER_STATUS = 2
    SERVER_ERROR = 3
    INVALID_ARGUMENT = 4
    RESOURCE_KEY_NOT_FOUND = 5
    USER_NOT_FOUND = 6
    DECRYPT_FAILED = 7
    INVALID_UNLOCK_KEY = 8
    INTERNAL_ERROR = 9
    INVALID_UNLOCK_PASSWORD = 10
    INVALID_VERIFICATION_CODE = 11
    UNLOCK_KEY_ALREADY_EXISTS = 12
    MAX_VERIFICATION_ATTEMPTS_REACHED = 13
    INVALID_GROUP_SIZE = 14
    RECIPIENT_NOT_FOUND = 15
    GROUP_NOT_FOUND = 16
    DEVICE_NOT_FOUND = 17
    IDENTITY_ALREADY_REGISTERED = 18
    OPERATION_CANCELED = 19
    NOTHING_TO_CLAIM = 20


class Error(Exception):
    def __init__(self, message: str, code: ErrorCode):
        super().__init__(message)
        self.code = code
