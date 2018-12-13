import asyncio
from _tanker import ffi
from _tanker import lib as tankerlib

from .error import Error


def str_to_c_string(text):
    return ffi.new("char[]", text.encode())


# Note: ffi.string returns a 'bytes' object
# despite its name, so let's wrap this
# in a better name
def c_string_to_bytes(c_data):
    return ffi.string(c_data)


def c_string_to_str(c_data, encoding="utf-8"):
    as_bytes = c_string_to_bytes(c_data)
    return as_bytes.decode(encoding=encoding)


def bytes_to_c_string(buffer):
    return ffi.new("char[]", buffer)


class CCharList:
    """ Helper to convert list of Python strings to a char*[] C array

    >>> my_list = CCharList["foo", "bar"]
    >>> my_list.data   # the char* array
    >>> my_list.size   # its size
    """

    def __init__(self, str_list):
        self._clist = None
        self.data = ffi.NULL
        self.size = 0
        if str_list:
            self._clist = [str_to_c_string(x) for x in str_list]  # Keep this alive
            self.data = ffi.new("char*[]", self._clist)
            self.size = len(str_list)


def c_fut_to_exception(c_fut):
    if tankerlib.tanker_future_has_error(c_fut):
        c_error = tankerlib.tanker_future_get_error(c_fut)
        # Error messages coming from C may contain invalid
        # UTF-8 sequences, so use 'latin-1' as a "lossless"
        # encoding:
        message = c_string_to_str(c_error.message, encoding="latin-1")
        print("error", message)
        return Error(message)


def ensure_no_error(c_fut):
    exception = c_fut_to_exception(c_fut)
    if exception:
        raise exception


def wait_fut_or_raise(c_fut):
    tankerlib.tanker_future_wait(c_fut)
    ensure_no_error(c_fut)


def unwrap_expected(c_expected, c_type):
    c_as_future = ffi.cast("tanker_future_t*", c_expected)
    ensure_no_error(c_as_future)
    c_voidp = tankerlib.tanker_future_get_voidptr(c_as_future)
    return ffi.cast(c_type, c_voidp)


async def handle_tanker_future(c_fut, handle_result=None):
    fut = asyncio.Future()
    loop = asyncio.get_event_loop()

    @ffi.callback("void*(tanker_future_t*, void*)")
    def then_callback(c_fut, p):
        exception = c_fut_to_exception(c_fut)

        async def set_result():
            if exception:
                fut.set_exception(exception)
            else:
                if handle_result:
                    res = handle_result()
                else:
                    res = None
                fut.set_result(res)

        asyncio.run_coroutine_threadsafe(set_result(), loop)

        return ffi.NULL

    tankerlib.tanker_future_then(c_fut, then_callback, ffi.NULL)
    return await fut
