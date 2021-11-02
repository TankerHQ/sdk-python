import asyncio
from asyncio import Future
from typing import Any, Callable, List, Optional, cast

from .error import Error, ErrorCode, make_error

# mypy does not know ffi types, this is for documentation purposes only
CData = Any

_TANKER_CALLBACKS: List[Callable[..., Any]] = []

OptionalStrList = Optional[List[str]]


class FFIHelpers:
    def __init__(self, ffi: Any, lib: Any):
        self.ffi = ffi
        self.lib = lib

    def str_to_c_string(self, text: Optional[str]) -> CData:
        if text is None:
            return self.ffi.NULL
        return self.ffi.new("char[]", text.encode())

    # Note: ffi.string returns a 'bytes' object
    # despite its name, so let's wrap this
    # in a better name
    def c_string_to_bytes(self, c_data: CData) -> bytes:
        return cast(bytes, self.ffi.string(c_data))

    def c_buffer_to_bytes(self, c_data: CData) -> bytes:
        res = self.ffi.buffer(c_data, len(c_data))
        # Make a copy of the self.ffi.buffer as a simple `bytes`
        # object so that it can be used without worrying
        # about the self.ffi buffer being garbage collected.
        return cast(bytes, res[:])

    def c_string_to_str(self, c_data: CData, encoding: str = "utf-8") -> str:
        as_bytes = self.c_string_to_bytes(c_data)
        return as_bytes.decode(encoding=encoding)

    def bytes_to_c_string(self, buffer: bytes) -> CData:
        return self.ffi.new("char[]", buffer)

    def bytes_to_c_buffer(self, buffer: bytes) -> CData:
        size = len(buffer)
        return self.ffi.new("uint8_t[%i]" % size, buffer)

    def c_fut_to_exception(self, c_fut: CData) -> Optional[Error]:
        if self.lib.tanker_future_has_error(c_fut):
            c_error = self.lib.tanker_future_get_error(c_fut)
            # Error messages coming from C may contain invalid
            # UTF-8 sequences, so use 'latin-1' as a "lossless"
            # encoding:
            message = self.c_string_to_str(c_error.message, encoding="latin-1")
            return make_error(message, ErrorCode(c_error.code))
        else:
            return None

    def ensure_no_error(self, c_fut: CData) -> None:
        exception = self.c_fut_to_exception(c_fut)
        if exception:
            raise exception

    def wait_fut_or_raise(self, c_fut: CData) -> None:
        self.lib.tanker_future_wait(c_fut)
        self.ensure_no_error(c_fut)

    def unwrap_expected(self, c_expected: CData, c_type: str) -> CData:
        c_as_future = self.ffi.cast("tanker_future_t*", c_expected)
        self.ensure_no_error(c_as_future)
        c_voidp = self.lib.tanker_future_get_voidptr(c_as_future)
        return self.ffi.cast(c_type, c_voidp)

    async def handle_tanker_future(self, c_fut: CData) -> CData:
        fut = Future()  # type: Future[CData]
        loop = asyncio.get_event_loop()

        @self.ffi.callback("void*(tanker_future_t*, void*)")  # type: ignore
        def then_callback(c_fut: CData, p: CData) -> CData:
            exception = self.c_fut_to_exception(c_fut)

            # we use a future continuation lambda because `fut`
            # must not be accessed from outside the Python event loop
            if exception:
                cont = lambda: fut.set_exception(exception)
            else:
                res = self.lib.tanker_future_get_voidptr(c_fut)
                cont = lambda: fut.set_result(res)

            loop.run_in_executor(None, cont)
            _TANKER_CALLBACKS.remove(then_callback)
            return self.ffi.NULL

        _TANKER_CALLBACKS.append(then_callback)
        fut2 = self.lib.tanker_future_then(c_fut, then_callback, self.ffi.NULL)
        self.lib.tanker_future_destroy(fut2)
        self.lib.tanker_future_destroy(c_fut)
        return await fut


class CCharList:
    """
    Helper to convert list of Python strings to a char*[] C array

    >>> my_list = CCharList["foo", "bar"]
    >>> my_list.data   # the char* array
    >>> my_list.size   # its size
    """

    def __init__(self, str_list: OptionalStrList, ffi: Any, lib: Any):
        self._clist = None
        self.ffi = ffi
        self.ffihelpers = FFIHelpers(ffi, lib)
        self.data = self.ffi.NULL
        self.size = 0
        if str_list:
            self._clist = [
                self.ffihelpers.str_to_c_string(x) for x in str_list
            ]  # Keep this alive
            self.data = self.ffi.new("char*[]", self._clist)
            self.size = len(str_list)
