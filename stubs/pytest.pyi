# Note: we still need this file because we use
# pytest-asyncio, which is not typed.
from typing import Any, Callable, NoReturn, Type

AnyFunc = Callable[..., Any]

class Marker:
    @classmethod
    def xfail(cls, condition: bool = False, reason: str = "") -> AnyFunc: ...
    @staticmethod
    def asyncio(func: AnyFunc) -> AnyFunc: ...

mark = Marker()

def fixture(*args: Any, **kwargs: Any) -> AnyFunc: ...
def raises(error: Type[BaseException]) -> Any: ...
def fail(message: str) -> NoReturn: ...
