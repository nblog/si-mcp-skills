class PhUtilsError(ValueError):
    """A stable reason code that never exposes a raw MCP response."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise PhUtilsError(reason)


def unwrap(exception: BaseException) -> BaseException:
    while isinstance(exception, BaseExceptionGroup) and len(exception.exceptions) == 1:
        exception = exception.exceptions[0]
    return exception
