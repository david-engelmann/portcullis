"""Type stubs for the portcullis Python package."""

from collections.abc import Callable
from os import PathLike
from typing import Any

__version__: str
DEFAULT_JUDGE_MODEL: str
JUDGE_MODELS: tuple[str, ...]

class PortcullisError(Exception): ...
class CallerError(PortcullisError): ...
class LogAppendError(PortcullisError): ...
class LogCorruptionError(PortcullisError): ...

def check(
    policy: Any,
    call: Any,
    log: str | PathLike[str],
    at: str,
    transport: Callable[[dict[str, Any]], str] | None = None,
) -> dict[str, Any]: ...
def read_log(log: str | PathLike[str]) -> list[dict[str, Any]]: ...
def audit_log(log: str | PathLike[str], sample: int) -> dict[str, Any]: ...
def detect_provider(model: str) -> str: ...
def format_provider_request(
    request: str | dict[str, Any],
    provider: str | None = None,
) -> str: ...
def normalize_provider_reply(
    raw_reply: str,
    provider: str | None = None,
    model: str | None = None,
) -> str: ...

__all__: list[str]
