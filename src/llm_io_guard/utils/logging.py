"""Structured logging configuration using structlog."""

import logging
import sys
from collections.abc import Callable
from contextvars import ContextVar
from functools import wraps
from time import perf_counter
from typing import Any, Literal

import structlog
from structlog.types import FilteringBoundLogger, Processor

# Context variable for request-scoped data
request_context: ContextVar[dict[str, Any]] = ContextVar("request_context", default={})  # noqa: B039


def configure_logging(
    level: str = "INFO",
    format: Literal["json", "console"] = "console",  # noqa: A002
) -> None:
    """Configure structured logging for the application.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format: Output format - 'json' for production, 'console' for development
    """
    # Configure Python's logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper()),
    )

    # Build processor chain
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if format == "json":
        # Production processors
        processors.extend(
            [
                structlog.processors.dict_tracebacks,
                structlog.processors.JSONRenderer(),
            ]
        )
    else:
        # Development processors with pretty console output
        processors.extend(
            [
                structlog.processors.add_log_level,
                structlog.dev.ConsoleRenderer(
                    colors=True,
                    exception_formatter=structlog.dev.plain_traceback,
                ),
            ]
        )

    # Configure structlog
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> FilteringBoundLogger:
    """Get a configured structlog logger.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


class log_context:  # noqa: N801
    """Context manager for adding structured context to logs.

    Example:
        with log_context(user_id=123, request_id="abc"):
            logger.info("processing_request")
    """

    def __init__(self, **kwargs: Any) -> None:
        self.context = kwargs
        self.token: Any | None = None

    def __enter__(self) -> "log_context":
        current = request_context.get()
        updated = {**current, **self.context}
        self.token = request_context.set(updated)
        structlog.contextvars.bind_contextvars(**self.context)
        return self

    def __exit__(self, *args: Any) -> None:
        if self.token:
            request_context.reset(self.token)
        structlog.contextvars.unbind_contextvars(*self.context.keys())


def log_execution_time(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to log function execution time.

    Example:
        @log_execution_time
        def process_data(data):
            # Process data
            return result
    """
    logger = get_logger(func.__module__)

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = perf_counter()
        logger.info(
            "function_start",
            function=func.__name__,
            module=func.__module__,
        )

        try:
            result = func(*args, **kwargs)
            elapsed = perf_counter() - start_time
            logger.info(
                "function_complete",
                function=func.__name__,
                module=func.__module__,
                duration_seconds=elapsed,
            )
            return result
        except Exception as e:
            elapsed = perf_counter() - start_time
            logger.error(
                "function_error",
                function=func.__name__,
                module=func.__module__,
                duration_seconds=elapsed,
                error=str(e),
                exc_info=True,
            )
            raise

    return wrapper


def log_exceptions(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to log exceptions with context.

    Example:
        @log_exceptions
        def risky_operation():
            # May raise exceptions
            pass
    """
    logger = get_logger(func.__module__)

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(
                "exception_caught",
                function=func.__name__,
                module=func.__module__,
                error=str(e),
                exc_info=True,
            )
            raise

    return wrapper
