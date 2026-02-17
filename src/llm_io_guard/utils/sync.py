"""Synchronous wrapper for async coroutines."""

import asyncio
from collections.abc import Coroutine


def run_sync[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously using asyncio.run().

    Args:
        coro: The coroutine to execute.

    Returns:
        The result of the coroutine.
    """
    return asyncio.run(coro)
