"""Core functionality for LLM IO Guard."""

from utils import get_logger

logger = get_logger(__name__)


def hello_world() -> str:
    """Print hello world and return the message.

    Returns:
        The hello world message

    Example:
        >>> message = hello_world()
        >>> print(message)
        Hello, World!
    """
    message = "Hello, World!"
    logger.info("hello_world_called", message=message)
    print(message)
    return message
