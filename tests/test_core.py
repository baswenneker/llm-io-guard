"""Tests for core module."""

from llm_io_guard.core import hello_world


class TestHelloWorld:
    """Tests for hello_world function."""
    
    def test_hello_world_returns_correct_message(self) -> None:
        """Test that hello_world returns the correct message."""
        result = hello_world()
        assert result == "Hello, World!"
    
    def test_hello_world_returns_string(self) -> None:
        """Test that hello_world returns a string."""
        result = hello_world()
        assert isinstance(result, str)