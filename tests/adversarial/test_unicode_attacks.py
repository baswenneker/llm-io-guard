"""Adversarial tests for Unicode and invisible text attacks."""

import pytest

from llm_io_guard.models import Action
from llm_io_guard.scanners.invisible_text import InvisibleTextScanner


@pytest.mark.adversarial
class TestZeroWidthInjection:
    """Test zero-width character injection attacks."""

    async def test_zero_width_space_stripped(self):
        """Zero-width spaces should be stripped from content."""
        scanner = InvisibleTextScanner()
        content = "Hello\u200bWorld"  # Zero-width space between words
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\u200b" not in sanitized
        assert "HelloWorld" in sanitized

    async def test_zero_width_joiner_stripped(self):
        """Zero-width joiners should be stripped."""
        scanner = InvisibleTextScanner()
        content = "test\u200dcontent"
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\u200d" not in sanitized

    async def test_zero_width_non_joiner_stripped(self):
        """Zero-width non-joiners should be stripped."""
        scanner = InvisibleTextScanner()
        content = "test\u200ccontent"
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\u200c" not in sanitized

    async def test_mass_zero_width_flagged(self):
        """Many zero-width characters should trigger FLAG."""
        scanner = InvisibleTextScanner()
        content = "Hello" + "\u200b" * 50 + "World"
        result = await scanner.scan(content)
        assert result.action == Action.FLAG
        assert result.details["invisible_char_count"] == 50


@pytest.mark.adversarial
class TestRtlOverride:
    """Test right-to-left override text hiding attacks."""

    async def test_rtl_override_stripped(self):
        """RTL override characters should be stripped."""
        scanner = InvisibleTextScanner()
        content = "Normal \u202eevil hidden text\u202c visible"
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\u202e" not in sanitized
        assert "\u202c" not in sanitized

    async def test_ltr_override_stripped(self):
        """LTR override characters should be stripped."""
        scanner = InvisibleTextScanner()
        content = "text \u202dhidden\u202c more"
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\u202d" not in sanitized

    async def test_directional_isolates_stripped(self):
        """Directional isolate characters should be stripped."""
        scanner = InvisibleTextScanner()
        content = "test \u2066hidden\u2069 content"
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\u2066" not in sanitized
        assert "\u2069" not in sanitized


@pytest.mark.adversarial
class TestTagCharacterHiding:
    """Test tag character hiding attacks."""

    async def test_tag_characters_stripped(self):
        """Unicode tag characters (U+E0001-U+E007F) should be stripped."""
        scanner = InvisibleTextScanner()
        # Build "HELLO" using tag characters (U+E0048 = tag H, etc.)
        tag_hello = "\U000e0048\U000e0045\U000e004c\U000e004c\U000e004f"
        content = f"Normal text{tag_hello}more text"
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\U000e0048" not in sanitized

    async def test_language_tag_stripped(self):
        """Language tag character U+E0001 should be stripped."""
        scanner = InvisibleTextScanner()
        content = "text\U000e0001more"
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\U000e0001" not in sanitized


@pytest.mark.adversarial
class TestBomSpam:
    """Test BOM (Byte Order Mark) spam attacks."""

    async def test_single_bom_stripped(self):
        """Single BOM character should be stripped."""
        scanner = InvisibleTextScanner()
        content = "\ufeffHello World"
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\ufeff" not in sanitized
        assert "Hello World" in sanitized

    async def test_bom_spam_flagged(self):
        """Many BOM characters should trigger FLAG."""
        scanner = InvisibleTextScanner()
        content = "\ufeff" * 20 + "Hidden message"
        result = await scanner.scan(content)
        assert result.action == Action.FLAG
        assert result.details["invisible_char_count"] >= 20


@pytest.mark.adversarial
class TestManyInvisibleCharsFlagged:
    """Test that large numbers of invisible characters trigger FLAG."""

    async def test_mixed_invisible_chars_flagged(self):
        """Mix of different invisible character types should be flagged."""
        scanner = InvisibleTextScanner()
        invisible = (
            "\u200b" * 5  # zero-width spaces
            + "\u200c" * 5  # zero-width non-joiners
            + "\u200d" * 5  # zero-width joiners
            + "\u200e" * 5  # LTR marks
            + "\ufeff" * 5  # BOMs
        )
        content = f"Normal{invisible}text"
        result = await scanner.scan(content)
        assert result.action == Action.FLAG
        assert result.details["invisible_char_count"] > 10

    async def test_c0_control_chars_stripped(self):
        """C0 control characters (except tab/newline/CR) should be stripped."""
        scanner = InvisibleTextScanner()
        content = "Hello\x01\x02\x03World"
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\x01" not in sanitized
        assert "\x02" not in sanitized
        assert "\x03" not in sanitized

    async def test_c1_control_chars_stripped(self):
        """C1 control characters should be stripped."""
        scanner = InvisibleTextScanner()
        content = "Hello\x80\x81\x82World"
        result = await scanner.scan(content)
        sanitized = result.details.get("sanitized_content", "")
        assert "\x80" not in sanitized

    async def test_clean_text_passes(self):
        """Normal text without invisible characters should pass cleanly."""
        scanner = InvisibleTextScanner()
        content = "This is perfectly normal text with no hidden characters."
        result = await scanner.scan(content)
        assert result.action == Action.PASS
        assert result.details.get("sanitized_content") == content
