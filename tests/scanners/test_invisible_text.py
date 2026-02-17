"""Tests for the InvisibleTextScanner."""

from llm_io_guard.models import Action
from llm_io_guard.scanners.invisible_text import InvisibleTextScanner


async def test_clean_text_passes():
    scanner = InvisibleTextScanner()
    result = await scanner.scan("Hello, this is clean text.")
    assert result.action == Action.PASS
    assert result.description == "No invisible characters detected"
    assert result.details["sanitized_content"] == "Hello, this is clean text."


async def test_zero_width_characters_stripped():
    text = "Hello\u200bWorld"  # zero-width space
    scanner = InvisibleTextScanner()
    result = await scanner.scan(text)
    assert result.action == Action.PASS
    assert result.details["sanitized_content"] == "HelloWorld"
    assert "Stripped" in result.description


async def test_rtl_override_stripped():
    text = "Hello\u202eWorld"  # RTL override
    scanner = InvisibleTextScanner()
    result = await scanner.scan(text)
    assert result.action == Action.PASS
    assert result.details["sanitized_content"] == "HelloWorld"


async def test_many_invisible_chars_flagged():
    # More than 10 invisible chars should FLAG
    text = "Hello" + "\u200b" * 20 + "World"
    scanner = InvisibleTextScanner()
    result = await scanner.scan(text)
    assert result.action == Action.FLAG
    assert result.details["invisible_char_count"] == 20
    assert result.details["sanitized_content"] == "HelloWorld"


async def test_tag_characters_stripped():
    # Unicode tag characters U+E0001 - U+E007F
    text = "Normal\U000e0001\U000e0041\U000e007fText"
    scanner = InvisibleTextScanner()
    result = await scanner.scan(text)
    assert result.action == Action.PASS
    assert result.details["sanitized_content"] == "NormalText"


async def test_bom_stripped():
    text = "\ufeffHello World"  # BOM at start
    scanner = InvisibleTextScanner()
    result = await scanner.scan(text)
    assert result.action == Action.PASS
    assert result.details["sanitized_content"] == "Hello World"


async def test_variation_selectors_stripped():
    text = "A\ufe0fB\ufe01C"
    scanner = InvisibleTextScanner()
    result = await scanner.scan(text)
    assert result.details["sanitized_content"] == "ABC"


async def test_scanner_name_and_tier():
    scanner = InvisibleTextScanner()
    assert scanner.name == "invisible_text"
    assert scanner.tier == 1
