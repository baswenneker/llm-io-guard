"""Adversarial tests for multilingual content handling.

Verifies that Tier 1 scanners do not incorrectly flag legitimate
Dutch, English, and mixed-language content.
"""

import pytest

from llm_io_guard.models import Action
from llm_io_guard.scanners.html_sanitizer import HtmlSanitizer
from llm_io_guard.scanners.invisible_text import InvisibleTextScanner

DUTCH_TEXTS = [
    "Beste klant, bedankt voor uw bestelling. Uw pakket wordt morgen bezorgd.",
    "De vergadering is verplaatst naar dinsdag 14:00 uur.",
    "Graag ontvangen wij uw reactie op dit voorstel voor het einde van de week.",
    "Het financiele overzicht van het derde kwartaal is bijgevoegd.",
    "Wij bevestigen hierbij de ontvangst van uw klacht en nemen contact met u op.",
]

ENGLISH_TEXTS = [
    "Thank you for your order. Your package will be delivered tomorrow.",
    "The meeting has been moved to Tuesday at 2:00 PM.",
    "Please send us your feedback on this proposal by end of week.",
    "The financial overview for Q3 is attached to this email.",
    "We confirm receipt of your complaint and will contact you shortly.",
]

MIXED_TEXTS = [
    "Hi team, de deadline voor het project is Friday. Please check de requirements.",
    "Het Q3 report is klaar. Shall I send it naar de stakeholders?",
    "We moeten de API endpoints updaten before the next sprint.",
    "De meeting met het development team is at 3 PM in room 201.",
]


@pytest.mark.adversarial
class TestDutchContentPassesTier1:
    """Test that normal Dutch content passes Tier 1 scanners cleanly."""

    async def test_dutch_text_passes_invisible_text(self):
        """Normal Dutch text should pass InvisibleTextScanner."""
        scanner = InvisibleTextScanner()
        for text in DUTCH_TEXTS:
            result = await scanner.ascan(text)
            assert result.action == Action.PASS, f"Dutch text incorrectly flagged: {text[:50]}"

    async def test_dutch_text_passes_html_sanitizer(self):
        """Normal Dutch text should pass HtmlSanitizer as plain text."""
        scanner = HtmlSanitizer()
        for text in DUTCH_TEXTS:
            result = await scanner.ascan(text)
            assert result.action == Action.PASS, f"Dutch text incorrectly flagged: {text[:50]}"

    async def test_dutch_with_special_chars(self):
        """Dutch text with diacritics and special characters should pass."""
        scanner = InvisibleTextScanner()
        special_dutch = [
            "De informatie is beschikbaar via onze website.",
            "Coordinerend: mevrouw Muller-de Vries.",
            "Cafe, creme brulee, naive, resume.",
        ]
        for text in special_dutch:
            result = await scanner.ascan(text)
            assert result.action == Action.PASS


@pytest.mark.adversarial
class TestEnglishContentPassesTier1:
    """Test that normal English content passes Tier 1 scanners cleanly."""

    async def test_english_text_passes_invisible_text(self):
        """Normal English text should pass InvisibleTextScanner."""
        scanner = InvisibleTextScanner()
        for text in ENGLISH_TEXTS:
            result = await scanner.ascan(text)
            assert result.action == Action.PASS, f"English text incorrectly flagged: {text[:50]}"

    async def test_english_text_passes_html_sanitizer(self):
        """Normal English text should pass HtmlSanitizer."""
        scanner = HtmlSanitizer()
        for text in ENGLISH_TEXTS:
            result = await scanner.ascan(text)
            assert result.action == Action.PASS, f"English text incorrectly flagged: {text[:50]}"


@pytest.mark.adversarial
class TestMixedLanguageContentPassesTier1:
    """Test that mixed Dutch/English content passes Tier 1 scanners."""

    async def test_mixed_text_passes_invisible_text(self):
        """Mixed language text should pass InvisibleTextScanner."""
        scanner = InvisibleTextScanner()
        for text in MIXED_TEXTS:
            result = await scanner.ascan(text)
            assert result.action == Action.PASS, f"Mixed text incorrectly flagged: {text[:50]}"

    async def test_mixed_text_passes_html_sanitizer(self):
        """Mixed language text should pass HtmlSanitizer."""
        scanner = HtmlSanitizer()
        for text in MIXED_TEXTS:
            result = await scanner.ascan(text)
            assert result.action == Action.PASS, f"Mixed text incorrectly flagged: {text[:50]}"


@pytest.mark.adversarial
class TestUnicodeLanguageCharacters:
    """Test that valid Unicode characters from various languages pass."""

    async def test_emoji_in_text_passes(self):
        """Text with emoji should pass (emoji are not invisible characters)."""
        scanner = InvisibleTextScanner()
        texts = [
            "Great job! \U0001f44d",
            "Meeting at 3pm \u2615",
            "Task complete \u2705",
        ]
        for text in texts:
            result = await scanner.ascan(text)
            assert result.action == Action.PASS

    async def test_accented_characters_pass(self):
        """Accented characters common in European languages should pass."""
        scanner = InvisibleTextScanner()
        texts = [
            "Rene, Noel, resume, cafe",
            "Uber, Munchen, Strae",
            "Cliches, naive, vis-a-vis",
        ]
        for text in texts:
            result = await scanner.ascan(text)
            assert result.action == Action.PASS
