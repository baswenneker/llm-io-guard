"""Adversarial tests for PII edge cases, focusing on BSN validation."""

import pytest

from llm_io_guard.scanners.pii_detector import BsnRecognizer


@pytest.mark.adversarial
class TestBsnValidation:
    """Test the BSN 11-proef validator with various edge cases."""

    def setup_method(self):
        self.recognizer = BsnRecognizer()

    def test_valid_bsn_passes_11proef(self):
        """Known valid BSN numbers should pass the 11-proef checksum."""
        # 111222333: sum = 9*1+8*1+7*1+6*2+5*2+4*2+3*3+2*3-1*3
        #          = 9+8+7+12+10+8+9+6-3 = 66, 66 % 11 = 0
        assert self.recognizer.validate_result("111222333") is True

    def test_valid_bsn_with_dots(self):
        """BSN with dot notation should be validated after stripping dots."""
        assert self.recognizer.validate_result("111.22.2333") is True

    def test_invalid_bsn_fails_11proef(self):
        """Invalid BSN numbers should fail the 11-proef checksum."""
        assert self.recognizer.validate_result("123456789") is False

    def test_all_zeros_fails(self):
        """All zeros BSN should fail (total == 0)."""
        assert self.recognizer.validate_result("000000000") is False

    def test_short_input_fails(self):
        """Input shorter than 9 digits should fail."""
        assert self.recognizer.validate_result("12345678") is False

    def test_long_input_fails(self):
        """Input longer than 9 digits should fail."""
        assert self.recognizer.validate_result("1234567890") is False

    def test_non_numeric_fails(self):
        """Non-numeric input should return False."""
        assert self.recognizer.validate_result("12345678a") is False

    def test_known_test_bsn_values(self):
        """Test a set of known valid/invalid BSN values."""
        # Valid: 999994669
        # sum = 9*9+8*9+7*9+6*9+5*9+4*4+3*6+2*6-1*9
        #     = 81+72+63+54+45+16+18+12-9 = 352, 352 % 11 = 0
        assert self.recognizer.validate_result("999994669") is True

        # Invalid: 999994668 (off by one)
        assert self.recognizer.validate_result("999994668") is False

    def test_bsn_with_dots_short_fails(self):
        """Dotted notation with wrong number of digits should fail."""
        assert self.recognizer.validate_result("11.22.333") is False
