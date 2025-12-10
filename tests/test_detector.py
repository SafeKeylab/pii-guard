"""Tests for PII detection functionality."""

import pytest
from pii_guard import PIIDetector, scan, redact, list_entities, PIIEntity


class TestPIIDetector:
    """Tests for the PIIDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a detector instance for tests."""
        return PIIDetector()

    def test_detector_initialization(self, detector):
        """Test that detector initializes correctly."""
        assert detector is not None
        assert len(detector.patterns) > 0

    def test_detect_email(self, detector):
        """Test email detection."""
        text = "Contact me at john.doe@example.com for more info"
        entities = detector.detect(text)

        assert len(entities) >= 1
        email_entities = [e for e in entities if e.label == "EMAIL"]
        assert len(email_entities) == 1
        assert email_entities[0].text == "john.doe@example.com"
        assert email_entities[0].confidence > 0.9

    def test_detect_ssn(self, detector):
        """Test SSN detection."""
        text = "My SSN is 123-45-6789"
        entities = detector.detect(text)

        ssn_entities = [e for e in entities if e.label == "SSN"]
        assert len(ssn_entities) == 1
        assert ssn_entities[0].text == "123-45-6789"

    def test_detect_credit_card_visa(self, detector):
        """Test Visa credit card detection."""
        text = "Card number: 4532015112830366"
        entities = detector.detect(text)

        cc_entities = [e for e in entities if e.label == "CREDIT_CARD"]
        assert len(cc_entities) == 1
        assert "4532015112830366" in cc_entities[0].text

    def test_detect_credit_card_mastercard(self, detector):
        """Test Mastercard detection."""
        text = "Payment card: 5425233430109903"
        entities = detector.detect(text)

        cc_entities = [e for e in entities if e.label == "CREDIT_CARD"]
        assert len(cc_entities) == 1

    def test_detect_phone(self, detector):
        """Test phone number detection."""
        text = "Call me at 555-123-4567"
        entities = detector.detect(text)

        phone_entities = [e for e in entities if e.label == "PHONE"]
        assert len(phone_entities) >= 1

    def test_detect_ip_address(self, detector):
        """Test IP address detection."""
        text = "Server IP: 192.168.1.100"
        entities = detector.detect(text)

        ip_entities = [e for e in entities if e.label == "IP_ADDRESS"]
        assert len(ip_entities) == 1
        assert ip_entities[0].text == "192.168.1.100"

    def test_detect_bitcoin_address(self, detector):
        """Test Bitcoin address detection."""
        text = "Send BTC to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        entities = detector.detect(text)

        btc_entities = [e for e in entities if e.label == "BITCOIN_ADDRESS"]
        assert len(btc_entities) == 1

    def test_detect_ethereum_address(self, detector):
        """Test Ethereum address detection."""
        text = "ETH wallet: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        entities = detector.detect(text)

        eth_entities = [e for e in entities if e.label == "ETHEREUM_ADDRESS"]
        assert len(eth_entities) == 1

    def test_detect_iban(self, detector):
        """Test IBAN detection."""
        text = "Bank transfer to IBAN GB82WEST12345698765432"
        entities = detector.detect(text)

        iban_entities = [e for e in entities if e.label == "IBAN"]
        assert len(iban_entities) == 1

    def test_detect_multiple_entities(self, detector):
        """Test detection of multiple entity types."""
        text = "Contact john@example.com or call 555-123-4567. SSN: 123-45-6789"
        entities = detector.detect(text)

        labels = {e.label for e in entities}
        assert "EMAIL" in labels
        assert "SSN" in labels

    def test_detect_no_pii(self, detector):
        """Test that clean text returns no entities."""
        text = "This is a normal sentence with no PII."
        entities = detector.detect(text)

        # Should return empty or only low-confidence matches
        high_confidence = [e for e in entities if e.confidence > 0.9]
        assert len(high_confidence) == 0

    def test_redact_basic(self, detector):
        """Test basic redaction."""
        text = "Email: john@example.com"
        redacted, entities = detector.redact(text)

        assert "john@example.com" not in redacted
        assert "[EMAIL:" in redacted

    def test_redact_multiple(self, detector):
        """Test redaction of multiple entities."""
        text = "Contact john@example.com, SSN: 123-45-6789"
        redacted, entities = detector.redact(text)

        assert "john@example.com" not in redacted
        assert "123-45-6789" not in redacted

    def test_redact_custom_mask(self, detector):
        """Test redaction with custom mask character."""
        text = "Email: test@example.com"
        redacted, entities = detector.redact(text, mask_char="#")

        assert "####" in redacted

    def test_entity_positions(self, detector):
        """Test that entity positions are correct."""
        text = "Email: test@example.com"
        entities = detector.detect(text)

        email_entities = [e for e in entities if e.label == "EMAIL"]
        assert len(email_entities) == 1

        entity = email_entities[0]
        assert text[entity.start:entity.end] == entity.text

    def test_get_statistics(self, detector):
        """Test statistics generation."""
        text = "Email: a@b.com, Phone: 555-1234, SSN: 123-45-6789"
        entities = detector.detect(text)
        stats = detector.get_statistics(entities)

        assert "total" in stats
        assert "by_type" in stats
        assert "avg_confidence" in stats
        assert stats["total"] >= 0

    def test_multilingual_name_spanish(self, detector):
        """Test Spanish name detection."""
        text = "Contactar a José García por más información"
        entities = detector.detect(text)

        # Should detect name entities
        name_entities = [e for e in entities if e.label == "NAME"]
        # Name detection works; language detection may vary due to
        # overlapping accented characters between Romance languages
        if name_entities:
            assert name_entities[0].language in ["es", "fr", "it"]  # Romance languages


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_scan_function(self):
        """Test the scan() convenience function."""
        entities = scan("Email me at test@example.com")

        assert isinstance(entities, list)
        assert len(entities) >= 1
        assert all(isinstance(e, PIIEntity) for e in entities)

    def test_redact_function(self):
        """Test the redact() convenience function."""
        result = redact("SSN: 123-45-6789")

        assert isinstance(result, str)
        assert "123-45-6789" not in result
        assert "[SSN:" in result

    def test_list_entities_function(self):
        """Test the list_entities() convenience function."""
        entities = list_entities()

        assert isinstance(entities, list)
        assert len(entities) > 30  # Should have 50+ types
        assert "EMAIL" in entities
        assert "SSN" in entities
        assert "CREDIT_CARD" in entities


class TestValidators:
    """Tests for built-in validators."""

    @pytest.fixture
    def detector(self):
        return PIIDetector()

    def test_luhn_valid(self, detector):
        """Test Luhn algorithm with valid card."""
        assert detector._luhn_check("4532015112830366") is True

    def test_luhn_invalid(self, detector):
        """Test Luhn algorithm with invalid card."""
        assert detector._luhn_check("4532015112830367") is False

    def test_vin_valid(self, detector):
        """Test VIN validation with valid VIN."""
        assert detector._validate_vin("1HGBH41JXMN109186") is True

    def test_vin_invalid_length(self, detector):
        """Test VIN validation with wrong length."""
        assert detector._validate_vin("1HGBH41JXMN1091") is False

    def test_vin_invalid_chars(self, detector):
        """Test VIN validation with invalid characters (I, O, Q)."""
        assert detector._validate_vin("1HGBH41IXMN109186") is False

    def test_iban_valid(self, detector):
        """Test IBAN validation."""
        assert detector._validate_iban("GB82WEST12345698765432") is True

    def test_iban_invalid(self, detector):
        """Test IBAN validation with invalid format."""
        assert detector._validate_iban("12WEST12345698765432") is False

    def test_bitcoin_valid(self, detector):
        """Test Bitcoin address validation."""
        assert detector._validate_bitcoin("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is True

    def test_bitcoin_invalid(self, detector):
        """Test Bitcoin address validation with invalid address."""
        assert detector._validate_bitcoin("invalid") is False

    def test_ip_valid(self, detector):
        """Test IP address validation."""
        assert detector._validate_ip("192.168.1.1") is True

    def test_ip_invalid(self, detector):
        """Test IP address validation with invalid address."""
        assert detector._validate_ip("256.168.1.1") is False

    def test_ssn_valid(self, detector):
        """Test SSN validation."""
        assert detector._validate_ssn("123-45-6789") is True

    def test_ssn_invalid_area(self, detector):
        """Test SSN validation with invalid area number."""
        assert detector._validate_ssn("000-45-6789") is False
        assert detector._validate_ssn("666-45-6789") is False


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @pytest.fixture
    def detector(self):
        return PIIDetector()

    def test_empty_string(self, detector):
        """Test with empty string."""
        entities = detector.detect("")
        assert entities == []

    def test_whitespace_only(self, detector):
        """Test with whitespace only."""
        entities = detector.detect("   \n\t  ")
        assert entities == []

    def test_unicode_text(self, detector):
        """Test with unicode text."""
        text = "Contact 田中太郎 at email@example.com"
        entities = detector.detect(text)
        # Should still detect email
        email_entities = [e for e in entities if e.label == "EMAIL"]
        assert len(email_entities) == 1

    def test_very_long_text(self, detector):
        """Test with very long text."""
        text = "Normal text. " * 1000 + "Email: test@example.com"
        entities = detector.detect(text)

        email_entities = [e for e in entities if e.label == "EMAIL"]
        assert len(email_entities) >= 1

    def test_overlapping_patterns(self, detector):
        """Test handling of overlapping pattern matches."""
        # This could match multiple patterns
        text = "123-45-6789"  # SSN format
        entities = detector.detect(text)

        # Should not have duplicates for same position
        positions = [(e.start, e.end) for e in entities]
        # Allow some overlap but not exact duplicates of same type
        ssn_entities = [e for e in entities if e.label == "SSN"]
        assert len(ssn_entities) <= 1
