"""
pii-guard: Fast, accurate PII detection for LLM applications.

A lightweight, offline-first Python library for detecting and redacting
Personally Identifiable Information (PII) in text.

Features:
- 50+ PII entity types (SSN, credit cards, emails, phones, crypto addresses, etc.)
- Zero external dependencies - pure Python stdlib
- Works 100% offline - no API calls
- Multilingual support (EN, ES, FR, DE, IT, ZH, JA, HI)
- Built-in validators (Luhn, VIN, IBAN, Bitcoin)
- Fast: ~10ms per document

Quick Start:
    >>> from pii_guard import scan, redact
    >>>
    >>> # Detect PII
    >>> entities = scan("Email me at john@example.com")
    >>> for e in entities:
    ...     print(f"{e.label}: {e.text}")
    EMAIL: john@example.com
    >>>
    >>> # Redact PII
    >>> clean = redact("SSN: 123-45-6789")
    >>> print(clean)
    SSN: [SSN:****]

Example with confidence scores:
    >>> entities = scan("Call me at 555-123-4567")
    >>> for e in entities:
    ...     print(f"{e.label}: {e.text} (confidence: {e.confidence:.2f})")
    PHONE: 555-123-4567 (confidence: 0.92)

For more control, use the PIIDetector class directly:
    >>> from pii_guard import PIIDetector
    >>> detector = PIIDetector()
    >>> entities = detector.detect("text with PII")
    >>> redacted, entities = detector.redact("text with PII")
"""

__version__ = "0.1.0"
__author__ = "PII Guard Contributors"

from .entities import PIIEntity, EntityType
from .detector import PIIDetector, EnhancedMLPIIDetector
from .anonymizer import (
    DataAnonymizer,
    AnonymizationMethod,
    AnonymizationConfig,
    FieldConfig,
    TableConfig,
    TokenVault,
    AnonymizationTemplates,
)
from .fake_data import FakeDataGenerator, get_fake_generator

__all__ = [
    # Core classes
    "PIIDetector",
    "PIIEntity",
    "EntityType",
    # Anonymization
    "DataAnonymizer",
    "AnonymizationMethod",
    "AnonymizationConfig",
    "FieldConfig",
    "TableConfig",
    "TokenVault",
    "AnonymizationTemplates",
    # Fake data
    "FakeDataGenerator",
    "get_fake_generator",
    # Convenience functions
    "scan",
    "redact",
    "list_entities",
    # Backwards compatibility
    "EnhancedMLPIIDetector",
]

# Module-level detector instance (lazy loaded)
_default_detector = None


def _get_detector() -> PIIDetector:
    """Get or create the default detector instance."""
    global _default_detector
    if _default_detector is None:
        _default_detector = PIIDetector()
    return _default_detector


def scan(text: str) -> list[PIIEntity]:
    """
    Detect PII entities in text.

    This is a convenience function that uses a shared detector instance.
    For more control, use PIIDetector directly.

    Args:
        text: The text to scan for PII

    Returns:
        List of PIIEntity objects found in the text

    Example:
        >>> from pii_guard import scan
        >>> entities = scan("Contact john@example.com or call 555-1234")
        >>> for e in entities:
        ...     print(f"{e.label}: {e.text}")
        EMAIL: john@example.com
        PHONE: 555-1234
    """
    return _get_detector().detect(text)


def redact(text: str, mask_char: str = "*") -> str:
    """
    Redact PII from text.

    Replaces detected PII with placeholders like [EMAIL:****].

    Args:
        text: The text to redact
        mask_char: Character to use for masking (default: "*")

    Returns:
        Text with PII replaced by type-labeled placeholders

    Example:
        >>> from pii_guard import redact
        >>> clean = redact("Email: john@example.com, SSN: 123-45-6789")
        >>> print(clean)
        Email: [EMAIL:****], SSN: [SSN:****]
    """
    redacted, _ = _get_detector().redact(text, mask_char)
    return redacted


def list_entities() -> list[str]:
    """
    List all supported PII entity types.

    Returns:
        List of entity type names (e.g., ["SSN", "EMAIL", "CREDIT_CARD", ...])

    Example:
        >>> from pii_guard import list_entities
        >>> types = list_entities()
        >>> print(types[:5])
        ['SSN', 'CREDIT_CARD', 'IBAN', 'BITCOIN_ADDRESS', 'ETHEREUM_ADDRESS']
    """
    return [e.value for e in EntityType]
