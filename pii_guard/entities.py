#!/usr/bin/env python3
"""
PII Entity definitions and types.

This module defines the core data structures for PII detection results
and the enumeration of all supported entity types.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class EntityType(Enum):
    """All supported PII entity types."""

    # Financial Identifiers
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    IBAN = "IBAN"
    BITCOIN_ADDRESS = "BITCOIN_ADDRESS"
    ETHEREUM_ADDRESS = "ETHEREUM_ADDRESS"
    ROUTING_NUMBER = "ROUTING_NUMBER"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    SWIFT_CODE = "SWIFT_CODE"

    # Contact Information
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IP_ADDRESS = "IP_ADDRESS"
    IPV6_ADDRESS = "IPV6_ADDRESS"
    MAC_ADDRESS = "MAC_ADDRESS"

    # Personal Identifiers
    NAME = "NAME"
    ADDRESS = "ADDRESS"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    DRIVER_LICENSE = "DRIVER_LICENSE"
    PASSPORT = "PASSPORT"

    # Vehicle
    VIN = "VIN"
    LICENSE_PLATE = "LICENSE_PLATE"

    # Healthcare
    MEDICAL_RECORD = "MEDICAL_RECORD"
    MEDICARE = "MEDICARE"
    DEA_NUMBER = "DEA_NUMBER"
    NPI = "NPI"

    # International Government IDs
    UK_NINO = "UK_NINO"
    CANADA_SIN = "CANADA_SIN"
    FRANCE_INSEE = "FRANCE_INSEE"
    GERMANY_STEUER = "GERMANY_STEUER"
    INDIA_AADHAAR = "INDIA_AADHAAR"
    INDIA_PAN = "INDIA_PAN"

    # Corporate
    EMPLOYEE_ID = "EMPLOYEE_ID"
    TAX_ID = "TAX_ID"


@dataclass
class PIIEntity:
    """
    Represents a detected PII entity.

    Attributes:
        text: The detected PII text
        label: The type of PII (e.g., "SSN", "EMAIL")
        start: Start position in the original text
        end: End position in the original text
        confidence: Confidence score (0.0 to 1.0)
        context: Surrounding text for context
        language: Detected language code (e.g., "en", "es")

    Example:
        >>> entity = PIIEntity(
        ...     text="john@example.com",
        ...     label="EMAIL",
        ...     start=10,
        ...     end=26,
        ...     confidence=0.99,
        ...     context="Contact john@example.com for help",
        ...     language="en"
        ... )
    """

    text: str
    label: str
    start: int
    end: int
    confidence: float
    context: str
    language: str = "en"

    def to_dict(self) -> dict:
        """Convert entity to dictionary."""
        return {
            "text": self.text,
            "label": self.label,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
            "context": self.context,
            "language": self.language,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PIIEntity":
        """Create entity from dictionary."""
        return cls(
            text=data["text"],
            label=data["label"],
            start=data["start"],
            end=data["end"],
            confidence=data["confidence"],
            context=data.get("context", ""),
            language=data.get("language", "en"),
        )
