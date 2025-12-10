#!/usr/bin/env python3
"""
Basic usage example for pii-guard.

This example demonstrates the core functionality:
- Scanning text for PII
- Redacting PII from text
- Using the detector class directly
- Getting detection statistics
"""

from pii_guard import scan, redact, PIIDetector, list_entities


def main():
    # Sample text with various PII types
    text = """
    Contact Information:
    - Name: John Smith
    - Email: john.smith@acme.com
    - Phone: 555-123-4567
    - SSN: 123-45-6789

    Payment Details:
    - Credit Card: 4532015112830366
    - Bitcoin: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2

    Server: 192.168.1.100
    """

    print("=" * 60)
    print("PII-GUARD BASIC USAGE EXAMPLE")
    print("=" * 60)

    # 1. Quick scan using convenience function
    print("\n1. SCANNING FOR PII")
    print("-" * 40)

    entities = scan(text)
    print(f"Found {len(entities)} PII entities:\n")

    for entity in entities:
        print(f"  [{entity.label}] '{entity.text}'")
        print(f"    Confidence: {entity.confidence:.2%}")
        print(f"    Position: {entity.start}-{entity.end}")
        print()

    # 2. Redact PII using convenience function
    print("\n2. REDACTING PII")
    print("-" * 40)

    redacted = redact(text)
    print("Redacted text:")
    print(redacted)

    # 3. Using the PIIDetector class directly
    print("\n3. USING PIIDETECTOR CLASS")
    print("-" * 40)

    detector = PIIDetector()

    # Detect and redact in one call
    redacted_text, detected_entities = detector.redact(
        "Contact jane@example.com or call 555-987-6543"
    )
    print(f"Original: Contact jane@example.com or call 555-987-6543")
    print(f"Redacted: {redacted_text}")
    print(f"Entities found: {len(detected_entities)}")

    # 4. Get statistics
    print("\n4. DETECTION STATISTICS")
    print("-" * 40)

    stats = detector.get_statistics(entities)
    print(f"Total entities: {stats['total']}")
    print(f"Average confidence: {stats['avg_confidence']:.2%}")
    print("\nBy type:")
    for pii_type, info in stats['by_type'].items():
        print(f"  {pii_type}: {info['count']} (avg conf: {info['avg_confidence']:.2%})")

    # 5. List all supported entity types
    print("\n5. SUPPORTED ENTITY TYPES")
    print("-" * 40)

    all_types = list_entities()
    print(f"Total supported types: {len(all_types)}")
    print("Types:", ", ".join(all_types[:10]), "...")


if __name__ == "__main__":
    main()
