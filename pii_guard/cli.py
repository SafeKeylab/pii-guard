#!/usr/bin/env python3
"""
pii-guard CLI

Command-line interface for PII detection and redaction.

Usage:
    pii-guard scan "Contact john@example.com"
    pii-guard scan "Text with PII" --json
    pii-guard redact "SSN: 123-45-6789"
    pii-guard redact "SSN: 123-45-6789" --mask "#"
    pii-guard entities
    pii-guard --version

Examples:
    $ pii-guard scan "Email me at test@example.com or call 555-123-4567"
    [EMAIL] test@example.com (confidence: 0.99)
    [PHONE] 555-123-4567 (confidence: 0.92)

    $ pii-guard redact "My SSN is 123-45-6789"
    My SSN is [SSN:****]

    $ pii-guard scan "test@example.com" --json
    [
      {
        "type": "EMAIL",
        "text": "test@example.com",
        "start": 0,
        "end": 16,
        "confidence": 0.99
      }
    ]
"""

import argparse
import sys
import json
from typing import Optional


def main(args: Optional[list] = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="pii-guard",
        description="Fast, accurate PII detection for LLM applications",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pii-guard scan "Contact john@example.com"
  pii-guard scan "Text" --json
  pii-guard redact "SSN: 123-45-6789"
  pii-guard entities
        """
    )

    parser.add_argument(
        "--version", "-v",
        action="store_true",
        help="Show version and exit"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Detect PII in text",
        description="Scan text for PII entities and display results"
    )
    scan_parser.add_argument(
        "text",
        help="Text to scan for PII"
    )
    scan_parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON"
    )
    scan_parser.add_argument(
        "--min-confidence", "-c",
        type=float,
        default=0.0,
        help="Minimum confidence threshold (0.0-1.0)"
    )

    # redact command
    redact_parser = subparsers.add_parser(
        "redact",
        help="Redact PII from text",
        description="Replace PII in text with masked placeholders"
    )
    redact_parser.add_argument(
        "text",
        help="Text to redact"
    )
    redact_parser.add_argument(
        "--mask", "-m",
        default="*",
        help="Mask character (default: *)"
    )

    # entities command
    entities_parser = subparsers.add_parser(
        "entities",
        help="List all supported PII entity types",
        description="Show all PII types that can be detected"
    )
    entities_parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output as JSON"
    )

    # Parse args
    parsed = parser.parse_args(args)

    # Handle version
    if parsed.version:
        from . import __version__
        print(f"pii-guard {__version__}")
        return 0

    # Handle no command
    if not parsed.command:
        parser.print_help()
        return 1

    # Import here to avoid slow startup for --help
    from . import scan, redact, list_entities

    if parsed.command == "scan":
        results = scan(parsed.text)

        # Filter by confidence
        if parsed.min_confidence > 0:
            results = [e for e in results if e.confidence >= parsed.min_confidence]

        if parsed.json:
            output = [
                {
                    "type": e.label,
                    "text": e.text,
                    "start": e.start,
                    "end": e.end,
                    "confidence": round(e.confidence, 4)
                }
                for e in results
            ]
            print(json.dumps(output, indent=2))
        else:
            if not results:
                print("No PII detected.")
            else:
                for e in results:
                    print(f"[{e.label}] {e.text} (confidence: {e.confidence:.2f})")
        return 0

    elif parsed.command == "redact":
        result = redact(parsed.text, parsed.mask)
        print(result)
        return 0

    elif parsed.command == "entities":
        entities = list_entities()
        if parsed.json:
            print(json.dumps(entities, indent=2))
        else:
            print(f"Supported PII entity types ({len(entities)} total):\n")
            # Group by category
            categories = {
                "Financial": ["SSN", "CREDIT_CARD", "IBAN", "BITCOIN_ADDRESS", "ETHEREUM_ADDRESS",
                             "ROUTING_NUMBER", "BANK_ACCOUNT", "SWIFT_CODE"],
                "Contact": ["EMAIL", "PHONE", "IP_ADDRESS", "IPV6_ADDRESS", "MAC_ADDRESS"],
                "Personal": ["NAME", "ADDRESS", "DATE_OF_BIRTH", "DRIVER_LICENSE", "PASSPORT"],
                "Vehicle": ["VIN", "LICENSE_PLATE"],
                "Healthcare": ["MEDICAL_RECORD", "MEDICARE", "DEA_NUMBER", "NPI"],
                "International IDs": ["UK_NINO", "CANADA_SIN", "FRANCE_INSEE", "GERMANY_STEUER",
                                     "INDIA_AADHAAR", "INDIA_PAN"],
                "Corporate": ["EMPLOYEE_ID", "TAX_ID"],
            }

            for category, types in categories.items():
                matching = [t for t in types if t in entities]
                if matching:
                    print(f"  {category}:")
                    for t in matching:
                        print(f"    - {t}")

            # Any uncategorized
            categorized = set()
            for types in categories.values():
                categorized.update(types)
            uncategorized = [t for t in entities if t not in categorized]
            if uncategorized:
                print(f"  Other:")
                for t in uncategorized:
                    print(f"    - {t}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
