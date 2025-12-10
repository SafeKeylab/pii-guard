#!/usr/bin/env python3
"""
Benchmark pii-guard against other PII detection libraries.

This script compares:
- pii-guard (this library)
- Microsoft Presidio (if installed)
- regex-only baseline

Usage:
    python benchmarks/vs_presidio.py

Requirements for full comparison:
    pip install presidio-analyzer presidio-anonymizer
"""

import time
import statistics
from typing import List, Tuple, Callable

# pii-guard import
from pii_guard import PIIDetector, scan


# Test data
TEST_DOCUMENTS = [
    # Short documents
    "Contact john@example.com for more info.",
    "Call me at 555-123-4567.",
    "SSN: 123-45-6789",
    "Credit card: 4532015112830366",

    # Medium documents
    """
    Customer Profile:
    Name: John Smith
    Email: john.smith@acme.com
    Phone: (555) 123-4567
    SSN: 123-45-6789
    Address: 123 Main Street, New York, NY 10001
    """,

    # Long document
    """
    Patient Medical Record

    Patient Information:
    - Name: Jane Doe
    - Date of Birth: 03/15/1985
    - SSN: 987-65-4321
    - Medicare ID: 1EG4-TE5-MK72
    - Phone: +1 (555) 987-6543
    - Email: jane.doe@healthcare.org

    Emergency Contact:
    - Name: John Doe
    - Phone: 555-123-4567
    - Email: john.doe@email.com

    Insurance Information:
    - Provider: Blue Cross Blue Shield
    - Policy Number: BCB123456789
    - Group Number: GRP98765

    Billing Address:
    456 Oak Avenue, Apt 7B
    Los Angeles, CA 90001

    Payment Method:
    Credit Card: 4532 0151 1283 0366
    Expiration: 12/25

    Medical History:
    Patient was seen on 01/15/2024 for routine checkup.
    Previous visit was on 06/20/2023.

    Notes:
    Contact patient at jane.doe@healthcare.org or 555-987-6543
    for follow-up appointment. Send records to fax: 555-111-2222.

    Server logs: 192.168.1.100, 10.0.0.50
    Bitcoin donation address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
    """,
]


def benchmark_function(func: Callable, name: str, iterations: int = 100) -> dict:
    """Benchmark a function over multiple iterations."""
    times = []

    for doc in TEST_DOCUMENTS:
        doc_times = []
        for _ in range(iterations):
            start = time.perf_counter()
            func(doc)
            end = time.perf_counter()
            doc_times.append((end - start) * 1000)  # Convert to ms
        times.extend(doc_times)

    return {
        "name": name,
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "min_ms": min(times),
        "max_ms": max(times),
        "std_ms": statistics.stdev(times) if len(times) > 1 else 0,
        "iterations": iterations * len(TEST_DOCUMENTS),
    }


def benchmark_pii_guard():
    """Benchmark pii-guard."""
    detector = PIIDetector()

    def detect(text):
        return detector.detect(text)

    return benchmark_function(detect, "pii-guard")


def benchmark_pii_guard_redact():
    """Benchmark pii-guard redaction."""
    detector = PIIDetector()

    def redact(text):
        return detector.redact(text)

    return benchmark_function(redact, "pii-guard (redact)")


def benchmark_presidio():
    """Benchmark Microsoft Presidio (if installed)."""
    try:
        from presidio_analyzer import AnalyzerEngine

        analyzer = AnalyzerEngine()

        def detect(text):
            return analyzer.analyze(text=text, language="en")

        return benchmark_function(detect, "Presidio", iterations=20)
    except ImportError:
        return None


def count_detections():
    """Count detections from each library on test data."""
    print("\n" + "=" * 60)
    print("DETECTION COMPARISON")
    print("=" * 60)

    detector = PIIDetector()

    for i, doc in enumerate(TEST_DOCUMENTS):
        print(f"\n--- Document {i + 1} ({len(doc)} chars) ---")

        # pii-guard
        pii_guard_entities = detector.detect(doc)
        print(f"pii-guard: {len(pii_guard_entities)} entities")
        for e in pii_guard_entities[:5]:  # Show first 5
            print(f"  [{e.label}] {e.text[:30]}...")

        # Presidio (if available)
        try:
            from presidio_analyzer import AnalyzerEngine
            analyzer = AnalyzerEngine()
            presidio_entities = analyzer.analyze(text=doc, language="en")
            print(f"Presidio: {len(presidio_entities)} entities")
            for e in presidio_entities[:5]:
                print(f"  [{e.entity_type}] {doc[e.start:e.end][:30]}...")
        except ImportError:
            pass


def main():
    print("=" * 60)
    print("PII-GUARD BENCHMARK")
    print("=" * 60)

    print(f"\nTest documents: {len(TEST_DOCUMENTS)}")
    print(f"Document sizes: {[len(d) for d in TEST_DOCUMENTS]} chars")

    results = []

    # Benchmark pii-guard
    print("\nRunning pii-guard benchmark...")
    results.append(benchmark_pii_guard())

    print("Running pii-guard redaction benchmark...")
    results.append(benchmark_pii_guard_redact())

    # Benchmark Presidio if available
    print("Running Presidio benchmark (if installed)...")
    presidio_result = benchmark_presidio()
    if presidio_result:
        results.append(presidio_result)
    else:
        print("  Presidio not installed, skipping.")

    # Print results
    print("\n" + "=" * 60)
    print("BENCHMARK RESULTS")
    print("=" * 60)

    print(f"\n{'Library':<25} {'Mean (ms)':<12} {'Median (ms)':<12} {'Min (ms)':<10} {'Max (ms)':<10}")
    print("-" * 70)

    for r in results:
        print(f"{r['name']:<25} {r['mean_ms']:<12.3f} {r['median_ms']:<12.3f} {r['min_ms']:<10.3f} {r['max_ms']:<10.3f}")

    # Show speedup
    if len(results) >= 2 and presidio_result:
        pii_guard_time = results[0]["mean_ms"]
        presidio_time = presidio_result["mean_ms"]
        speedup = presidio_time / pii_guard_time
        print(f"\npii-guard is {speedup:.1f}x faster than Presidio")

    # Detection comparison
    count_detections()

    print("\n" + "=" * 60)
    print("NOTES")
    print("=" * 60)
    print("""
- pii-guard uses pure Python regex patterns (no ML models)
- Presidio uses spaCy NER + custom recognizers
- pii-guard has zero external dependencies
- Presidio requires ~500MB+ of dependencies

Install Presidio to compare:
    pip install presidio-analyzer presidio-anonymizer
    python -m spacy download en_core_web_lg
    """)


if __name__ == "__main__":
    main()
