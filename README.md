# pii-guard

Fast, accurate PII detection for LLM applications. Zero dependencies, works 100% offline.

[![PyPI version](https://badge.fury.io/py/pii-guard.svg)](https://badge.fury.io/py/pii-guard)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **50+ PII entity types** - SSN, credit cards, emails, phones, crypto addresses, medical records, international IDs, and more
- **Zero dependencies** - Pure Python stdlib, no heavy ML frameworks
- **Works offline** - No API calls, no cloud services, runs entirely on your machine
- **Fast** - ~10ms per document on average
- **Multilingual** - Supports names/addresses in EN, ES, FR, DE, IT, ZH, JA, HI
- **Production-ready** - Built-in validators (Luhn, VIN, IBAN, Bitcoin address validation)

## Quick Start

### Installation

```bash
pip install pii-guard
```

### Usage in 3 lines

```python
from pii_guard import scan, redact

# Detect PII
entities = scan("Email me at john@example.com or call 555-123-4567")
print(entities)  # [PIIEntity(label='EMAIL', ...), PIIEntity(label='PHONE', ...)]

# Redact PII
clean = redact("My SSN is 123-45-6789")
print(clean)  # "My SSN is [SSN:****]"
```

### CLI

```bash
# Scan text
pii-guard scan "Contact john@example.com"
# [EMAIL] john@example.com (confidence: 0.99)

# Redact text
pii-guard redact "SSN: 123-45-6789"
# SSN: [SSN:****]

# JSON output
pii-guard scan "test@example.com" --json

# List all supported types
pii-guard entities
```

## Supported Entity Types

### Financial
- `SSN` - Social Security Numbers
- `CREDIT_CARD` - Credit/debit cards (Visa, MC, Amex, Discover)
- `IBAN` - International Bank Account Numbers
- `BITCOIN_ADDRESS` - Bitcoin addresses (legacy and bech32)
- `ETHEREUM_ADDRESS` - Ethereum addresses
- `ROUTING_NUMBER` - US bank routing numbers
- `BANK_ACCOUNT` - Bank account numbers
- `SWIFT_CODE` - SWIFT/BIC codes

### Contact
- `EMAIL` - Email addresses
- `PHONE` - Phone numbers (US and international)
- `IP_ADDRESS` - IPv4 addresses
- `IPV6_ADDRESS` - IPv6 addresses
- `MAC_ADDRESS` - MAC addresses

### Personal
- `NAME` - Person names (multilingual)
- `ADDRESS` - Physical addresses
- `DATE_OF_BIRTH` - Dates of birth
- `DRIVER_LICENSE` - Driver's license numbers
- `PASSPORT` - Passport numbers

### Healthcare
- `MEDICAL_RECORD` - Medical record numbers
- `MEDICARE` - Medicare IDs
- `DEA_NUMBER` - DEA registration numbers
- `NPI` - National Provider Identifiers

### Vehicle
- `VIN` - Vehicle Identification Numbers
- `LICENSE_PLATE` - License plate numbers

### International IDs
- `UK_NINO` - UK National Insurance Numbers
- `CANADA_SIN` - Canadian Social Insurance Numbers
- `FRANCE_INSEE` - French INSEE numbers
- `GERMANY_STEUER` - German Tax IDs
- `INDIA_AADHAAR` - Indian Aadhaar numbers
- `INDIA_PAN` - Indian PAN cards

### Corporate
- `EMPLOYEE_ID` - Employee IDs
- `TAX_ID` - Tax identification numbers (EIN)

## Advanced Usage

### Using the Detector Class

```python
from pii_guard import PIIDetector

detector = PIIDetector()

# Detect entities
entities = detector.detect("Call me at 555-123-4567")
for entity in entities:
    print(f"{entity.label}: {entity.text} (confidence: {entity.confidence:.2f})")

# Get both redacted text and entities
redacted_text, entities = detector.redact("SSN: 123-45-6789")
print(redacted_text)  # "SSN: [SSN:****]"

# Get statistics
stats = detector.get_statistics(entities)
print(stats)
```

### Data Anonymization

For database anonymization and GDPR compliance:

```python
from pii_guard import (
    DataAnonymizer,
    AnonymizationConfig,
    AnonymizationMethod,
    FieldConfig,
    TableConfig,
)

# Configure anonymization
config = AnonymizationConfig(
    config_id="demo",
    name="User Data Anonymization",
    tables=[
        TableConfig(
            table_name="users",
            fields=[
                FieldConfig("email", "email", AnonymizationMethod.FAKE),
                FieldConfig("phone", "phone", AnonymizationMethod.MASK, {"show_last": 4}),
                FieldConfig("ssn", "ssn", AnonymizationMethod.REDACT),
                FieldConfig("name", "name", AnonymizationMethod.FAKE),
            ]
        )
    ],
    seed=42,  # For reproducible results
)

anonymizer = DataAnonymizer(config)

# Anonymize records
records = [
    {"email": "john@company.com", "phone": "555-123-4567", "ssn": "123-45-6789", "name": "John Doe"},
]
anonymized, result = anonymizer.anonymize_records(records, "users")
print(anonymized)
```

### Anonymization Methods

| Method | Description | Example |
|--------|-------------|---------|
| `REDACT` | Replace with placeholder | `[EMAIL_REDACTED]` |
| `MASK` | Partial masking | `****4567` |
| `HASH` | One-way hash | `anon_a1b2c3@example.com` |
| `TOKENIZE` | Reversible token | `TOK_EMAIL_abc123` |
| `FAKE` | Realistic fake data | `jane.doe@example.com` |
| `GENERALIZE` | Reduce precision | `1990-01-01` → `1990` |
| `NULL` | Replace with null | `null` |
| `PRESERVE` | Keep original | (unchanged) |

### Fake Data Generation

```python
from pii_guard import FakeDataGenerator

faker = FakeDataGenerator(seed=42, locale="en_US")

print(faker.full_name())      # "James Williams"
print(faker.email())          # "abcdefgh@example.com"
print(faker.phone())          # "+1-555-123-4567"
print(faker.ssn())            # "456-78-9012"
print(faker.credit_card())    # "4532 0151 1283 0366"
print(faker.address()["full"])  # "123 Main Street, New York, NY 10001"
```

## Integrations

### LangChain

```python
from langchain.schema import BaseOutputParser
from pii_guard import redact

class PIIRedactingParser(BaseOutputParser):
    def parse(self, text: str) -> str:
        return redact(text)

# Use with any LangChain chain
# chain = prompt | llm | PIIRedactingParser()
```

### FastAPI Middleware

```python
from fastapi import FastAPI, Request
from pii_guard import redact

app = FastAPI()

@app.middleware("http")
async def redact_pii(request: Request, call_next):
    response = await call_next(request)
    # Add PII redaction logic here
    return response
```

## Performance

pii-guard is designed for speed:

| Document Size | Detection Time |
|---------------|----------------|
| 100 chars | ~2ms |
| 1,000 chars | ~10ms |
| 10,000 chars | ~80ms |

Benchmarked on Apple M1, Python 3.11.

## Why pii-guard?

| Feature | pii-guard | Presidio | spaCy NER |
|---------|-----------|----------|-----------|
| Zero dependencies | ✅ | ❌ | ❌ |
| Works offline | ✅ | ✅ | ✅ |
| Entity types | 50+ | 20+ | ~18 |
| Install size | <100KB | >500MB | >200MB |
| Startup time | <50ms | >2s | >1s |

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Need More?

**pii-guard** is the open-source core of [SafeKeyLab](https://safekeylab.com).

For production deployments, SafeKeyLab Cloud adds:
- 🛡️ **Prompt injection detection** — 80+ attack patterns blocked
- 🤖 **Agent security** — Tool call validation and audit trails
- 📚 **RAG security** — Vector DB protection
- 📋 **Compliance dashboards** — GDPR, HIPAA, SOC2 reporting
- ☁️ **Hosted API** — <5ms latency, 99.99% uptime

[Start free trial →](https://safekeylab.com)
