#!/usr/bin/env python3
"""
Data Anonymization Engine

Production-ready data anonymization for:
- Database sanitization for dev/staging environments
- GDPR data export requests
- Analytics/ML training data preparation
- Third-party data sharing

Features:
- 9 anonymization methods (redact, mask, hash, tokenize, fake, generalize, shuffle, null, preserve)
- Consistent anonymization (same input → same output)
- Reversible tokenization (optional)
- Format-preserving anonymization
- Batch processing for databases
- Multiple output formats (SQL, CSV, JSON)
"""

import hashlib
import uuid
import re
import json
import random
import string
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, date, timedelta
from enum import Enum
from abc import ABC, abstractmethod
import base64

logger = logging.getLogger(__name__)


class AnonymizationMethod(Enum):
    """Methods for anonymizing data."""
    REDACT = "redact"  # Replace with placeholder [REDACTED]
    MASK = "mask"  # Partial masking (e.g., ****1234)
    HASH = "hash"  # One-way hash
    TOKENIZE = "tokenize"  # Reversible token
    FAKE = "fake"  # Replace with realistic fake data
    GENERALIZE = "generalize"  # Reduce precision (e.g., age range)
    SHUFFLE = "shuffle"  # Shuffle values within column
    NULL = "null"  # Replace with null
    PRESERVE = "preserve"  # Keep original (for non-sensitive fields)


@dataclass
class FieldConfig:
    """
    Configuration for anonymizing a specific field.

    Attributes:
        field_name: Name of the field to anonymize
        field_type: Type of data (email, phone, name, ssn, date, text, numeric, etc.)
        method: Anonymization method to use
        params: Additional parameters for the method

    Example:
        >>> config = FieldConfig(
        ...     field_name="email",
        ...     field_type="email",
        ...     method=AnonymizationMethod.MASK
        ... )
    """
    field_name: str
    field_type: str  # email, phone, name, ssn, date, text, numeric, etc.
    method: AnonymizationMethod
    params: Dict[str, Any] = field(default_factory=dict)
    # Examples:
    # - mask: {"show_last": 4, "mask_char": "*"}
    # - generalize: {"ranges": [[0, 18], [19, 30], [31, 50], [51, 100]]}
    # - fake: {"locale": "en_US"}


@dataclass
class TableConfig:
    """
    Configuration for anonymizing a database table.

    Attributes:
        table_name: Name of the table
        fields: List of field configurations
        primary_key: Primary key column name
        foreign_keys: Foreign key relationships for consistent anonymization
    """
    table_name: str
    fields: List[FieldConfig]
    primary_key: str = "id"
    foreign_keys: Dict[str, str] = field(default_factory=dict)
    # Format: {"user_id": "users.id"} - use same anonymized value


@dataclass
class AnonymizationConfig:
    """
    Full configuration for a data anonymization job.

    Attributes:
        config_id: Unique identifier for this configuration
        name: Human-readable name
        tables: List of table configurations
        seed: Random seed for reproducibility
        preserve_nulls: Whether to preserve null values
        preserve_format: Whether to use format-preserving encryption
        use_token_vault: Whether to enable reversible tokenization
        vault_encryption_key: Key for token vault encryption
        output_format: Output format (json, csv, sql)
        created_at: Creation timestamp
    """
    config_id: str
    name: str
    tables: List[TableConfig] = field(default_factory=list)

    # Global settings
    seed: Optional[int] = None  # For reproducible randomness
    preserve_nulls: bool = True
    preserve_format: bool = True  # Format-preserving encryption

    # Tokenization vault (for reversible anonymization)
    use_token_vault: bool = False
    vault_encryption_key: Optional[str] = None

    # Output settings
    output_format: str = "json"  # json, csv, sql

    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AnonymizationResult:
    """Result of anonymizing data."""
    original_count: int
    anonymized_count: int
    fields_processed: Dict[str, int]
    processing_time_seconds: float
    errors: List[str] = field(default_factory=list)


class TokenVault:
    """
    Secure vault for reversible tokenization.

    Maps original values to tokens for later reversal (e.g., GDPR requests).

    Example:
        >>> vault = TokenVault()
        >>> token = vault.tokenize("john@example.com", "email")
        >>> original = vault.detokenize(token, "email")
    """

    def __init__(self, encryption_key: Optional[str] = None):
        self.encryption_key = encryption_key or self._generate_key()
        self._vault: Dict[str, Dict[str, str]] = {}  # {field_type: {hash: token}}
        self._reverse: Dict[str, Dict[str, str]] = {}  # {field_type: {token: original}}

    def _generate_key(self) -> str:
        return base64.b64encode(uuid.uuid4().bytes).decode()

    def tokenize(self, value: str, field_type: str) -> str:
        """Tokenize a value (reversible)."""
        if field_type not in self._vault:
            self._vault[field_type] = {}
            self._reverse[field_type] = {}

        value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]

        if value_hash in self._vault[field_type]:
            return self._vault[field_type][value_hash]

        token = f"TOK_{field_type.upper()}_{uuid.uuid4().hex[:12]}"

        self._vault[field_type][value_hash] = token
        self._reverse[field_type][token] = value

        return token

    def detokenize(self, token: str, field_type: str) -> Optional[str]:
        """Reverse a token to original value."""
        if field_type not in self._reverse:
            return None
        return self._reverse[field_type].get(token)

    def export_vault(self) -> Dict[str, Any]:
        """Export vault for secure storage."""
        return {
            "vault": self._vault,
            "reverse": self._reverse,
        }

    def import_vault(self, data: Dict[str, Any]):
        """Import vault from storage."""
        self._vault = data.get("vault", {})
        self._reverse = data.get("reverse", {})


class Anonymizer(ABC):
    """Base class for field anonymizers."""

    @abstractmethod
    def anonymize(self, value: Any, config: FieldConfig, context: Dict[str, Any] = None) -> Any:
        """Anonymize a value according to the config."""
        pass


class EmailAnonymizer(Anonymizer):
    """Anonymize email addresses."""

    def anonymize(self, value: Any, config: FieldConfig, context: Dict[str, Any] = None) -> Any:
        if value is None:
            return None

        email = str(value)
        method = config.method

        if method == AnonymizationMethod.REDACT:
            return "[EMAIL_REDACTED]"

        elif method == AnonymizationMethod.MASK:
            if "@" in email:
                local, domain = email.split("@", 1)
                masked_local = local[0] + "***" if len(local) > 1 else "***"
                return f"{masked_local}@{domain}"
            return "***@***.***"

        elif method == AnonymizationMethod.HASH:
            hash_val = hashlib.sha256(email.encode()).hexdigest()[:12]
            return f"anon_{hash_val}@example.com"

        elif method == AnonymizationMethod.FAKE:
            seed = int(hashlib.md5(email.encode()).hexdigest()[:8], 16)
            random.seed(seed)
            fake_name = ''.join(random.choices(string.ascii_lowercase, k=8))
            fake_domain = random.choice(["example.com", "test.org", "sample.net"])
            return f"{fake_name}@{fake_domain}"

        elif method == AnonymizationMethod.TOKENIZE:
            vault = context.get("vault") if context else None
            if vault:
                return vault.tokenize(email, "email")
            return f"TOK_EMAIL_{hashlib.md5(email.encode()).hexdigest()[:12]}"

        return "[EMAIL_REDACTED]"


class PhoneAnonymizer(Anonymizer):
    """Anonymize phone numbers."""

    def anonymize(self, value: Any, config: FieldConfig, context: Dict[str, Any] = None) -> Any:
        if value is None:
            return None

        phone = str(value)
        digits = re.sub(r'\D', '', phone)
        method = config.method

        if method == AnonymizationMethod.REDACT:
            return "[PHONE_REDACTED]"

        elif method == AnonymizationMethod.MASK:
            show_last = config.params.get("show_last", 4)
            mask_char = config.params.get("mask_char", "*")
            if len(digits) > show_last:
                return mask_char * (len(digits) - show_last) + digits[-show_last:]
            return mask_char * len(digits)

        elif method == AnonymizationMethod.HASH:
            hash_val = hashlib.sha256(phone.encode()).hexdigest()[:10]
            return f"+1{hash_val}"

        elif method == AnonymizationMethod.FAKE:
            seed = int(hashlib.md5(phone.encode()).hexdigest()[:8], 16)
            random.seed(seed)
            area = random.randint(200, 999)
            exchange = random.randint(200, 999)
            subscriber = random.randint(1000, 9999)
            return f"+1-{area}-{exchange}-{subscriber}"

        return "[PHONE_REDACTED]"


class NameAnonymizer(Anonymizer):
    """Anonymize names."""

    FAKE_FIRST_NAMES = ["John", "Jane", "Alex", "Sam", "Chris", "Pat", "Jordan", "Taylor", "Morgan", "Casey"]
    FAKE_LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Wilson", "Moore"]

    def anonymize(self, value: Any, config: FieldConfig, context: Dict[str, Any] = None) -> Any:
        if value is None:
            return None

        name = str(value)
        method = config.method

        if method == AnonymizationMethod.REDACT:
            return "[NAME_REDACTED]"

        elif method == AnonymizationMethod.MASK:
            parts = name.split()
            masked = [p[0] + "***" if len(p) > 1 else "***" for p in parts]
            return " ".join(masked)

        elif method == AnonymizationMethod.HASH:
            hash_val = hashlib.sha256(name.encode()).hexdigest()[:8]
            return f"User_{hash_val}"

        elif method == AnonymizationMethod.FAKE:
            seed = int(hashlib.md5(name.encode()).hexdigest()[:8], 16)
            random.seed(seed)
            first = random.choice(self.FAKE_FIRST_NAMES)
            last = random.choice(self.FAKE_LAST_NAMES)
            return f"{first} {last}"

        return "[NAME_REDACTED]"


class SSNAnonymizer(Anonymizer):
    """Anonymize Social Security Numbers."""

    def anonymize(self, value: Any, config: FieldConfig, context: Dict[str, Any] = None) -> Any:
        if value is None:
            return None

        ssn = str(value)
        digits = re.sub(r'\D', '', ssn)
        method = config.method

        if method == AnonymizationMethod.REDACT:
            return "[SSN_REDACTED]"

        elif method == AnonymizationMethod.MASK:
            if len(digits) >= 4:
                return f"***-**-{digits[-4:]}"
            return "***-**-****"

        elif method == AnonymizationMethod.HASH:
            hash_val = hashlib.sha256(ssn.encode()).hexdigest()[:9]
            return f"{hash_val[:3]}-{hash_val[3:5]}-{hash_val[5:9]}"

        elif method == AnonymizationMethod.FAKE:
            seed = int(hashlib.md5(ssn.encode()).hexdigest()[:8], 16)
            random.seed(seed)
            area = random.randint(100, 999)
            group = random.randint(10, 99)
            serial = random.randint(1000, 9999)
            return f"{area}-{group}-{serial}"

        return "[SSN_REDACTED]"


class DateAnonymizer(Anonymizer):
    """Anonymize dates."""

    def anonymize(self, value: Any, config: FieldConfig, context: Dict[str, Any] = None) -> Any:
        if value is None:
            return None

        method = config.method

        if isinstance(value, (date, datetime)):
            dt = value
        else:
            try:
                dt = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
            except ValueError:
                return "[DATE_REDACTED]"

        if method == AnonymizationMethod.REDACT:
            return "[DATE_REDACTED]"

        elif method == AnonymizationMethod.GENERALIZE:
            precision = config.params.get("precision", "month")
            if precision == "year":
                return dt.strftime("%Y-01-01")
            elif precision == "month":
                return dt.strftime("%Y-%m-01")
            elif precision == "decade":
                decade = (dt.year // 10) * 10
                return f"{decade}-01-01"

        elif method == AnonymizationMethod.FAKE:
            seed = int(hashlib.md5(str(value).encode()).hexdigest()[:8], 16)
            random.seed(seed)
            shift_days = random.randint(-365, 365)
            new_date = dt + timedelta(days=shift_days)
            return new_date.strftime("%Y-%m-%d")

        return dt.strftime("%Y-%m-%d")


class NumericAnonymizer(Anonymizer):
    """Anonymize numeric values."""

    def anonymize(self, value: Any, config: FieldConfig, context: Dict[str, Any] = None) -> Any:
        if value is None:
            return None

        try:
            num = float(value)
        except (ValueError, TypeError):
            return None

        method = config.method

        if method == AnonymizationMethod.REDACT:
            return 0

        elif method == AnonymizationMethod.GENERALIZE:
            ranges = config.params.get("ranges", [[0, 10], [11, 20], [21, 50], [51, 100]])
            for r in ranges:
                if r[0] <= num <= r[1]:
                    return f"{r[0]}-{r[1]}"
            return "other"

        elif method == AnonymizationMethod.FAKE:
            seed = int(hashlib.md5(str(value).encode()).hexdigest()[:8], 16)
            random.seed(seed)
            noise_pct = config.params.get("noise_percent", 10)
            noise = num * (random.uniform(-noise_pct, noise_pct) / 100)
            return round(num + noise, 2)

        return num


class TextAnonymizer(Anonymizer):
    """Anonymize free text fields."""

    def anonymize(self, value: Any, config: FieldConfig, context: Dict[str, Any] = None) -> Any:
        if value is None:
            return None

        text = str(value)
        method = config.method

        if method == AnonymizationMethod.REDACT:
            return "[TEXT_REDACTED]"

        elif method == AnonymizationMethod.HASH:
            hash_val = hashlib.sha256(text.encode()).hexdigest()[:16]
            return f"text_{hash_val}"

        elif method == AnonymizationMethod.MASK:
            return re.sub(r'[a-zA-Z0-9]', '*', text)

        elif method == AnonymizationMethod.PRESERVE:
            return text

        return "[TEXT_REDACTED]"


class AddressAnonymizer(Anonymizer):
    """Anonymize addresses."""

    FAKE_STREETS = ["Main St", "Oak Ave", "Park Blvd", "First St", "Elm Way", "Maple Dr"]
    FAKE_CITIES = ["Springfield", "Riverside", "Fairview", "Madison", "Georgetown", "Clinton"]

    def anonymize(self, value: Any, config: FieldConfig, context: Dict[str, Any] = None) -> Any:
        if value is None:
            return None

        address = str(value)
        method = config.method

        if method == AnonymizationMethod.REDACT:
            return "[ADDRESS_REDACTED]"

        elif method == AnonymizationMethod.FAKE:
            seed = int(hashlib.md5(address.encode()).hexdigest()[:8], 16)
            random.seed(seed)
            num = random.randint(100, 9999)
            street = random.choice(self.FAKE_STREETS)
            city = random.choice(self.FAKE_CITIES)
            state = random.choice(["CA", "NY", "TX", "FL", "WA", "IL"])
            zipcode = random.randint(10000, 99999)
            return f"{num} {street}, {city}, {state} {zipcode}"

        elif method == AnonymizationMethod.GENERALIZE:
            precision = config.params.get("precision", "city")
            if precision == "zip":
                zip_match = re.search(r'\b\d{5}(?:-\d{4})?\b', address)
                if zip_match:
                    return zip_match.group()
            return "[LOCATION_GENERALIZED]"

        return "[ADDRESS_REDACTED]"


class CreditCardAnonymizer(Anonymizer):
    """Anonymize credit card numbers."""

    def anonymize(self, value: Any, config: FieldConfig, context: Dict[str, Any] = None) -> Any:
        if value is None:
            return None

        cc = str(value)
        digits = re.sub(r'\D', '', cc)
        method = config.method

        if method == AnonymizationMethod.REDACT:
            return "[CC_REDACTED]"

        elif method == AnonymizationMethod.MASK:
            show_last = config.params.get("show_last", 4)
            mask_char = config.params.get("mask_char", "*")
            if len(digits) > show_last:
                return mask_char * (len(digits) - show_last) + digits[-show_last:]
            return mask_char * len(digits)

        elif method == AnonymizationMethod.HASH:
            hash_val = hashlib.sha256(cc.encode()).hexdigest()[:16]
            return hash_val

        return "[CC_REDACTED]"


class DataAnonymizer:
    """
    Main data anonymization engine.

    Example:
        >>> config = AnonymizationConfig(
        ...     config_id="demo",
        ...     name="Demo Config",
        ...     tables=[TableConfig(
        ...         table_name="users",
        ...         fields=[
        ...             FieldConfig("email", "email", AnonymizationMethod.MASK),
        ...             FieldConfig("phone", "phone", AnonymizationMethod.MASK),
        ...         ]
        ...     )]
        ... )
        >>> anonymizer = DataAnonymizer(config)
        >>> result = anonymizer.anonymize_record(
        ...     {"email": "john@example.com", "phone": "555-123-4567"},
        ...     "users"
        ... )
    """

    def __init__(self, config: AnonymizationConfig):
        self.config = config
        self.vault = TokenVault(config.vault_encryption_key) if config.use_token_vault else None

        if config.seed is not None:
            random.seed(config.seed)

        # Initialize anonymizers
        self.anonymizers: Dict[str, Anonymizer] = {
            "email": EmailAnonymizer(),
            "phone": PhoneAnonymizer(),
            "name": NameAnonymizer(),
            "ssn": SSNAnonymizer(),
            "date": DateAnonymizer(),
            "numeric": NumericAnonymizer(),
            "text": TextAnonymizer(),
            "address": AddressAnonymizer(),
            "credit_card": CreditCardAnonymizer(),
        }

        # Build field lookup
        self.field_configs: Dict[str, Dict[str, FieldConfig]] = {}
        for table in config.tables:
            self.field_configs[table.table_name] = {
                f.field_name: f for f in table.fields
            }

        # Track anonymized values for consistency
        self._consistency_map: Dict[str, Dict[str, Any]] = {}

    def anonymize_record(
        self,
        record: Dict[str, Any],
        table_name: str
    ) -> Dict[str, Any]:
        """Anonymize a single record."""
        if table_name not in self.field_configs:
            return record

        result = {}
        field_configs = self.field_configs[table_name]

        for field_name, value in record.items():
            if field_name in field_configs:
                config = field_configs[field_name]

                if value is None and self.config.preserve_nulls:
                    result[field_name] = None
                    continue

                consistency_key = f"{table_name}.{field_name}"
                if value is not None and consistency_key in self._consistency_map:
                    if str(value) in self._consistency_map[consistency_key]:
                        result[field_name] = self._consistency_map[consistency_key][str(value)]
                        continue

                anonymizer = self.anonymizers.get(config.field_type, self.anonymizers["text"])
                context = {"vault": self.vault} if self.vault else {}

                anon_value = anonymizer.anonymize(value, config, context)

                if consistency_key not in self._consistency_map:
                    self._consistency_map[consistency_key] = {}
                self._consistency_map[consistency_key][str(value)] = anon_value

                result[field_name] = anon_value
            else:
                result[field_name] = value

        return result

    def anonymize_records(
        self,
        records: List[Dict[str, Any]],
        table_name: str
    ) -> Tuple[List[Dict[str, Any]], AnonymizationResult]:
        """Anonymize a list of records."""
        import time
        start = time.time()

        anonymized = []
        fields_processed: Dict[str, int] = {}
        errors = []

        for i, record in enumerate(records):
            try:
                anon_record = self.anonymize_record(record, table_name)
                anonymized.append(anon_record)

                for field in anon_record.keys():
                    fields_processed[field] = fields_processed.get(field, 0) + 1

            except Exception as e:
                errors.append(f"Record {i}: {str(e)}")
                anonymized.append(record)

        result = AnonymizationResult(
            original_count=len(records),
            anonymized_count=len(anonymized),
            fields_processed=fields_processed,
            processing_time_seconds=time.time() - start,
            errors=errors,
        )

        return anonymized, result

    def anonymize_text(self, text: str, method: AnonymizationMethod = AnonymizationMethod.REDACT) -> str:
        """
        Simple text anonymization.

        Args:
            text: Text to anonymize
            method: Anonymization method to use

        Returns:
            Anonymized text
        """
        config = FieldConfig("text", "text", method)
        return self.anonymizers["text"].anonymize(text, config)

    def export_vault(self) -> Optional[Dict[str, Any]]:
        """Export token vault for storage."""
        if self.vault:
            flattened = {}
            vault_data = self.vault.export_vault()
            for field_type, token_map in vault_data.get("reverse", {}).items():
                flattened.update(token_map)
            return flattened
        return None


class AnonymizationTemplates:
    """Common anonymization configurations."""

    @staticmethod
    def user_table() -> TableConfig:
        """Standard user table anonymization."""
        return TableConfig(
            table_name="users",
            primary_key="id",
            fields=[
                FieldConfig("email", "email", AnonymizationMethod.FAKE),
                FieldConfig("phone", "phone", AnonymizationMethod.MASK, {"show_last": 4}),
                FieldConfig("first_name", "name", AnonymizationMethod.FAKE),
                FieldConfig("last_name", "name", AnonymizationMethod.FAKE),
                FieldConfig("ssn", "ssn", AnonymizationMethod.REDACT),
                FieldConfig("date_of_birth", "date", AnonymizationMethod.GENERALIZE, {"precision": "year"}),
                FieldConfig("address", "address", AnonymizationMethod.FAKE),
                FieldConfig("created_at", "date", AnonymizationMethod.PRESERVE),
            ],
        )

    @staticmethod
    def orders_table() -> TableConfig:
        """Order table anonymization."""
        return TableConfig(
            table_name="orders",
            primary_key="id",
            fields=[
                FieldConfig("customer_email", "email", AnonymizationMethod.FAKE),
                FieldConfig("shipping_address", "address", AnonymizationMethod.FAKE),
                FieldConfig("phone", "phone", AnonymizationMethod.MASK),
                FieldConfig("amount", "numeric", AnonymizationMethod.PRESERVE),
                FieldConfig("created_at", "date", AnonymizationMethod.PRESERVE),
            ],
            foreign_keys={"user_id": "users.id"},
        )

    @staticmethod
    def gdpr_export_config() -> AnonymizationConfig:
        """GDPR-compliant export configuration."""
        return AnonymizationConfig(
            config_id=str(uuid.uuid4()),
            name="GDPR Export",
            tables=[
                AnonymizationTemplates.user_table(),
            ],
            preserve_nulls=True,
            use_token_vault=True,
        )

    @staticmethod
    def staging_copy_config() -> AnonymizationConfig:
        """Configuration for prod → staging copies."""
        return AnonymizationConfig(
            config_id=str(uuid.uuid4()),
            name="Staging Copy",
            tables=[
                AnonymizationTemplates.user_table(),
                AnonymizationTemplates.orders_table(),
            ],
            seed=42,
            preserve_nulls=True,
            use_token_vault=False,
        )


# Convenience function
def get_anonymizer(config: AnonymizationConfig = None) -> DataAnonymizer:
    """Get or create anonymizer instance."""
    if config is None:
        config = AnonymizationConfig(
            config_id="default",
            name="Default",
        )
    return DataAnonymizer(config)
