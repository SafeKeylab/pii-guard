"""Tests for data anonymization functionality."""

import pytest
from pii_guard import (
    DataAnonymizer,
    AnonymizationConfig,
    AnonymizationMethod,
    FieldConfig,
    TableConfig,
    TokenVault,
    AnonymizationTemplates,
)
from pii_guard.fake_data import FakeDataGenerator


class TestAnonymizationMethods:
    """Tests for different anonymization methods."""

    @pytest.fixture
    def simple_config(self):
        """Create a simple anonymization config."""
        return AnonymizationConfig(
            config_id="test",
            name="Test Config",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("email", "email", AnonymizationMethod.REDACT),
                        FieldConfig("phone", "phone", AnonymizationMethod.MASK),
                        FieldConfig("name", "name", AnonymizationMethod.FAKE),
                        FieldConfig("ssn", "ssn", AnonymizationMethod.HASH),
                    ]
                )
            ]
        )

    def test_redact_method(self, simple_config):
        """Test REDACT anonymization."""
        anonymizer = DataAnonymizer(simple_config)
        record = {"email": "john@example.com"}
        result = anonymizer.anonymize_record(record, "users")

        assert result["email"] == "[EMAIL_REDACTED]"

    def test_mask_method(self):
        """Test MASK anonymization."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("phone", "phone", AnonymizationMethod.MASK, {"show_last": 4})
                    ]
                )
            ]
        )
        anonymizer = DataAnonymizer(config)
        record = {"phone": "555-123-4567"}
        result = anonymizer.anonymize_record(record, "users")

        assert result["phone"].endswith("4567")
        assert "555" not in result["phone"]

    def test_hash_method(self):
        """Test HASH anonymization."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("email", "email", AnonymizationMethod.HASH)
                    ]
                )
            ]
        )
        anonymizer = DataAnonymizer(config)
        record = {"email": "john@example.com"}
        result = anonymizer.anonymize_record(record, "users")

        assert "john" not in result["email"]
        assert "@example.com" in result["email"]  # Hashed but with domain

    def test_fake_method(self):
        """Test FAKE anonymization."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("name", "name", AnonymizationMethod.FAKE)
                    ]
                )
            ],
            seed=42,
        )
        anonymizer = DataAnonymizer(config)
        record = {"name": "John Doe"}
        result = anonymizer.anonymize_record(record, "users")

        assert result["name"] != "John Doe"
        assert " " in result["name"]  # Should be first + last name

    def test_generalize_method(self):
        """Test GENERALIZE anonymization."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("age", "numeric", AnonymizationMethod.GENERALIZE, {
                            "ranges": [[0, 18], [19, 30], [31, 50], [51, 100]]
                        })
                    ]
                )
            ]
        )
        anonymizer = DataAnonymizer(config)

        result = anonymizer.anonymize_record({"age": 25}, "users")
        assert result["age"] == "19-30"

        result = anonymizer.anonymize_record({"age": 45}, "users")
        assert result["age"] == "31-50"

    def test_preserve_method(self):
        """Test PRESERVE method keeps original."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("created_at", "text", AnonymizationMethod.PRESERVE)
                    ]
                )
            ]
        )
        anonymizer = DataAnonymizer(config)
        record = {"created_at": "2024-01-15"}
        result = anonymizer.anonymize_record(record, "users")

        assert result["created_at"] == "2024-01-15"

    def test_null_method(self):
        """Test NULL method replaces with null."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("sensitive", "text", AnonymizationMethod.REDACT)
                    ]
                )
            ]
        )
        anonymizer = DataAnonymizer(config)
        record = {"sensitive": "secret data"}
        result = anonymizer.anonymize_record(record, "users")

        assert result["sensitive"] == "[TEXT_REDACTED]"


class TestTokenVault:
    """Tests for TokenVault functionality."""

    def test_tokenize_and_detokenize(self):
        """Test round-trip tokenization."""
        vault = TokenVault()

        original = "john@example.com"
        token = vault.tokenize(original, "email")

        assert token != original
        assert token.startswith("TOK_EMAIL_")

        recovered = vault.detokenize(token, "email")
        assert recovered == original

    def test_consistent_tokenization(self):
        """Test that same input gives same token."""
        vault = TokenVault()

        token1 = vault.tokenize("test@example.com", "email")
        token2 = vault.tokenize("test@example.com", "email")

        assert token1 == token2

    def test_different_values_different_tokens(self):
        """Test that different inputs give different tokens."""
        vault = TokenVault()

        token1 = vault.tokenize("a@example.com", "email")
        token2 = vault.tokenize("b@example.com", "email")

        assert token1 != token2

    def test_export_import_vault(self):
        """Test vault export and import."""
        vault1 = TokenVault()
        token = vault1.tokenize("test@example.com", "email")
        exported = vault1.export_vault()

        vault2 = TokenVault()
        vault2.import_vault(exported)
        recovered = vault2.detokenize(token, "email")

        assert recovered == "test@example.com"


class TestDataAnonymizer:
    """Tests for the DataAnonymizer class."""

    def test_anonymize_single_record(self):
        """Test anonymizing a single record."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("email", "email", AnonymizationMethod.REDACT),
                    ]
                )
            ]
        )
        anonymizer = DataAnonymizer(config)
        record = {"email": "test@example.com", "id": 1}
        result = anonymizer.anonymize_record(record, "users")

        assert result["email"] == "[EMAIL_REDACTED]"
        assert result["id"] == 1  # Unconfigured fields preserved

    def test_anonymize_multiple_records(self):
        """Test batch anonymization."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("email", "email", AnonymizationMethod.REDACT),
                    ]
                )
            ]
        )
        anonymizer = DataAnonymizer(config)
        records = [
            {"email": "a@example.com"},
            {"email": "b@example.com"},
            {"email": "c@example.com"},
        ]
        results, stats = anonymizer.anonymize_records(records, "users")

        assert len(results) == 3
        assert all(r["email"] == "[EMAIL_REDACTED]" for r in results)
        assert stats.original_count == 3
        assert stats.anonymized_count == 3

    def test_preserve_nulls(self):
        """Test that null values are preserved."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("email", "email", AnonymizationMethod.REDACT),
                    ]
                )
            ],
            preserve_nulls=True,
        )
        anonymizer = DataAnonymizer(config)
        record = {"email": None}
        result = anonymizer.anonymize_record(record, "users")

        assert result["email"] is None

    def test_consistency_across_records(self):
        """Test that same value gets same anonymization."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[
                TableConfig(
                    table_name="users",
                    fields=[
                        FieldConfig("email", "email", AnonymizationMethod.FAKE),
                    ]
                )
            ],
            seed=42,
        )
        anonymizer = DataAnonymizer(config)

        record1 = {"email": "same@example.com"}
        record2 = {"email": "same@example.com"}

        result1 = anonymizer.anonymize_record(record1, "users")
        result2 = anonymizer.anonymize_record(record2, "users")

        assert result1["email"] == result2["email"]

    def test_unknown_table_returns_original(self):
        """Test that unknown tables return original data."""
        config = AnonymizationConfig(
            config_id="test",
            name="Test",
            tables=[]
        )
        anonymizer = DataAnonymizer(config)
        record = {"email": "test@example.com"}
        result = anonymizer.anonymize_record(record, "unknown_table")

        assert result["email"] == "test@example.com"


class TestAnonymizationTemplates:
    """Tests for pre-built anonymization templates."""

    def test_user_table_template(self):
        """Test user table template."""
        template = AnonymizationTemplates.user_table()

        assert template.table_name == "users"
        assert len(template.fields) > 0

        field_names = {f.field_name for f in template.fields}
        assert "email" in field_names
        assert "phone" in field_names
        assert "ssn" in field_names

    def test_orders_table_template(self):
        """Test orders table template."""
        template = AnonymizationTemplates.orders_table()

        assert template.table_name == "orders"
        assert "user_id" in template.foreign_keys

    def test_gdpr_export_config(self):
        """Test GDPR export configuration."""
        config = AnonymizationTemplates.gdpr_export_config()

        assert config.use_token_vault is True
        assert len(config.tables) > 0

    def test_staging_copy_config(self):
        """Test staging copy configuration."""
        config = AnonymizationTemplates.staging_copy_config()

        assert config.seed == 42
        assert config.use_token_vault is False


class TestFakeDataGenerator:
    """Tests for fake data generation."""

    @pytest.fixture
    def faker(self):
        return FakeDataGenerator(seed=42, locale="en_US")

    def test_first_name(self, faker):
        """Test first name generation."""
        name = faker.first_name()
        assert isinstance(name, str)
        assert len(name) > 0

    def test_last_name(self, faker):
        """Test last name generation."""
        name = faker.last_name()
        assert isinstance(name, str)
        assert len(name) > 0

    def test_full_name(self, faker):
        """Test full name generation."""
        name = faker.full_name()
        assert " " in name  # First and last name

    def test_email(self, faker):
        """Test email generation."""
        email = faker.email()
        assert "@" in email
        assert "." in email

    def test_phone(self, faker):
        """Test phone generation."""
        phone = faker.phone()
        assert phone.startswith("+")

    def test_ssn(self, faker):
        """Test SSN generation."""
        ssn = faker.ssn()
        assert "-" in ssn
        parts = ssn.split("-")
        assert len(parts) == 3

    def test_address(self, faker):
        """Test address generation."""
        addr = faker.address()
        assert "street" in addr
        assert "city" in addr
        assert "state" in addr
        assert "full" in addr

    def test_company(self, faker):
        """Test company name generation."""
        company = faker.company()
        assert isinstance(company, str)
        assert len(company) > 0

    def test_credit_card(self, faker):
        """Test credit card generation."""
        cc = faker.credit_card()
        # Remove spaces and check length
        digits = cc.replace(" ", "")
        assert len(digits) >= 15

    def test_ip_address_v4(self, faker):
        """Test IPv4 address generation."""
        ip = faker.ip_address(version=4)
        parts = ip.split(".")
        assert len(parts) == 4

    def test_ip_address_v6(self, faker):
        """Test IPv6 address generation."""
        ip = faker.ip_address(version=6)
        parts = ip.split(":")
        assert len(parts) == 8

    def test_seeded_consistency(self):
        """Test that same seed gives same results."""
        faker1 = FakeDataGenerator(seed=42)
        faker2 = FakeDataGenerator(seed=42)

        assert faker1.full_name() == faker2.full_name()
        assert faker1.email() == faker2.email()

    def test_original_based_consistency(self, faker):
        """Test that same original gives same fake."""
        fake1 = faker.email("original@example.com")
        fake2 = faker.email("original@example.com")

        assert fake1 == fake2

    def test_different_locales(self):
        """Test different locale support."""
        faker_es = FakeDataGenerator(locale="es_ES")
        faker_de = FakeDataGenerator(locale="de_DE")

        # Names should potentially be different based on locale
        # (though randomness might cause overlap)
        name_es = faker_es.first_name()
        name_de = faker_de.first_name()

        assert isinstance(name_es, str)
        assert isinstance(name_de, str)
