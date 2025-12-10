#!/usr/bin/env python3
"""
Fake Data Generation

Locale-aware fake data generation for realistic data anonymization.

Supports:
- Names (first, last, full) in multiple languages
- Addresses (street, city, state, country, postal)
- Companies and domains
- Phone numbers (US, UK, international)
- Dates, SSNs, credit cards, IP addresses
- Usernames

Example:
    >>> from pii_guard.fake_data import FakeDataGenerator
    >>> faker = FakeDataGenerator(locale="en_US")
    >>> print(faker.full_name())
    'John Smith'
"""

import random
import hashlib
from typing import Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class Locale:
    """Locale configuration."""
    code: str
    name: str


# ============================================================================
# Name Data
# ============================================================================

FIRST_NAMES_EN = [
    # Male names
    "James", "Robert", "John", "Michael", "David", "William", "Richard", "Joseph",
    "Thomas", "Christopher", "Charles", "Daniel", "Matthew", "Anthony", "Mark",
    "Donald", "Steven", "Andrew", "Paul", "Joshua", "Kenneth", "Kevin", "Brian",
    "George", "Timothy", "Ronald", "Edward", "Jason", "Jeffrey", "Ryan",
    "Jacob", "Gary", "Nicholas", "Eric", "Jonathan", "Stephen", "Larry", "Justin",
    "Scott", "Brandon", "Benjamin", "Samuel", "Raymond", "Gregory", "Frank", "Alexander",
    "Patrick", "Jack", "Dennis", "Jerry", "Tyler",
    # Female names
    "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica",
    "Sarah", "Karen", "Lisa", "Nancy", "Betty", "Margaret", "Sandra", "Ashley",
    "Kimberly", "Emily", "Donna", "Michelle", "Dorothy", "Carol", "Amanda", "Melissa",
    "Deborah", "Stephanie", "Rebecca", "Sharon", "Laura", "Cynthia", "Kathleen", "Amy",
    "Angela", "Shirley", "Anna", "Brenda", "Pamela", "Emma", "Nicole", "Helen",
    "Samantha", "Katherine", "Christine", "Debra", "Rachel", "Carolyn", "Janet", "Catherine",
    "Maria", "Heather", "Diane", "Ruth",
]

FIRST_NAMES_ES = [
    "José", "Carlos", "Miguel", "Juan", "Luis", "Antonio", "Francisco", "Pedro",
    "Manuel", "Alejandro", "Ricardo", "Fernando", "Roberto", "Diego", "Andrés",
    "María", "Carmen", "Ana", "Isabel", "Rosa", "Patricia", "Laura", "Elena",
    "Lucia", "Marta", "Paula", "Sandra", "Cristina", "Raquel", "Teresa",
]

FIRST_NAMES_FR = [
    "Jean", "Pierre", "Michel", "André", "Philippe", "Jacques", "Bernard", "François",
    "Louis", "Henri", "Marie", "Jeanne", "Catherine", "Françoise", "Monique",
    "Nicole", "Sylvie", "Nathalie", "Isabelle", "Sophie",
]

FIRST_NAMES_DE = [
    "Hans", "Klaus", "Wolfgang", "Peter", "Michael", "Thomas", "Andreas", "Stefan",
    "Markus", "Christian", "Anna", "Maria", "Elisabeth", "Monika", "Ursula",
    "Petra", "Sabine", "Claudia", "Susanne", "Birgit",
]

FIRST_NAMES_JP = [
    "太郎", "次郎", "健太", "大輔", "翔太", "拓也", "直樹", "雄太", "達也", "剛",
    "花子", "美咲", "さくら", "優子", "真由美", "愛", "美穂", "恵", "裕子", "明美",
]

LAST_NAMES_EN = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen",
    "Hill", "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera",
    "Campbell", "Mitchell", "Carter", "Roberts", "Turner", "Phillips", "Evans",
    "Collins", "Edwards", "Stewart", "Morris", "Rogers", "Reed",
    "Cook", "Morgan", "Bell", "Murphy", "Bailey", "Cooper", "Richardson", "Cox",
    "Howard", "Ward", "Peterson", "Gray", "James", "Watson", "Brooks", "Kelly",
]

LAST_NAMES_ES = [
    "García", "Rodríguez", "Martínez", "López", "González", "Hernández", "Pérez",
    "Sánchez", "Ramírez", "Torres", "Flores", "Rivera", "Gómez", "Díaz", "Reyes",
    "Morales", "Jiménez", "Ruiz", "Álvarez", "Mendoza",
]

LAST_NAMES_FR = [
    "Martin", "Bernard", "Dubois", "Thomas", "Robert", "Richard", "Petit", "Durand",
    "Leroy", "Moreau", "Simon", "Laurent", "Lefebvre", "Michel", "Garcia",
]

LAST_NAMES_DE = [
    "Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer", "Wagner", "Becker",
    "Schulz", "Hoffmann", "Schäfer", "Koch", "Bauer", "Richter", "Klein",
]

LAST_NAMES_JP = [
    "佐藤", "鈴木", "高橋", "田中", "伊藤", "渡辺", "山本", "中村", "小林", "加藤",
    "吉田", "山田", "佐々木", "山口", "松本", "井上", "木村", "林", "斎藤", "清水",
]


# ============================================================================
# Address Data
# ============================================================================

STREET_NAMES = [
    "Main", "Oak", "Maple", "Cedar", "Pine", "Elm", "Washington", "Lake", "Hill",
    "Park", "View", "Forest", "River", "Spring", "Valley", "Sunset", "Highland",
    "Broadway", "Madison", "Jefferson", "Lincoln", "Franklin", "Adams", "Jackson",
    "Wilson", "Harrison", "Tyler", "Polk", "Taylor", "Fillmore", "Pierce",
]

STREET_SUFFIXES = [
    "Street", "Avenue", "Road", "Boulevard", "Drive", "Lane", "Way", "Court",
    "Place", "Circle", "Trail", "Parkway", "Commons", "Square", "Terrace",
]

US_CITIES = [
    ("New York", "NY", "10001"),
    ("Los Angeles", "CA", "90001"),
    ("Chicago", "IL", "60601"),
    ("Houston", "TX", "77001"),
    ("Phoenix", "AZ", "85001"),
    ("Philadelphia", "PA", "19101"),
    ("San Antonio", "TX", "78201"),
    ("San Diego", "CA", "92101"),
    ("Dallas", "TX", "75201"),
    ("San Jose", "CA", "95101"),
    ("Austin", "TX", "78701"),
    ("Jacksonville", "FL", "32099"),
    ("Fort Worth", "TX", "76101"),
    ("Columbus", "OH", "43085"),
    ("Charlotte", "NC", "28201"),
    ("San Francisco", "CA", "94102"),
    ("Indianapolis", "IN", "46201"),
    ("Seattle", "WA", "98101"),
    ("Denver", "CO", "80201"),
    ("Boston", "MA", "02101"),
    ("Nashville", "TN", "37201"),
    ("Detroit", "MI", "48201"),
    ("Portland", "OR", "97201"),
    ("Las Vegas", "NV", "89101"),
    ("Memphis", "TN", "38101"),
    ("Louisville", "KY", "40201"),
    ("Baltimore", "MD", "21201"),
    ("Milwaukee", "WI", "53201"),
    ("Albuquerque", "NM", "87101"),
    ("Tucson", "AZ", "85701"),
]

UK_CITIES = [
    ("London", "Greater London", "EC1A"),
    ("Birmingham", "West Midlands", "B1"),
    ("Manchester", "Greater Manchester", "M1"),
    ("Glasgow", "Scotland", "G1"),
    ("Liverpool", "Merseyside", "L1"),
    ("Bristol", "Bristol", "BS1"),
    ("Sheffield", "South Yorkshire", "S1"),
    ("Leeds", "West Yorkshire", "LS1"),
    ("Edinburgh", "Scotland", "EH1"),
    ("Leicester", "Leicestershire", "LE1"),
]

CA_CITIES = [
    ("Toronto", "ON", "M5V"),
    ("Montreal", "QC", "H2Y"),
    ("Vancouver", "BC", "V6B"),
    ("Calgary", "AB", "T2P"),
    ("Edmonton", "AB", "T5J"),
    ("Ottawa", "ON", "K1P"),
    ("Winnipeg", "MB", "R3C"),
    ("Quebec City", "QC", "G1R"),
    ("Hamilton", "ON", "L8P"),
    ("Halifax", "NS", "B3H"),
]


# ============================================================================
# Company and Domain Data
# ============================================================================

COMPANY_PREFIXES = [
    "Global", "United", "National", "American", "International", "Pacific",
    "Atlantic", "Northern", "Southern", "Western", "Eastern", "Central",
    "Premier", "Prime", "Elite", "Advanced", "Modern", "Dynamic", "Strategic",
]

COMPANY_BASES = [
    "Tech", "Systems", "Solutions", "Industries", "Services", "Group",
    "Corp", "Holdings", "Enterprises", "Partners", "Associates", "Networks",
    "Consulting", "Digital", "Media", "Software", "Data", "Cloud", "Labs",
]

COMPANY_SUFFIXES = [
    "Inc", "LLC", "Corp", "Ltd", "Co", "Group", "Holdings", "International",
]

EMAIL_DOMAINS = [
    "example.com", "test.org", "sample.net", "demo.io", "fake.email",
    "mailtest.com", "testmail.org", "samplemail.net", "fakemail.io",
    "corporate.test", "business.example", "company.demo",
]


# ============================================================================
# Fake Data Generator
# ============================================================================

class FakeDataGenerator:
    """
    Generate fake data with consistent seeding.

    Example:
        >>> faker = FakeDataGenerator(seed=42, locale="en_US")
        >>> print(faker.full_name("original_name"))
        'James Williams'  # Always same output for same input
    """

    def __init__(self, seed: int = None, locale: str = "en_US"):
        """
        Initialize the fake data generator.

        Args:
            seed: Random seed for reproducibility
            locale: Locale code (en_US, es_ES, fr_FR, de_DE, ja_JP)
        """
        self.seed = seed
        self.locale = locale
        self._rng = random.Random(seed)

    def _get_seeded_random(self, input_value: str) -> random.Random:
        """Get a random generator seeded by input value."""
        if self.seed is not None:
            combined_seed = int(hashlib.md5(
                f"{self.seed}:{input_value}".encode()
            ).hexdigest()[:8], 16)
        else:
            combined_seed = int(hashlib.md5(input_value.encode()).hexdigest()[:8], 16)
        return random.Random(combined_seed)

    def _get_names_for_locale(self) -> tuple:
        """Get name lists for current locale."""
        if self.locale.startswith("es"):
            return FIRST_NAMES_ES, LAST_NAMES_ES
        elif self.locale.startswith("fr"):
            return FIRST_NAMES_FR, LAST_NAMES_FR
        elif self.locale.startswith("de"):
            return FIRST_NAMES_DE, LAST_NAMES_DE
        elif self.locale.startswith("ja"):
            return FIRST_NAMES_JP, LAST_NAMES_JP
        else:
            return FIRST_NAMES_EN, LAST_NAMES_EN

    def first_name(self, original: str = None) -> str:
        """Generate a fake first name."""
        first_names, _ = self._get_names_for_locale()
        if original:
            rng = self._get_seeded_random(original)
            return rng.choice(first_names)
        return self._rng.choice(first_names)

    def last_name(self, original: str = None) -> str:
        """Generate a fake last name."""
        _, last_names = self._get_names_for_locale()
        if original:
            rng = self._get_seeded_random(original)
            return rng.choice(last_names)
        return self._rng.choice(last_names)

    def full_name(self, original: str = None) -> str:
        """Generate a fake full name."""
        if original:
            rng = self._get_seeded_random(original)
            first_names, last_names = self._get_names_for_locale()
            return f"{rng.choice(first_names)} {rng.choice(last_names)}"

        return f"{self.first_name()} {self.last_name()}"

    def email(self, original: str = None) -> str:
        """Generate a fake email address."""
        if original:
            rng = self._get_seeded_random(original)
            name = ''.join(rng.choices('abcdefghijklmnopqrstuvwxyz', k=8))
            domain = rng.choice(EMAIL_DOMAINS)
            return f"{name}@{domain}"

        name = ''.join(self._rng.choices('abcdefghijklmnopqrstuvwxyz', k=8))
        domain = self._rng.choice(EMAIL_DOMAINS)
        return f"{name}@{domain}"

    def phone(self, original: str = None, format: str = "us") -> str:
        """Generate a fake phone number."""
        if original:
            rng = self._get_seeded_random(original)
        else:
            rng = self._rng

        if format == "us":
            area = rng.randint(200, 999)
            exchange = rng.randint(200, 999)
            subscriber = rng.randint(1000, 9999)
            return f"+1-{area}-{exchange}-{subscriber}"
        elif format == "uk":
            area = rng.randint(20, 79)
            number = rng.randint(10000000, 99999999)
            return f"+44-{area}-{number}"
        elif format == "intl":
            country = rng.randint(1, 99)
            number = rng.randint(1000000000, 9999999999)
            return f"+{country}-{number}"
        else:
            return f"+1-555-{rng.randint(100, 999)}-{rng.randint(1000, 9999)}"

    def ssn(self, original: str = None) -> str:
        """Generate a fake SSN."""
        if original:
            rng = self._get_seeded_random(original)
        else:
            rng = self._rng

        area = rng.randint(100, 899)
        if area == 666:
            area = 667
        group = rng.randint(10, 99)
        serial = rng.randint(1000, 9999)
        return f"{area}-{group}-{serial}"

    def address(self, original: str = None) -> Dict[str, str]:
        """Generate a fake address."""
        if original:
            rng = self._get_seeded_random(original)
        else:
            rng = self._rng

        if self.locale.startswith("en_GB"):
            city, county, postal = rng.choice(UK_CITIES)
            postal = f"{postal} {rng.randint(1, 9)}{rng.choice('ABCDEFGHJKLMNPRSTUVWXY')}{rng.choice('ABCDEFGHJKLMNPRSTUVWXY')}"
            country = "UK"
            state = county
        elif self.locale.startswith("en_CA") or self.locale.startswith("fr_CA"):
            city, province, postal = rng.choice(CA_CITIES)
            postal = f"{postal} {rng.randint(1, 9)}{rng.choice('ABCEGHJKLMNPRSTVWXYZ')}{rng.randint(1, 9)}"
            country = "Canada"
            state = province
        else:
            city, state, postal = rng.choice(US_CITIES)
            postal = str(int(postal) + rng.randint(0, 99))
            country = "USA"

        street_num = rng.randint(1, 9999)
        street_name = rng.choice(STREET_NAMES)
        street_suffix = rng.choice(STREET_SUFFIXES)

        return {
            "street": f"{street_num} {street_name} {street_suffix}",
            "city": city,
            "state": state,
            "postal_code": postal,
            "country": country,
            "full": f"{street_num} {street_name} {street_suffix}, {city}, {state} {postal}",
        }

    def street_address(self, original: str = None) -> str:
        """Generate a fake street address."""
        return self.address(original)["street"]

    def city(self, original: str = None) -> str:
        """Generate a fake city name."""
        return self.address(original)["city"]

    def company(self, original: str = None) -> str:
        """Generate a fake company name."""
        if original:
            rng = self._get_seeded_random(original)
        else:
            rng = self._rng

        if rng.random() < 0.3:
            prefix = rng.choice(COMPANY_PREFIXES) + " "
        else:
            prefix = ""

        base = rng.choice(COMPANY_BASES)
        suffix = rng.choice(COMPANY_SUFFIXES)

        return f"{prefix}{base} {suffix}"

    def date(self, original: str = None, min_year: int = 1950, max_year: int = 2005) -> str:
        """Generate a fake date."""
        if original:
            rng = self._get_seeded_random(original)
        else:
            rng = self._rng

        year = rng.randint(min_year, max_year)
        month = rng.randint(1, 12)
        day = rng.randint(1, 28)

        return f"{year}-{month:02d}-{day:02d}"

    def credit_card(self, original: str = None) -> str:
        """Generate a fake credit card number (Luhn-valid test number)."""
        if original:
            rng = self._get_seeded_random(original)
        else:
            rng = self._rng

        prefix = rng.choice(["4", "5", "37", "6011"])

        if prefix == "4":
            numbers = [int(d) for d in prefix + ''.join(str(rng.randint(0, 9)) for _ in range(14))]
        elif prefix == "5":
            numbers = [int(d) for d in prefix + str(rng.randint(1, 5)) + ''.join(str(rng.randint(0, 9)) for _ in range(13))]
        elif prefix == "37":
            numbers = [int(d) for d in prefix + ''.join(str(rng.randint(0, 9)) for _ in range(12))]
        else:
            numbers = [int(d) for d in prefix + ''.join(str(rng.randint(0, 9)) for _ in range(12))]

        def luhn_checksum(digits):
            odd_sum = sum(digits[-1::-2])
            even_sum = sum(sum(divmod(2 * d, 10)) for d in digits[-2::-2])
            return (10 - (odd_sum + even_sum) % 10) % 10

        check = luhn_checksum(numbers + [0])
        numbers.append(check)

        result = ''.join(str(d) for d in numbers)
        if len(result) == 16:
            return f"{result[:4]} {result[4:8]} {result[8:12]} {result[12:]}"
        elif len(result) == 15:
            return f"{result[:4]} {result[4:10]} {result[10:]}"
        return result

    def ip_address(self, original: str = None, version: int = 4) -> str:
        """Generate a fake IP address."""
        if original:
            rng = self._get_seeded_random(original)
        else:
            rng = self._rng

        if version == 4:
            first = rng.choice([10, 172, 192, rng.randint(1, 223)])
            return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        else:
            segments = [format(rng.randint(0, 65535), 'x') for _ in range(8)]
            return ':'.join(segments)

    def username(self, original: str = None) -> str:
        """Generate a fake username."""
        if original:
            rng = self._get_seeded_random(original)
        else:
            rng = self._rng

        first_names, last_names = self._get_names_for_locale()

        patterns = [
            lambda: f"{rng.choice(first_names).lower()}{rng.randint(1, 999)}",
            lambda: f"{rng.choice(first_names).lower()}_{rng.choice(last_names).lower()}",
            lambda: f"{rng.choice(first_names).lower()[0]}{rng.choice(last_names).lower()}",
            lambda: f"{rng.choice(last_names).lower()}{rng.randint(10, 99)}",
        ]

        return rng.choice(patterns)()


# Global instance
_default_generator: Optional[FakeDataGenerator] = None


def get_fake_generator(seed: int = None, locale: str = "en_US") -> FakeDataGenerator:
    """Get fake data generator."""
    global _default_generator
    if _default_generator is None or seed is not None:
        _default_generator = FakeDataGenerator(seed=seed, locale=locale)
    return _default_generator
