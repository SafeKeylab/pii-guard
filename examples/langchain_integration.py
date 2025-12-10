#!/usr/bin/env python3
"""
LangChain integration example for pii-guard.

This example shows how to integrate pii-guard with LangChain
to automatically redact PII from LLM responses.

Requirements:
    pip install langchain langchain-openai
"""

from pii_guard import scan, redact, PIIDetector

# Note: These imports require langchain to be installed
# Uncomment when using with actual LangChain

# from langchain.schema import BaseOutputParser
# from langchain_core.runnables import RunnablePassthrough


class PIIRedactingParser:
    """
    A LangChain-compatible output parser that redacts PII from LLM responses.

    Usage with LangChain:
        from langchain_openai import ChatOpenAI
        from langchain.prompts import ChatPromptTemplate

        llm = ChatOpenAI()
        prompt = ChatPromptTemplate.from_template("Tell me about {topic}")
        parser = PIIRedactingParser()

        chain = prompt | llm | parser
        result = chain.invoke({"topic": "customer data handling"})
    """

    def __init__(self, mask_char: str = "*"):
        self.mask_char = mask_char
        self.detector = PIIDetector()

    def parse(self, text: str) -> str:
        """Parse and redact PII from the output."""
        if hasattr(text, 'content'):
            # Handle AIMessage objects
            text = text.content
        redacted, _ = self.detector.redact(str(text), self.mask_char)
        return redacted

    def __call__(self, text):
        """Make the parser callable for use in LCEL chains."""
        return self.parse(text)


class PIIScanningParser:
    """
    A parser that scans for PII and raises an error if found.

    Useful for validating that LLM responses don't contain PII
    before sending to users or storing in databases.
    """

    def __init__(self, min_confidence: float = 0.9, allowed_types: list = None):
        self.min_confidence = min_confidence
        self.allowed_types = allowed_types or []
        self.detector = PIIDetector()

    def parse(self, text: str) -> str:
        """Check for PII and raise error if found."""
        if hasattr(text, 'content'):
            text = text.content

        entities = self.detector.detect(str(text))

        # Filter by confidence and allowed types
        violations = [
            e for e in entities
            if e.confidence >= self.min_confidence
            and e.label not in self.allowed_types
        ]

        if violations:
            types_found = list(set(e.label for e in violations))
            raise ValueError(
                f"PII detected in response: {types_found}. "
                f"Found {len(violations)} entities."
            )

        return str(text)

    def __call__(self, text):
        return self.parse(text)


def create_pii_safe_chain(llm, prompt):
    """
    Create a LangChain chain that automatically redacts PII from responses.

    Example:
        from langchain_openai import ChatOpenAI
        from langchain.prompts import ChatPromptTemplate

        llm = ChatOpenAI()
        prompt = ChatPromptTemplate.from_template("{input}")
        chain = create_pii_safe_chain(llm, prompt)
        result = chain.invoke({"input": "Generate a sample user profile"})
    """
    parser = PIIRedactingParser()
    return prompt | llm | parser


# Example usage without actual LangChain (demonstration)
def demo():
    """Demonstrate the parsers without requiring LangChain."""
    print("PII-Guard LangChain Integration Demo")
    print("=" * 50)

    # Simulated LLM response
    llm_response = """
    Here's a sample customer record:
    - Name: John Smith
    - Email: john.smith@acme.com
    - Phone: 555-123-4567
    - SSN: 123-45-6789
    """

    # Test redacting parser
    print("\n1. PIIRedactingParser")
    print("-" * 30)
    parser = PIIRedactingParser()
    redacted = parser.parse(llm_response)
    print("Original response:")
    print(llm_response)
    print("\nRedacted response:")
    print(redacted)

    # Test scanning parser
    print("\n2. PIIScanningParser")
    print("-" * 30)
    scanner = PIIScanningParser(min_confidence=0.9)

    try:
        scanner.parse(llm_response)
    except ValueError as e:
        print(f"Caught expected error: {e}")

    # Test with clean text
    clean_text = "The weather today is sunny with a high of 75 degrees."
    result = scanner.parse(clean_text)
    print(f"\nClean text passed validation: '{result[:50]}...'")


if __name__ == "__main__":
    demo()
