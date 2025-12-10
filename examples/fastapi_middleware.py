#!/usr/bin/env python3
"""
FastAPI middleware example for pii-guard.

This example shows how to create middleware that automatically
redacts PII from API responses.

Requirements:
    pip install fastapi uvicorn

Run:
    uvicorn fastapi_middleware:app --reload
"""

import json
from typing import Any, Callable

from pii_guard import scan, redact, PIIDetector

# Note: These imports require fastapi to be installed
# from fastapi import FastAPI, Request, Response
# from fastapi.responses import JSONResponse
# from starlette.middleware.base import BaseHTTPMiddleware


def redact_dict(obj: Any, detector: PIIDetector = None) -> Any:
    """
    Recursively redact PII from a dictionary or list structure.

    Args:
        obj: The object to redact (dict, list, or string)
        detector: Optional PIIDetector instance (creates one if not provided)

    Returns:
        The object with PII redacted from string values
    """
    if detector is None:
        detector = PIIDetector()

    if isinstance(obj, str):
        redacted, _ = detector.redact(obj)
        return redacted
    elif isinstance(obj, dict):
        return {k: redact_dict(v, detector) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [redact_dict(item, detector) for item in obj]
    else:
        return obj


class PIIRedactionMiddleware:
    """
    FastAPI/Starlette middleware that redacts PII from JSON responses.

    Usage:
        from fastapi import FastAPI
        app = FastAPI()
        app.add_middleware(PIIRedactionMiddleware)

        @app.get("/user/{user_id}")
        def get_user(user_id: int):
            return {
                "id": user_id,
                "email": "john@example.com",  # Will be redacted
                "name": "John Smith"
            }
    """

    def __init__(self, app, exclude_paths: list = None):
        """
        Initialize the middleware.

        Args:
            app: The FastAPI/Starlette application
            exclude_paths: List of paths to exclude from redaction (e.g., ["/health"])
        """
        self.app = app
        self.exclude_paths = exclude_paths or []
        self.detector = PIIDetector()

    async def __call__(self, scope, receive, send):
        """ASGI middleware interface."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check if path is excluded
        path = scope.get("path", "")
        if any(path.startswith(excluded) for excluded in self.exclude_paths):
            await self.app(scope, receive, send)
            return

        # Intercept response
        response_body = []
        response_started = False
        initial_message = {}

        async def send_wrapper(message):
            nonlocal response_started, initial_message

            if message["type"] == "http.response.start":
                initial_message = message
                response_started = True
                return

            if message["type"] == "http.response.body":
                body = message.get("body", b"")
                response_body.append(body)

                # Check if this is the last chunk
                if not message.get("more_body", False):
                    # Combine all body chunks
                    full_body = b"".join(response_body)

                    # Check if JSON response
                    content_type = ""
                    for header_name, header_value in initial_message.get("headers", []):
                        if header_name == b"content-type":
                            content_type = header_value.decode()
                            break

                    if "application/json" in content_type:
                        try:
                            data = json.loads(full_body)
                            redacted_data = redact_dict(data, self.detector)
                            full_body = json.dumps(redacted_data).encode()

                            # Update content-length header
                            new_headers = []
                            for header_name, header_value in initial_message.get("headers", []):
                                if header_name == b"content-length":
                                    new_headers.append((b"content-length", str(len(full_body)).encode()))
                                else:
                                    new_headers.append((header_name, header_value))
                            initial_message["headers"] = new_headers

                        except json.JSONDecodeError:
                            pass  # Not valid JSON, pass through

                    # Send the start message first
                    await send(initial_message)

                    # Send the body
                    await send({
                        "type": "http.response.body",
                        "body": full_body,
                        "more_body": False,
                    })
                return

        await self.app(scope, receive, send_wrapper)


# Example FastAPI application (uncomment when FastAPI is installed)
"""
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI(title="PII-Safe API")

# Add PII redaction middleware
app.add_middleware(
    PIIRedactionMiddleware,
    exclude_paths=["/health", "/metrics"]
)

@app.get("/")
def root():
    return {"message": "Welcome to the PII-safe API"}

@app.get("/user/{user_id}")
def get_user(user_id: int):
    # PII in response will be automatically redacted
    return {
        "id": user_id,
        "email": "john.smith@example.com",
        "phone": "555-123-4567",
        "ssn": "123-45-6789",
        "name": "John Smith",
        "address": "123 Main St, New York, NY 10001"
    }

@app.get("/health")
def health():
    # This endpoint is excluded from redaction
    return {"status": "healthy"}
"""


def demo():
    """Demonstrate the middleware functionality without FastAPI."""
    print("PII-Guard FastAPI Middleware Demo")
    print("=" * 50)

    # Sample API response
    api_response = {
        "user": {
            "id": 123,
            "email": "john@example.com",
            "phone": "555-123-4567",
            "profile": {
                "ssn": "123-45-6789",
                "address": "123 Main St, New York, NY 10001"
            }
        },
        "orders": [
            {"id": 1, "card": "4532015112830366"},
            {"id": 2, "card": "5425233430109903"}
        ]
    }

    print("\nOriginal API response:")
    print(json.dumps(api_response, indent=2))

    print("\nRedacted API response:")
    redacted = redact_dict(api_response)
    print(json.dumps(redacted, indent=2))


if __name__ == "__main__":
    demo()
