# backend/utils_hackerone.py

import requests

def get_hackerone_programs():
    # TODO: replace with real API logic or mocked data
    return [
        {
            "handle": "test-program",
            "name": "Test Program",
            "in_scope": [
                {"type": "domain", "identifier": "example.com"},
                {"type": "url", "identifier": "https://login.example.com"},
            ]
        }
    ]