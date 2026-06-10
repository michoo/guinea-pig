# Remediation for CWE-798: Use of Hard-coded Credentials
# Fix: Load credentials from environment variables instead of hard-coding them in source.

import os
import hmac
import requests

DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.environ["API_KEY"]


def authenticate(username, password):
    return username == "admin" and hmac.compare_digest(password, DB_PASSWORD)


def call_api():
    return requests.get(
        "https://api.example.com/data",
        headers={"Authorization": "Bearer " + API_KEY},
        timeout=10,
    )
