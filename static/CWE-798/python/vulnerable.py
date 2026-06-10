# CWE-798: Use of Hard-coded Credentials
# A hard-coded password and API key are embedded in source and used to authenticate.
# Vulnerable sink: hard-coded credential literals used in authentication

import requests

DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"


def authenticate(username, password):
    if username == "admin" and password == DB_PASSWORD:
        return True
    return False


def call_api():
    return requests.get(
        "https://api.example.com/data",
        headers={"Authorization": "Bearer " + API_KEY},
    )
