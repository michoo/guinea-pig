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
