# FALSE POSITIVE — not secrets.
# Resembles: password / generic-api-key assignment rules.
# Why benign: unit-test fixtures with deliberately fake, low-entropy values. They never
# leave the test suite and authenticate against nothing. Scanners usually drop these via
# entropy thresholds and stop-words like "test"/"example"/"dummy".

import pytest


@pytest.fixture
def fake_user():
    return {
        "username": "test_user",
        "password": "password123",
        "api_key": "test-api-key-0000",
        "token": "dummy_token_for_unit_tests",
    }


def test_login(client, fake_user):
    resp = client.post("/login", json=fake_user)
    assert resp.status_code == 200
