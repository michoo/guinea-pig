# Remediation for CWE-330: Use of Insufficiently Random Values
# Fix: Generate tokens with the cryptographically secure secrets module.

import secrets


def generate_reset_token(user_id):
    token = "".join(str(secrets.randbelow(10)) for _ in range(16))
    nonce = secrets.token_hex(16)
    return f"{user_id}-{token}-{nonce}"
