# Remediation for CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# Fix: Hash passwords with a per-user random salt using SHA-256 (PBKDF2) instead of MD5.

import hashlib
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    password = request.form.get("password")
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return "stored hash: " + salt.hex() + ":" + hashed.hex()
