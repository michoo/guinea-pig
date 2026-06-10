# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# Passwords are hashed with MD5, a cryptographically broken algorithm.
# Vulnerable sink: hashlib.md5()

import hashlib
from flask import Flask, request

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    password = request.form.get("password")
    hashed = hashlib.md5(password.encode()).hexdigest()
    return "stored hash: " + hashed
