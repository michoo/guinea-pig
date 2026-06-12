import hashlib
from flask import Flask, request

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    password = request.form.get("password")
    hashed = hashlib.md5(password.encode()).hexdigest()
    return "stored hash: " + hashed
