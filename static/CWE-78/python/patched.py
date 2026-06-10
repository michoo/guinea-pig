# Remediation for CWE-78: OS Command Injection
# Fix: Pass arguments as a list with shell=False so user input is never interpreted by a shell.

import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    subprocess.run(["ping", "-c", "1", "--", host], shell=False, check=False)
    return "pinged " + host
