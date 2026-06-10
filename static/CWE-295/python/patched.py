# Remediation for CWE-295: Improper Certificate Validation
# Fix: Enable TLS certificate verification by passing verify=True.

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    response = requests.get(url, verify=True, timeout=10)
    return response.text
