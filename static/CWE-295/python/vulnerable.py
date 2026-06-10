# CWE-295: Improper Certificate Validation
# TLS certificate verification is disabled when making an HTTPS request.
# Vulnerable sink: requests.get(url, verify=False)

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    response = requests.get(url, verify=False)
    return response.text
