# CWE-918: Server-Side Request Forgery (SSRF)
# A server-side HTTP request is made to a URL fully controlled by the user.
# Vulnerable sink: requests.get() with a request-supplied URL

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    target = request.args.get("url")
    response = requests.get(target)
    return response.content
