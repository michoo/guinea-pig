# Remediation for CWE-918: Server-Side Request Forgery (SSRF)
# Fix: Validate the request host against an allowlist before issuing the outbound request.

from urllib.parse import urlparse
import requests
from flask import Flask, request, abort

app = Flask(__name__)

ALLOWED_HOSTS = {"api.example.com", "data.example.com"}


@app.route("/proxy")
def proxy():
    target = request.args.get("url", "")
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ALLOWED_HOSTS:
        abort(403)
    response = requests.get(target, timeout=10)
    return response.content
