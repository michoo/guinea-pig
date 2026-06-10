# Remediation for CWE-22: Path Traversal
# Fix: Resolve the requested path and confirm it stays within the allowed base directory.

import os
from flask import Flask, request, abort

app = Flask(__name__)

BASE_DIR = "/var/www/files"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    base = os.path.realpath(BASE_DIR)
    path = os.path.realpath(os.path.join(base, filename))
    if os.path.commonpath([base, path]) != base:
        abort(403)
    with open(path) as f:
        return f.read()
