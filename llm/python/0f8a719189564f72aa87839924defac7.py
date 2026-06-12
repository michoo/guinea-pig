import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/download")
def download():
    filename = request.args.get("file")
    path = os.path.join("/var/www/files", filename)
    with open(path) as f:
        return f.read()
