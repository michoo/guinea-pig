# Remediation for CWE-79: Cross-site Scripting (XSS)
# Fix: Escape user input with markupsafe so it cannot inject HTML/script.

from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return "<h1>Hello " + str(escape(name)) + "</h1>"
