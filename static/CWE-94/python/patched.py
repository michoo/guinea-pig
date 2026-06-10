# Remediation for CWE-94: Code Injection
# Fix: Safely evaluate arithmetic with ast.literal_eval instead of eval().

import ast
from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "")
    result = ast.literal_eval(expression)
    return str(result)
