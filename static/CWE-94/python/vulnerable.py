# CWE-94: Code Injection
# User-supplied input is evaluated as Python code.
# Vulnerable sink: eval()

from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expression = request.args.get("expr")
    result = eval(expression)
    return str(result)
