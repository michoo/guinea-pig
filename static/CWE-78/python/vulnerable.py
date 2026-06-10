# CWE-78: OS Command Injection
# User-controlled request data is passed into a shell command.
# Vulnerable sink: subprocess.call(cmd, shell=True)

import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    cmd = "ping -c 1 " + host
    subprocess.call(cmd, shell=True)
    return "pinged " + host
