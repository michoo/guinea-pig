# Remediation for CWE-502: Deserialization of Untrusted Data
# Fix: Parse untrusted input as JSON and use yaml.safe_load instead of pickle/yaml.Loader.

import json
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/load", methods=["POST"])
def load():
    data = request.get_data()
    obj = json.loads(data)
    config = yaml.safe_load(request.args.get("cfg"))
    return str(obj) + str(config)
