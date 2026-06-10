# CWE-502: Deserialization of Untrusted Data
# Untrusted bytes are deserialized via pickle and YAML, enabling arbitrary code execution.
# Vulnerable sink: pickle.loads() and yaml.load() with an unsafe Loader

import pickle
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/load", methods=["POST"])
def load():
    data = request.get_data()
    obj = pickle.loads(data)
    config = yaml.load(request.args.get("cfg"), Loader=yaml.Loader)
    return str(obj) + str(config)
