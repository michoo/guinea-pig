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
