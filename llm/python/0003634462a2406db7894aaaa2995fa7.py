import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    target = request.args.get("url")
    response = requests.get(target)
    return response.content
