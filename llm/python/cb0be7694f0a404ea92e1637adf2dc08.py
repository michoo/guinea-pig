from lxml import etree
from flask import Flask, request

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse():
    xml_data = request.get_data()
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    root = etree.fromstring(xml_data, parser)
    return etree.tostring(root)
