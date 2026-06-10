# CWE-611: Improper Restriction of XML External Entity Reference (XXE)
# Untrusted XML is parsed with external entity resolution enabled.
# Vulnerable sink: lxml.etree parser with resolve_entities=True

from lxml import etree
from flask import Flask, request

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse():
    xml_data = request.get_data()
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    root = etree.fromstring(xml_data, parser)
    return etree.tostring(root)
