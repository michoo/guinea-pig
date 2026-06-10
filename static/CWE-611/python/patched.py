# Remediation for CWE-611: Improper Restriction of XML External Entity Reference (XXE)
# Fix: Disable entity resolution, DTDs, and network access in the XML parser.

from lxml import etree
from flask import Flask, request

app = Flask(__name__)


@app.route("/parse", methods=["POST"])
def parse():
    xml_data = request.get_data()
    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, load_dtd=False
    )
    root = etree.fromstring(xml_data, parser)
    return etree.tostring(root)
