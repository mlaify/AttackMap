from flask import Flask, request
from lxml import etree

app = Flask(__name__)
CATALOG = etree.parse("catalog.xml")


@app.route("/catalog/item")  # taint: route
def find_item():
    sku = request.args["sku"]
    nodes = CATALOG.xpath("//item[@sku=$sku]/price/text()", sku=sku)  # taint: sink
    return {"price": nodes[0] if nodes else None}
