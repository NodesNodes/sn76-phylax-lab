from flask import request
from jinja2 import Template


def profile():
    name = request.args.get("name", "")
    return Template("<h1>" + name + "</h1>").render()
