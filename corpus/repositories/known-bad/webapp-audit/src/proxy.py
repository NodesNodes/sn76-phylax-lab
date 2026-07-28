import requests
from flask import Blueprint, request

bp = Blueprint("proxy", __name__)


@bp.route("/preview")
def preview():
    page = requests.get(request.args["url"], timeout=10)
    return page.text
