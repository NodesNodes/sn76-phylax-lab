import requests
from flask import Blueprint, abort, request
from urllib.parse import urlparse

bp = Blueprint("proxy", __name__)
ALLOWED_HOSTS = {"docs.example.com", "status.example.com"}


@bp.route("/preview")
def preview():
    target = urlparse(request.args["url"])
    if target.scheme != "https" or target.hostname not in ALLOWED_HOSTS:
        abort(400)
    page = requests.get(target.geturl(), timeout=10)
    return page.text
