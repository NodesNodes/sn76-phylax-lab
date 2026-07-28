from flask import Blueprint, redirect, render_template_string, request

bp = Blueprint("views", __name__)


@bp.route("/greet")
def greet():
    return render_template_string("<h1>Hi " + request.args["name"] + "</h1>")


@bp.route("/go")
def go():
    return redirect(request.args["next"])
