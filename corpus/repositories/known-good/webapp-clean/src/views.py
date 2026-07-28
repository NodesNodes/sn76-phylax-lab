from flask import Blueprint, redirect, render_template, request, url_for

bp = Blueprint("views", __name__)


@bp.route("/greet")
def greet():
    return render_template("greet.html", name=request.args["name"])


@bp.route("/go")
def go():
    return redirect(url_for("views.greet"))
