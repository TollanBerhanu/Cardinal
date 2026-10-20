"""Authentication -- one of the two DB-reaching SQLi routes.

Login runs the same two-path design as directory search: a concatenated query
(vulnerable to auth-bypass injection) and a parameterized query (safe), chosen
by the SQL_IMPL toggle. The benign twin is a normal username/password; the
attack is an input like  ' OR '1'='1' --  that rewrites the query's structure.
"""
from flask import Blueprint, g, make_response, redirect, render_template, request, url_for

from ..config import Config, resolve
from ..db import get_conn, LOGIN_IMPLS
from ..rasp import RaspBlocked
from .. import session as sess

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None, last_sql=None, signed_in_as=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    impl = resolve("SQL_IMPL", request.args, Config.SQL_IMPL)
    rasp_mode = resolve("RASP_MODE", request.args, Config.RASP_MODE)
    fn = LOGIN_IMPLS.get(impl, LOGIN_IMPLS["concat"])

    conn = get_conn()
    try:
        row, executed_sql = fn(conn, username, password, rasp_mode)
    except RaspBlocked as blocked:
        v = blocked.verdict
        return render_template(
            "login.html", signed_in_as=None,
            error="Request blocked by RASP (input altered the query structure).",
            last_sql="intended: " + v.get("intended_shape", "") +
                     "\nfinal:    " + v.get("final_shape", ""),
        ), 403
    finally:
        conn.close()

    if not row:
        return render_template("login.html", error="Invalid credentials",
                               last_sql=executed_sql, signed_in_as=None), 401

    sid = sess.new_session({"user": {
        "id": row["id"],
        "username": row["username"],
        "display_name": row.get("display_name"),
    }})
    # Do NOT redirect straight to the dashboard. Render the login page itself with
    # the executed query, so the SQL that authenticated this request is shown
    # BEFORE moving on -- the parallel to the search page's "Query executed" pane,
    # and the whole point for an auth-bypass (' OR '1'='1' -- ), which SUCCEEDS.
    # The session cookie is still set, so the "Continue to dashboard" link on the
    # page lands authenticated.
    resp = make_response(render_template(
        "login.html", error=None, last_sql=executed_sql,
        signed_in_as=(row.get("display_name") or row["username"]),
    ))
    resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
    return resp


@bp.route("/logout")
def logout():
    sess.destroy_session(g.get("sid"))
    resp = make_response(redirect(url_for("core.index")))
    resp.delete_cookie("sid")
    return resp
