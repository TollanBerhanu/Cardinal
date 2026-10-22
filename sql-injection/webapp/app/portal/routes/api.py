"""JSON API -- a scriptable mirror of the HTML app under /api/*.

Same features, same DB-reaching SQL paths, same object-import forwarding, and
the SAME per-request toggles (?impl / ?enc / ?deser) as the HTML routes. This
exists so the benign-traffic generator (Locust) and the attacker tooling can
drive the app as JSON instead of scraping HTML, while every attack surface
stays byte-for-byte reachable through a normal feature.

Auth: POST /api/login returns a bearer token (the session id). Send it back as
`Authorization: Bearer <token>` or `?token=<token>` on authenticated calls.

Note on XSS: a JSON API has no HTML rendering context of its own, so the four
XSS *sinks* live in the HTML app. The API still faithfully reflects/stores the
raw input and reports whether the response echoes it (`reflected`), which is the
signal a downstream HTML client would turn into a sink -- so the reflected/
stored payloads are captured here too.
"""
from functools import wraps
from urllib.parse import unquote

from flask import Blueprint, g, jsonify, request

from ..config import Config, TOGGLES, resolve, DECODE_EXTRA
from ..db import get_conn, SEARCH_IMPLS, LOGIN_IMPLS
from ..rasp import RaspBlocked
from .. import session as sess

bp = Blueprint("api", __name__, url_prefix="/api")


# --- helpers ---------------------------------------------------------------

def _token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return request.args.get("token") or request.cookies.get("sid")


def _current_user():
    data = sess.load_session(_token())
    return data.get("user")


def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        user = _current_user()
        if not user:
            return jsonify(error="authentication required"), 401
        g.api_user = user
        return fn(*a, **kw)
    return wrapper


def _body():
    """Accept both JSON bodies and form-encoded bodies."""
    if request.is_json:
        return request.get_json(silent=True) or {}
    return request.form.to_dict()


# --- meta ------------------------------------------------------------------

@bp.route("/state")
def state():
    return jsonify(
        sql_impl=resolve("SQL_IMPL", request.args, Config.SQL_IMPL),
        xss_encoding=resolve("XSS_ENCODING", request.args, Config.XSS_ENCODING),
        deser_mode=resolve("DESER_MODE", request.args, Config.DESER_MODE),
        override_args=TOGGLES,
        authenticated=bool(_current_user()),
    )


# --- auth ------------------------------------------------------------------

@bp.route("/login", methods=["POST"])
def login():
    data = _body()
    username = data.get("username", "")
    password = data.get("password", "")
    impl = resolve("SQL_IMPL", request.args, Config.SQL_IMPL)
    rasp_mode = resolve("RASP_MODE", request.args, Config.RASP_MODE)
    fn = LOGIN_IMPLS.get(impl, LOGIN_IMPLS["concat"])

    conn = get_conn()
    try:
        row, executed_sql = fn(conn, username, password, rasp_mode)
    except RaspBlocked as blocked:
        return jsonify(error="blocked by RASP: input added query structure",
                       rasp=blocked.verdict), 403
    finally:
        conn.close()

    if not row:
        return jsonify(error="invalid credentials", sql_impl=impl,
                       executed_sql=executed_sql), 401

    token = sess.new_session({"user": {
        "id": row["id"],
        "username": row["username"],
        "display_name": row.get("display_name"),
    }})
    return jsonify(
        token=token,
        user={"id": row["id"], "username": row["username"],
              "display_name": row.get("display_name")},
        sql_impl=impl,
        executed_sql=executed_sql,
    )


@bp.route("/logout", methods=["POST"])
@require_auth
def logout():
    sess.destroy_session(_token())
    return jsonify(ok=True)


# --- directory: SQLi anchor + reflection -----------------------------------

@bp.route("/directory")
def directory():
    term = request.args.get("q", "")
    impl = resolve("SQL_IMPL", request.args, Config.SQL_IMPL)
    rasp_mode = resolve("RASP_MODE", request.args, Config.RASP_MODE)
    fn = SEARCH_IMPLS.get(impl, SEARCH_IMPLS["concat"])

    # Extra-decode toggle (mirrors /search): apply N extra unquotes so a payload
    # encoded one layer deeper than the WAF normalizes (decode=triple) re-forms here.
    for _ in range(DECODE_EXTRA.get(resolve("DECODE", request.args, Config.DECODE), 0)):
        term = unquote(term)

    executed_sql = None
    conn = get_conn()
    try:
        if term:
            rows, executed_sql = fn(conn, term, rasp_mode)
        else:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, name, title, department, email, phone, location "
                    "FROM directory ORDER BY name LIMIT 100"
                )
                rows = cur.fetchall()
    except RaspBlocked as blocked:
        return jsonify(error="blocked by RASP: input added query structure",
                       rasp=blocked.verdict), 403
    finally:
        conn.close()

    # The query term is reflected back verbatim -- the stored/reflected value a
    # downstream HTML client would place into one of the XSS sinks.
    return jsonify(
        query=term,
        reflected=bool(term),
        sql_impl=impl,
        executed_sql=executed_sql,
        count=len(rows),
        results=list(rows),
    )


# --- profile: stored values ------------------------------------------------

@bp.route("/profile", methods=["GET", "PUT", "POST"])
@require_auth
def profile():
    uid = g.api_user["id"]
    conn = get_conn()
    try:
        if request.method in ("PUT", "POST"):
            data = _body()
            # Stored verbatim; no sanitisation at write time (by design).
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET display_name=%s, bio=%s, status=%s, homepage=%s "
                    "WHERE id=%s",
                    (data.get("display_name", ""), data.get("bio", ""),
                     data.get("status", ""), data.get("homepage", ""), uid),
                )
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, username, display_name, title, department, bio, status, homepage "
                "FROM users WHERE id=%s",
                (uid,),
            )
            row = cur.fetchone()
    finally:
        conn.close()
    return jsonify(profile=row)


# --- records + comments: stored values -------------------------------------

@bp.route("/records/<int:record_id>", methods=["GET", "POST"])
def record(record_id):
    conn = get_conn()
    try:
        if request.method == "POST":
            user = _current_user()
            author = user["username"] if user else "anonymous"
            data = _body()
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO comments (record_id, author, body) VALUES (%s, %s, %s)",
                    (record_id, author, data.get("body", "")),
                )
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, title, department, email, phone, location "
                "FROM directory WHERE id=%s",
                (record_id,),
            )
            rec = cur.fetchone()
            cur.execute(
                "SELECT id, author, body, created_at FROM comments "
                "WHERE record_id=%s ORDER BY created_at",
                (record_id,),
            )
            comment_rows = cur.fetchall()
    finally:
        conn.close()

    if not rec:
        return jsonify(error="record not found"), 404
    return jsonify(record=rec, comments=list(comment_rows))


# --- settings: export + insecure-deserialization import --------------------

@bp.route("/settings/export")
@require_auth
def export_settings():
    import base64
    import pickle
    settings_obj = {"theme": "dark", "lang": "en", "owner": g.api_user["username"]}
    blob = base64.b64encode(pickle.dumps(settings_obj)).decode()
    return jsonify(blob=blob)


@bp.route("/settings/import", methods=["POST"])
@require_auth
def import_settings():
    import base64
    import requests

    data = _body()
    blob_b64 = (data.get("blob") or "").strip()
    mode = resolve("DESER_MODE", request.args, Config.DESER_MODE)

    try:
        raw = base64.b64decode(blob_b64)
    except Exception:
        return jsonify(error="not valid base64"), 400

    # Forward untrusted bytes to deser-svc; the webapp never deserializes here.
    try:
        resp = requests.post(
            Config.DESER_SVC_URL,
            data=raw,
            headers={"Content-Type": "application/octet-stream"},
            params={"mode": mode},
            timeout=10,
        )
        return jsonify(deser_mode=mode, result=resp.json()), resp.status_code
    except requests.RequestException as exc:
        return jsonify(deser_mode=mode, error=f"deser-svc unavailable: {exc}"), 502
