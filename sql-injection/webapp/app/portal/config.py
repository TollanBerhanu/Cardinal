"""Central configuration for the Cardinal webapp (system under test).

Every attack surface is controlled by an explicit toggle that defaults from an
environment variable but can be overridden per request. This gives us two
things the experiment needs at once:

  * A *fixed per-condition* default: pin ``SQL_IMPL=concat`` (etc.) for a whole
    deployment run, exactly as the tasklist asks.
  * A *per-request* override: the same endpoint can serve the vulnerable or the
    safe path in one deployment, so an attack and its byte-identical benign twin
    traverse the identical route. Nothing about the choice is visible in the
    request body -- it rides in a query parameter the benign client sets too.

The webapp is intentionally vulnerable. That is the point of the testbed.
"""
import os


def _env_flag(name: str, default: str) -> str:
    return os.environ.get(name, default).strip().lower()


class Config:
    # --- Flask ---
    SECRET_KEY = os.environ.get("SECRET_KEY", "cardinal-dev-not-secret")

    # --- Database (data tier) ---
    # Defaults are the Kathara-lab app-net IPs; webapp.startup also exports these.
    # (Docker-DNS hostnames db/cache/deser-svc are the fallback for a compose run.)
    DB_HOST = os.environ.get("DB_HOST", "172.31.0.30")
    DB_PORT = int(os.environ.get("DB_PORT", "3306"))
    DB_USER = os.environ.get("DB_USER", "portal")
    # Accept DB_PASSWORD (this app) or DB_PASS (rest of the lab's startup scripts).
    DB_PASSWORD = os.environ.get("DB_PASSWORD") or os.environ.get("DB_PASS", "portal")
    DB_NAME = os.environ.get("DB_NAME", "portal")

    # --- Cache / sessions (data tier) ---
    REDIS_HOST = os.environ.get("REDIS_HOST", "172.31.0.31")
    REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
    SESSION_TTL = int(os.environ.get("SESSION_TTL", "3600"))

    # --- Deserialization backend (app tier) ---
    DESER_SVC_URL = os.environ.get("DESER_SVC_URL", "http://172.31.0.32:8090/reconstruct")

    # --- Per-condition attack-surface defaults ---------------------------------
    # SQL path: "concat" (vulnerable, string-built) or "param" (safe, bound).
    # Accept SQL_IMPL (this app) or SQL_MODE (the name used elsewhere in the lab).
    SQL_IMPL = (os.environ.get("SQL_IMPL") or os.environ.get("SQL_MODE") or "concat").strip().lower()

    # Output encoding for reflected/stored values: "raw" (vulnerable, no escaping)
    # or "escape" (safe, contextual escaping applied). Controls every XSS sink.
    XSS_ENCODING = _env_flag("XSS_ENCODING", "raw")

    # Deserialization: "unsafe" (reconstruct arbitrary objects) or
    # "safe" (accept a restricted, data-only format).
    DESER_MODE = _env_flag("DESER_MODE", "unsafe")

    # RASP structural detector at the DB call (app/rasp.py): "off" (no check),
    # "detect" (log the verdict, allow) or "block" (log, and 403 when the input
    # added query structure). Default off so existing experiments are unchanged.
    RASP_MODE = _env_flag("RASP_MODE", "off")

    # Extra URL-decode applied by the app before the SQL path: "single" (the
    # Werkzeug default -- one decode) or "double" (one more unquote). The second
    # layer models the common double-decoding app and is what makes a
    # double-encoded payload survive the WAF yet still execute (see the directory
    # route and attacker/scripts/encoding_evasion.sh).
    DECODE = _env_flag("DECODE", "single")


def resolve(name: str, request_args, default: str) -> str:
    """Resolve a toggle: per-request query arg wins, else the configured default.

    e.g. resolve("SQL_IMPL", request.args, Config.SQL_IMPL) reads ?impl=... when
    present. The mapping of query-arg name -> config attribute lives in TOGGLES.
    """
    arg_name = TOGGLES[name]
    val = request_args.get(arg_name)
    if val:
        return val.strip().lower()
    return default


# Query-arg names used to override each toggle on a single request.
TOGGLES = {
    "SQL_IMPL": "impl",
    "XSS_ENCODING": "enc",
    "DESER_MODE": "deser",
    "RASP_MODE": "rasp",
    "DECODE": "decode",
}
