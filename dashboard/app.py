"""ERPGuard Security Dashboard.

Run benchmark:
    python -m evaluation.run_eval

Run dashboard:
    python -m dashboard.app
"""

import json
import os
import pathlib
import re
from collections import Counter
from datetime import datetime, timezone, timedelta

from flask import Flask, abort, jsonify, render_template, request
from markupsafe import Markup, escape

from erpguard.store import Store


RESULTS = (
    pathlib.Path(__file__).resolve().parent.parent
    / "evaluation"
    / "results.json"
)

# Indian Standard Time = UTC + 5 hours 30 minutes.
# This fixed offset avoids requiring a timezone database on Windows.
IST = timezone(timedelta(hours=5, minutes=30), name="IST")


def format_ist(timestamp):
    """Convert a Unix timestamp into Indian Standard Time."""
    if timestamp is None:
        return ""
    try:
        dt = datetime.fromtimestamp(
            float(timestamp), tz=timezone.utc
        ).astimezone(IST)
        return dt.strftime("%d-%m-%Y %I:%M:%S %p IST")
    except (ValueError, TypeError, OverflowError, OSError):
        return ""


def safe_json(value, default=None):
    """Decode JSON stored in SQLite, returning a safe default on failure."""
    if default is None:
        default = []
    try:
        return json.loads(value) if value else default
    except (json.JSONDecodeError, TypeError):
        return default


def normalize_list(value):
    """Normalize a JSON list, decoded list, or plain string into a list.

    Older audit rows may contain a plain text reason, while newer rows store
    reasons as a JSON array. This prevents Jinja from iterating over a string
    one character at a time.
    """
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return [value]
        if isinstance(decoded, list):
            return decoded
        if isinstance(decoded, str):
            return [decoded] if decoded else []
        return [decoded]
    return [value]


def create_app(db=None):
    app = Flask(__name__)
    store = Store(db or os.environ.get("ERPGUARD_DB", "erpguard.db"))

    def stats(mode):
        result = {
            "blocked_attacks": 0,
            "attack_calls_allowed": 0,
            "benign_allowed": 0,
            "confirms": 0,
            "overblocks": 0,
            "observed_inputs": 0,
            "by_tool": Counter(),
            "by_source": Counter(),
        }
        if not mode:
            return result

        rows = store.events(mode=mode, limit=100000)
        for row in rows:
            kind = row["kind"]
            verdict = row["verdict"]
            blocked = (
                verdict == "block"
                or (verdict == "confirm" and not row["approved"])
            )

            # An observation records untrusted content being read. It is not
            # automatically counted as a confirmed attack attempt.
            if kind == "untrusted_input":
                result["observed_inputs"] += 1
                continue

            if kind == "attack":
                if blocked:
                    result["blocked_attacks"] += 1
                    result["by_tool"][row["tool"]] += 1
                    for source in safe_json(row["sources"], []):
                        result["by_source"][source] += 1
                else:
                    result["attack_calls_allowed"] += 1
            elif kind == "benign":
                if verdict == "confirm":
                    result["confirms"] += 1
                if verdict == "block":
                    result["overblocks"] += 1
                elif not blocked:
                    result["benign_allowed"] += 1
        return result

    @app.template_filter("highlight")
    def highlight(snippet, args_json):
        output = str(escape(snippet or ""))
        args = safe_json(args_json, {})
        if not isinstance(args, dict):
            return Markup(output)
        for value in args.values():
            value = str(value)
            if len(value) >= 3:
                output = re.sub(
                    re.escape(value),
                    lambda match: f"<mark>{match.group(0)}</mark>",
                    output,
                    flags=re.I,
                )
        return Markup(output)

    @app.template_filter("fromjson")
    def fromjson(value):
        """Decode JSON and normalize scalar strings to a one-item list."""
        return normalize_list(value)

    @app.template_filter("datetime_ist")
    def datetime_ist(timestamp):
        return format_ist(timestamp)

    def mode_arg():
        modes = store.modes()
        selected_mode = (
            request.args.get("mode")
            or ("hybrid" if "hybrid" in modes else modes[0] if modes else None)
        )
        return selected_mode, modes

    def serialize_event(row):
        return {
            "id": row["id"],
            "timestamp": row["ts"],
            "date": format_ist(row["ts"]),
            "run_id": row["run_id"],
            "mode": row["mode"],
            "kind": row["kind"],
            "task_id": row["task_id"],
            "tool": row["tool"],
            "args": safe_json(row["args"], {}),
            "verdict": row["verdict"],
            "approved": row["approved"],
            "reasons": normalize_list(row["reasons"]),
            "sources": normalize_list(row["sources"]),
            "user_msg": row["user_msg"],
            "snippet": row["snippet"],
        }

    @app.route("/")
    def index():
        mode, modes = mode_arg()
        return render_template(
            "page.html", view="index", mode=mode, modes=modes, s=stats(mode)
        )

    @app.route("/events")
    def events():
        mode, modes = mode_arg()
        rows = store.events(
            mode=mode,
            kind=request.args.get("kind"),
            verdict=request.args.get("verdict"),
            limit=300,
        )
        return render_template(
            "page.html", view="events", mode=mode, modes=modes, rows=rows
        )

    @app.route("/event/<int:eid>")
    def event(eid):
        event_row = store.event(eid)
        if not event_row:
            abort(404)
        return render_template(
            "page.html",
            view="event",
            mode=event_row["mode"],
            modes=store.modes(),
            e=event_row,
        )

    @app.route("/compare")
    def compare():
        mode, modes = mode_arg()
        results = None
        if RESULTS.exists():
            try:
                results = json.loads(RESULTS.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                results = None
        return render_template(
            "page.html", view="compare", mode=mode, modes=modes, res=results
        )

    @app.route("/api/events")
    def api_events():
        mode, _ = mode_arg()
        rows = store.events(
            mode=mode,
            kind=request.args.get("kind"),
            verdict=request.args.get("verdict"),
            limit=100,
        )
        return jsonify([serialize_event(row) for row in rows])

    @app.route("/api/stats")
    def api_stats():
        mode, _ = mode_arg()
        result = stats(mode)
        result["by_tool"] = dict(result["by_tool"])
        result["by_source"] = dict(result["by_source"])
        return jsonify(mode=mode, **result)

    @app.route("/api/time")
    def api_time():
        now = datetime.now(IST)
        return jsonify(
            date=now.strftime("%d-%m-%Y"),
            time=now.strftime("%I:%M:%S %p"),
            timezone="IST",
            datetime=now.strftime("%d-%m-%Y %I:%M:%S %p IST"),
        )

    return app


if __name__ == "__main__":
    app = create_app()
    print("\n" + "=" * 55)
    print("          ERPGUARD SECURITY DASHBOARD")
    print("=" * 55)
    print("Dashboard : http://127.0.0.1:5000")
    print("Events    : http://127.0.0.1:5000/events")
    print("Compare   : http://127.0.0.1:5000/compare")
    print("Live API  : http://127.0.0.1:5000/api/events")
    print("Stats API : http://127.0.0.1:5000/api/stats")
    print("Time API  : http://127.0.0.1:5000/api/time")
    print("Timezone  : Indian Standard Time (UTC+05:30)")
    print("=" * 55 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
