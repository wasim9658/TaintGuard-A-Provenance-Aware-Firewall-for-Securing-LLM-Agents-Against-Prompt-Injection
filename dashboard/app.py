"""python -m dashboard.app   (after python -m evaluation.run_eval)"""
import json
import os
import pathlib
import re
from collections import Counter

from flask import Flask, abort, jsonify, render_template, request
from markupsafe import Markup, escape

from erpguard.store import Store

RESULTS = pathlib.Path(__file__).resolve().parent.parent / "evaluation" / "results.json"


def create_app(db=None):
    app = Flask(__name__)
    store = Store(db or os.environ.get("ERPGUARD_DB", "erpguard.db"))

    def stats(mode):
        s = dict(blocked_attacks=0, attack_calls_allowed=0, benign_allowed=0, confirms=0, overblocks=0,
                 by_tool=Counter(), by_source=Counter())
        for r in store.events(mode=mode, limit=100000):
            blocked = r["verdict"] == "block" or (r["verdict"] == "confirm" and not r["approved"])
            if r["kind"] == "attack":
                if blocked:
                    s["blocked_attacks"] += 1
                    s["by_tool"][r["tool"]] += 1
                    for src in json.loads(r["sources"]):
                        s["by_source"][src] += 1
                else:
                    s["attack_calls_allowed"] += 1
            elif r["kind"] == "benign":
                s["confirms"] += r["verdict"] == "confirm"
                if r["verdict"] == "block":
                    s["overblocks"] += 1
                elif not blocked:
                    s["benign_allowed"] += 1
        return s

    @app.template_filter("highlight")
    def highlight(snippet, args_json):
        out = str(escape(snippet or ""))
        for v in json.loads(args_json).values():
            v = str(escape(str(v)))
            if len(v) >= 3:
                out = re.sub(re.escape(v), lambda m: f"<mark>{m.group(0)}</mark>", out, flags=re.I)
        return Markup(out)

    @app.template_filter("fromjson")
    def fromjson(s):
        return json.loads(s or "null")

    def mode_arg():
        modes = store.modes()
        m = request.args.get("mode") or ("hybrid" if "hybrid" in modes else (modes[0] if modes else None))
        return m, modes

    @app.route("/")
    def index():
        m, modes = mode_arg()
        return render_template("page.html", view="index", mode=m, modes=modes, s=stats(m))

    @app.route("/events")
    def events():
        m, modes = mode_arg()
        rows = store.events(mode=m, kind=request.args.get("kind"), verdict=request.args.get("verdict"), limit=300)
        return render_template("page.html", view="events", mode=m, modes=modes, rows=rows)

    @app.route("/event/<int:eid>")
    def event(eid):
        e = store.event(eid) or abort(404)
        return render_template("page.html", view="event", mode=e["mode"], modes=store.modes(), e=e)

    @app.route("/compare")
    def compare():
        m, modes = mode_arg()
        res = json.loads(RESULTS.read_text()) if RESULTS.exists() else None
        return render_template("page.html", view="compare", mode=m, modes=modes, res=res)

    @app.route("/api/stats")
    def api_stats():
        m, _ = mode_arg()
        s = stats(m)
        s["by_tool"], s["by_source"] = dict(s["by_tool"]), dict(s["by_source"])
        return jsonify(mode=m, **s)

    return app


if __name__ == "__main__":
    create_app().run(debug=True, port=5000)
