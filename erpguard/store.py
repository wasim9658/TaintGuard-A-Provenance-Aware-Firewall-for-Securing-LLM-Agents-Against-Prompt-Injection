import json
import sqlite3
import time

SCHEMA = """CREATE TABLE IF NOT EXISTS events(
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, run_id TEXT, mode TEXT, kind TEXT, task_id TEXT,
 tool TEXT, args TEXT, verdict TEXT, approved INTEGER, reasons TEXT, sources TEXT,
 user_msg TEXT, snippet TEXT)"""


class Store:
    def __init__(self, path="erpguard.db"):
        self.path = path
        with self._c() as c:
            c.execute(SCHEMA)

    def _c(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        return c

    def reset(self):
        with self._c() as c:
            c.execute("DELETE FROM events")

    def record(self, *, run_id="", mode="", kind="", task_id="", tool, args, verdict, approved=None,
               reasons=(), sources=(), user_msg="", snippet=""):
        with self._c() as c:
            c.execute("INSERT INTO events(ts,run_id,mode,kind,task_id,tool,args,verdict,approved,reasons,sources,user_msg,snippet)"
                      " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (time.time(), run_id, mode, kind, task_id, tool, json.dumps(args, default=str), verdict,
                       None if approved is None else int(approved), json.dumps(list(reasons)),
                       json.dumps(sorted(sources)), user_msg, snippet))

    def events(self, mode=None, kind=None, verdict=None, limit=500):
        q, a = "SELECT * FROM events WHERE 1=1", []
        for col, v in (("mode", mode), ("kind", kind), ("verdict", verdict)):
            if v:
                q += f" AND {col}=?"
                a.append(v)
        with self._c() as c:
            return [dict(r) for r in c.execute(q + " ORDER BY id DESC LIMIT ?", a + [limit])]

    def event(self, eid):
        with self._c() as c:
            r = c.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
            return dict(r) if r else None

    def modes(self):
        with self._c() as c:
            return [r[0] for r in c.execute("SELECT DISTINCT mode FROM events ORDER BY mode")]
