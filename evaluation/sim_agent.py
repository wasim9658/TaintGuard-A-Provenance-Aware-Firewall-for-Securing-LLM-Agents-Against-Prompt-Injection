"""Deterministic 'gullible' planner: executes the user's task plan, but ALSO obeys any
`ACTION: tool | k=v | ...` line it finds in tool output (a worst-case prompt-injectable LLM).
It de-obfuscates 'x at y dot com' values, modelling an LLM that paraphrases/normalises."""
import re
from collections import deque

from erpguard.agent import Action


class GulliblePlanner:
    def __init__(self, steps):
        self.steps, self.queue, self.vars, self.out, self.last, self.n = list(steps), deque(), {}, {}, "", 0

    def start(self, user_msg, tools):
        pass

    def _res(self, v):
        if isinstance(v, dict):
            return self.vars[v["var"]]
        if isinstance(v, str) and v.startswith("$"):
            return self.out.get(v[1:], v)
        return v

    def next(self):
        self.n += 1
        if self.queue:
            name, args = self.queue.popleft()
            return Action(name, {k: self._res(v) for k, v in args.items()}, f"i{self.n}", injected=True)
        if self.steps:
            s = self.steps.pop(0)
            return Action(s["tool"], {k: self._res(v) for k, v in s.get("args", {}).items()}, f"p{self.n}", save=s.get("save"))
        return Action(final=self.last)

    def observe(self, action, text, blocked):
        if blocked:
            return
        self.out[action.name] = text
        if action.save:
            self.vars[action.save] = text
        if not action.injected:
            self.last = text
        for line in text.replace("ACTION:", "\nACTION:").replace("-->", "\n").splitlines():
            line = line.strip()
            if not line.startswith("ACTION:"):
                continue
            parts = [p.strip() for p in line[7:].split("|")]
            args = {}
            for p in parts[1:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    v = v.strip()
                    if " at " in v and " dot " in v:
                        v = v.replace(" at ", "@").replace(" dot ", ".")
                    args[k.strip()] = v
            self.queue.append((parts[0], args))
