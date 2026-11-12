import re

from .labels import Integrity
from .policy import POLICIES, Verdict
from .provenance import _norm, arg_label

SEV = {Verdict.ALLOW: 0, Verdict.CONFIRM: 1, Verdict.BLOCK: 2}
KEYWORDS = re.compile(r"ignore (all )?(previous|prior) instructions|disregard (prior|previous)|"
                      r"system override|you must now|new instructions:", re.I)


class Firewall:
    """modes: none | keyword | coarse | match | hybrid | hybrid-nodecl (ablation)"""

    def __init__(self, mode="hybrid"):
        self.name = mode
        self.use_decl = not mode.endswith("-nodecl")
        self.mode = mode.replace("-nodecl", "")

    def is_privileged(self, tool):
        return tool in POLICIES and POLICIES[tool].privileged

    def sanitize(self, text):
        """Naive keyword baseline: redact whole output if it looks like an injection."""
        if self.mode == "keyword" and KEYWORDS.search(text):
            return "[content removed by keyword filter]"
        return text

    def check(self, tool, args, ctx):
        pol = POLICIES.get(tool)
        if self.mode in ("none", "keyword") or not pol or not pol.privileged:
            return Verdict.ALLOW, [], set()
        worst, reasons, srcs = Verdict.ALLOW, [], set()
        for name, ap in pol.args.items():
            if name not in args:
                continue
            val = args[name]
            lab = arg_label(val, self.mode, ctx, ap.free_text)
            if lab.integrity >= ap.min_integrity:
                continue
            if self.mode != "coarse" and self.use_decl and ap.declassify:
                try:
                    ok = ap.declassify(val, ctx)
                except Exception:
                    ok = False
                if ok:
                    reasons.append(f"{name}={val!r}: tainted by {sorted(lab.sources)} but passed declassifier")
                    continue
            v = Verdict.BLOCK if self.mode == "coarse" else ap.on_violation
            reasons.append(f"{name}={val!r}: tainted by {sorted(lab.sources)}")
            srcs |= lab.sources
            worst = max(worst, v, key=SEV.get)
        return worst, reasons, srcs


def find_snippet(args, ctx):
    """Untrusted text that (probably) influenced these args, for the dashboard."""
    first = ""
    for text, lab in ctx["ledger"]:
        if not lab.untrusted:
            continue
        first = first or text
        for v in args.values():
            if len(_norm(v)) >= 3 and _norm(v) in _norm(text):
                return text
    return first
