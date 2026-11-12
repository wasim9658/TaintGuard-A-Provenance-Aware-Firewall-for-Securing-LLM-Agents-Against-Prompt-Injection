"""Decide how trustworthy a tool argument is. Three modes (the main experiment):

coarse : any untrusted content seen anywhere in the session taints every argument.
match  : an argument is tainted only if its text appears in an untrusted source.
         (no match => trusted. Misses paraphrase/obfuscation.)
hybrid : positive attribution. Structured args must be traceable to a trusted/record
         source or they are UNATTRIBUTED (untrusted). Free-text args that match nothing
         fall back to the coarse session label.
"""
import re

from .labels import USER, UNATTRIBUTED, Integrity, Label


def _norm(s):
    return re.sub(r"\s+", " ", str(s)).strip().lower()


def _contains(v, t, n=16):
    if len(v) < 3:
        return False
    if v in t:
        return True
    # partial copies of long values: any n-char window appearing in the source
    return len(v) >= 2 * n and any(v[i:i + n] in t for i in range(0, len(v) - n + 1, 4))


def hits(value, ledger):
    v = _norm(value)
    return [lab for text, lab in ledger if _contains(v, _norm(text))]


def context_label(ctx):
    t = ctx["tainted"]
    return Label(Integrity.UNTRUSTED, t) if t else USER


def arg_label(value, mode, ctx, free_text=False):
    if mode == "coarse":
        return context_label(ctx)
    hs = hits(value, ctx["ledger"])
    if hs:
        lab = hs[0]
        for h in hs[1:]:
            lab = lab.join(h)
        return lab
    if mode == "match":
        return USER
    return context_label(ctx) if free_text else UNATTRIBUTED
