"""Deterministic policies. NO LLM is ever called in the enforcement path."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .labels import Integrity


class Verdict(str, Enum):
    ALLOW = "allow"
    CONFIRM = "confirm"
    BLOCK = "block"


@dataclass
class ArgPolicy:
    min_integrity: Integrity = Integrity.SYSTEM_OF_RECORD
    declassify: Optional[Callable] = None     # deterministic check that rescues a tainted value
    on_violation: Verdict = Verdict.BLOCK
    free_text: bool = False                   # prose args get the coarse fallback in hybrid mode


@dataclass
class ToolPolicy:
    privileged: bool
    args: dict = field(default_factory=dict)


# ---- declassifiers: typed predicates over system-of-record data ----
def recipient_in_directory(v, ctx):
    return str(v).strip().lower() in ctx["erp"].directory_emails()


def amount_matches_dues(v, ctx):
    return float(v) == float(ctx["erp"].dues(ctx["student_id"]))


def account_is_college(v, ctx):
    return str(v).strip() in ctx["erp"].fee_accounts


def course_enrolled(v, ctx):
    return str(v).strip() in ctx["erp"].courses


T, R = Integrity.TRUSTED, Integrity.SYSTEM_OF_RECORD

POLICIES = {
    "send_email": ToolPolicy(True, {
        "to": ArgPolicy(T, declassify=recipient_in_directory),
        "body": ArgPolicy(R, on_violation=Verdict.CONFIRM, free_text=True)}),
    "pay_fee": ToolPolicy(True, {
        "amount": ArgPolicy(T, declassify=amount_matches_dues),
        "account": ArgPolicy(T, declassify=account_is_college)}),
    "submit_leave_request": ToolPolicy(True, {
        "reason": ArgPolicy(R, on_violation=Verdict.CONFIRM, free_text=True)}),
    "submit_exam_form": ToolPolicy(True, {
        "course": ArgPolicy(T, declassify=course_enrolled)}),
    "update_contact": ToolPolicy(True, {
        "phone": ArgPolicy(T), "email": ArgPolicy(T)}),
}
