"""Integrity labels + provenance. join() = lowest integrity, union of sources."""
from dataclasses import dataclass, field
from enum import IntEnum


class Integrity(IntEnum):
    UNTRUSTED = 0          # web pages, email bodies, notices, student-written text
    SYSTEM_OF_RECORD = 1   # ERP DB fields written by staff
    TRUSTED = 2            # the user's own message, system prompt


@dataclass(frozen=True)
class Label:
    integrity: Integrity
    sources: frozenset = field(default_factory=frozenset)

    def join(self, other: "Label") -> "Label":
        return Label(min(self.integrity, other.integrity), self.sources | other.sources)

    @property
    def untrusted(self) -> bool:
        return self.integrity == Integrity.UNTRUSTED


USER = Label(Integrity.TRUSTED, frozenset({"user"}))


def untrusted(src: str) -> Label:
    return Label(Integrity.UNTRUSTED, frozenset({src}))


def record(src: str) -> Label:
    return Label(Integrity.SYSTEM_OF_RECORD, frozenset({src}))


UNATTRIBUTED = untrusted("unattributed")  # value not traceable to any trusted source
