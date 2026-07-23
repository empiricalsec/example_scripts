"""Sanity-check the size of a generated dataset before it ships downstream.

Tool-agnostic: a scheduled job that silently produces far fewer rows than usual
(an upstream hiccup, a mis-scoped query, etc.) would otherwise ship a bad dataset
with no signal. :func:`validate_row_count` flags such a run so the caller can log
it, alert on it, and exit non-zero.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of the row-count check.

    ``ok`` is ``True`` when at least ``min_rows`` rows were produced. A
    ``min_rows`` of ``0`` (or less) disables the check, so every run passes.
    """

    row_count: int
    min_rows: int

    @property
    def ok(self) -> bool:
        return self.row_count >= self.min_rows

    @property
    def message(self) -> str:
        if self.ok:
            return f"{self.row_count} rows (minimum {self.min_rows}): OK"
        return f"only {self.row_count} rows written; expected at least {self.min_rows}"


def validate_row_count(row_count: int, min_rows: int) -> ValidationResult:
    """Flag a run whose output is smaller than ``min_rows`` rows.

    The boundary is inclusive: ``row_count == min_rows`` passes. Set
    ``min_rows <= 0`` to disable the check.
    """
    return ValidationResult(row_count=row_count, min_rows=min_rows)
