"""
category_utils.py – Single source of truth for category-name normalization.

Root cause fixed here (Problem 10 / category fragmentation):
The source attack dataset contains two different spellings for the same
real-world category ("weapon" and "weapons"). Because every downstream
component (OWASP mapping, per-category ASR, severity classification)
grouped rows by the raw category string, that one typo silently split a
single category into two, showing up as two separate (and each smaller,
individually-less-alarming) rows everywhere: two OWASP "UNMAPPED" buckets,
two entries in category_asr, two severity buckets, etc.

This module does NOT invent new OWASP mappings and does NOT change the
attack dataset or the evaluation/mutation pipeline. It only makes sure
that a single real-world category is always referred to by one name, so
that counting/grouping code (which is correct) isn't fooled by spelling
differences.

If you need to add another known synonym in the future, add it to
CATEGORY_ALIASES below — do not scatter ad-hoc `.replace(...)` calls
through the codebase.
"""

from __future__ import annotations


# Known synonyms in the source dataset -> canonical spelling.
# Add new entries here ONLY when you've confirmed two labels refer to the
# exact same real-world category (see FINAL_VERIFICATION.md, Problem 10).
CATEGORY_ALIASES = {
    "weapons": "weapon",
}


def normalize_category(category) -> str:
    """Normalize category names from the dataset (whitespace/case/punct only).

    This does NOT apply synonym aliasing — use canonical_category() for
    that. Kept separate so callers that need the literal normalized-but-
    unaliased label (e.g. displaying the dataset's own spelling) still can.
    """
    return (
        str(category or "")
        .strip()
        .lower()
        .replace("\\_", "_")
        .replace("-", "_")
        .replace(" ", "_")
    )


def canonical_category(category) -> str:
    """Normalize AND collapse known synonyms to one canonical spelling.

    Use this everywhere categories are grouped, mapped to OWASP, or used
    to determine severity, so that dataset spelling inconsistencies don't
    fragment the stats.
    """
    cat = normalize_category(category)
    return CATEGORY_ALIASES.get(cat, cat)
