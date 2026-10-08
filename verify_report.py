"""How `verify` prints what it found: one row per condition, naming every
workspace it applies to.

The checks produce findings as sentences, each naming the sandbox it is about
by its slug. Printing them one per line repeats a sentence once per sandbox,
and on a fleet of thirty the one line that differs is lost. So the sentences
are grouped: the slug is lifted out of each, and sentences that are then the
same text are one condition, with the sandboxes listed beside it. A sentence
whose detail differs per sandbox (a heartbeat's age) stays its own row, so
nothing a check said is dropped.

Sandboxes are shown by their workspace name, the slug without its hash. The
slug stays the identity everywhere else; a name two sandboxes share keeps
its hash, so a row never names an ambiguous workspace.

Standard library only, and no sandy or router: it formats, it never checks.
"""
import re
import shutil
import textwrap
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

# Sandy names a sandbox `<workspace name>-<8 hex>`.
_SLUG_HASH = re.compile(r"^(?P<name>.+)-[0-9a-f]{8}$")

# A row lists at most this many workspaces unless the operator asks for all.
COLLAPSE_AFTER = 8

# The narrowest the condition column gets, and its share of the terminal.
_CONDITION_MIN = 30
_CONDITION_SHARE = 0.6
_GUTTER = "  "
_INDENT = "  "


@dataclass
class Row:
    """One condition and the sandboxes (slugs) it applies to. No slugs: the
    condition is about the host or the router, not a sandbox."""
    condition: str
    slugs: List[str] = field(default_factory=list)


def display_names(slugs: Iterable[str]) -> Dict[str, str]:
    """Each slug's workspace name: the slug without its hash. Where two slugs
    would show the same name, both keep the hash."""
    slugs = sorted(set(slugs))
    short = {}
    for slug in slugs:
        m = _SLUG_HASH.match(slug)
        short[slug] = m.group("name") if m else slug
    counts: Dict[str, int] = {}
    for name in short.values():
        counts[name] = counts.get(name, 0) + 1
    return {slug: (name if counts[name] == 1 else slug) for slug, name in short.items()}


# What a slug left inside a sentence (a path through its lane tree) reads as,
# so that the same sentence about two sandboxes is the same text.
SLUG_PLACEHOLDER = "<slug>"


def _lift(line: str, slug: str) -> str:
    """The sentence with its slug lifted out where it is the subject:
    `slug: rest` and `label: slug: rest` lose the slug and its colon. Inside
    a path (after a `/`) it becomes SLUG_PLACEHOLDER. Anywhere else it is
    kept verbatim: a sentence that names a slug as a value (a policy entry
    to edit) must still show the exact string."""
    if line.startswith(slug + ": "):
        line = line[len(slug) + 2:]
    else:
        line = line.replace(f": {slug}: ", ": ", 1)
    return re.sub(rf"(?<=/){re.escape(slug)}(?![\w-])", SLUG_PLACEHOLDER, line)


def _slugs_in(line: str, slugs: Sequence[str]) -> List[str]:
    return [s for s in slugs if re.search(rf"(?<![\w-]){re.escape(s)}(?![\w-])", line)]


def group(lines: Iterable[str], slugs: Sequence[str]) -> List[Row]:
    """Rows from finding sentences. A sentence naming exactly one known slug
    joins the row of every other sentence that reads the same with its slug
    lifted out. One naming none, or several, is a row of its own, verbatim.
    Rows keep the order their first sentence appeared in."""
    rows: List[Row] = []
    by_condition: Dict[str, Row] = {}
    for line in lines:
        # The match is bounded by characters a slug cannot contain, so one
        # slug is never found inside another (`pka-...` in `pka-skills-...`).
        found = _slugs_in(line, slugs)
        if len(found) != 1:
            rows.append(Row(line))
            continue
        condition = _lift(line, found[0])
        row = by_condition.get(condition)
        if row is None:
            row = by_condition[condition] = Row(condition)
            rows.append(row)
        if found[0] not in row.slugs:
            row.slugs.append(found[0])
    return rows


def render(title: str, rows: Sequence[Row], names: Dict[str, str], *,
           show_all: bool = False, width: Optional[int] = None) -> List[str]:
    """The rows as a two-column table under `title`: the condition, wrapped,
    and the workspaces it applies to. More than COLLAPSE_AFTER workspaces
    collapse to a count unless `show_all`. A row about no sandbox spans both
    columns."""
    if width is None:
        width = shutil.get_terminal_size((100, 24)).columns
    usable = max(width - len(_INDENT), _CONDITION_MIN * 2)
    cond_w = max(_CONDITION_MIN, int(usable * _CONDITION_SHARE))
    names_w = max(usable - cond_w - len(_GUTTER), _CONDITION_MIN)
    out = [title]
    if not rows:
        out.append(f"{_INDENT}(none)")
        return out
    out.append(f"{_INDENT}{'Condition':<{cond_w}}{_GUTTER}Workspaces")
    out.append(f"{_INDENT}{'─' * cond_w}{_GUTTER}{'─' * min(names_w, len('Workspaces') * 3)}")
    for row in rows:
        if not row.slugs:
            for line in textwrap.wrap(row.condition, usable) or [""]:
                out.append(f"{_INDENT}{line}")
            continue
        shown = sorted(names.get(s, s) for s in row.slugs)
        hidden = 0
        if not show_all and len(shown) > COLLAPSE_AFTER:
            hidden = len(shown) - COLLAPSE_AFTER
            shown = shown[:COLLAPSE_AFTER]
        listing = ", ".join(shown)
        if hidden:
            listing += f", … {hidden} more (--all to list)"
        left = textwrap.wrap(row.condition, cond_w) or [""]
        right = textwrap.wrap(listing, names_w, break_on_hyphens=False) or [""]
        for i in range(max(len(left), len(right))):
            l = left[i] if i < len(left) else ""
            r = right[i] if i < len(right) else ""
            out.append(f"{_INDENT}{l:<{cond_w}}{_GUTTER}{r}".rstrip())
    return out


def part_summary(label: str, report: str, settled: bool) -> Optional[str]:
    """An install part's report in one line when the caller judged it
    settled (nothing needed doing): its label, with a count for a part made
    of several `; `-joined pieces. None when it is not settled, so the
    caller prints the report whole."""
    if not settled:
        return None
    pieces = report.split("; ")
    return f"{label} ({len(pieces)} files)" if len(pieces) > 1 else label
