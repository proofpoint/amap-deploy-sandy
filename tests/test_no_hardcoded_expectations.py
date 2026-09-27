"""The literal budget, enforced mechanically over router_health.py's AST.

**No `3/3`, no `15`, no `17 mount(s)`, no `227 passed`, no `since=1.7.0`.**
Each of those is an expected value typed in rather than derived, and each goes
stale the day the fleet changes. A number typed into an assertion is a number
nobody derived.

Two rules, both scoped to `verify_*` functions (the two sections' entry
points) and every helper that builds a Check — the only places an expected
value can appear:

  1. NO INT LITERAL other than 0, 1 and 2. Those three are exit codes and
     small structural counts (`one notice`, `one recipient`), and anything
     bigger is a fleet fact that must come from a Fact.
  2. EVERY STRING LITERAL must be either a key of `WIRE_NAMES` (a name another
     program emits or reads, which we do not get to choose), a key of
     `FACT_SOURCES` (a handle, not a value), argv (which is not an expected
     value), or prose (`claim`/`remedy`/`do_not`/`why`/`look_at`/`reason`).

Both are mutation-provable in one line: paste `assertEqual(n, 3)` into any
verify and rule 1 fires; compare against a bare `"marker set"` and rule 2
fires. A rule that cannot be made to fire is not a rule, and this repo's worst
recurring defect is exactly that shape of test.

Rule 2's exemptions are chosen so that no exempt position can carry an
expected value:
  * argv — a flag or a subcommand is what we ASK, never what we ASSERT;
  * a Fact's `name` and `provenance` — a handle and a sentence, never a value;
    the Fact's VALUE is the middle argument and is NOT exempt;
  * ctx.fact/value/known/captured keys — handles into the fact cache.
"""
from __future__ import annotations

import sys
from pathlib import Path
import ast
import unittest

if str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import router_health as rh  # noqa: E402

_SRC_PATH = Path(rh.__file__)
_SRC = _SRC_PATH.read_text(encoding="utf-8")
_TREE = ast.parse(_SRC)


ALLOWED_INTS = {0, 1, 2}

# Calls whose ENTIRE subtree is argv or a handle, never an expected value.
ARGV_BUILDERS = {"run", "_inspect", "oneshot_name", "runsh_argv"}

# Keyword arguments that carry PROSE, not values.
PROSE_KWARGS = {"claim", "remedy", "do_not", "why", "look_at", "reason", "provenance"}

# Calls whose every argument is prose: the sentence explaining an Unresolved,
# or a warning/note for a human to read.
PROSE_CALLS = {"_unresolved", "Unresolved", "warn", "note"}

# Calls whose string arguments are SELECTORS — a glob pattern asks a question,
# it is never the answer.
SELECTOR_CALLS = {"glob", "rglob", "startswith", "endswith"}


def _builds_a_check(fn: ast.FunctionDef) -> bool:
    """Does this function CONSTRUCT an assertion?

    Scoping the budget to `verify_*` by name alone left one escape hatch open:
    factoring a check out into a helper — `_roles_check`, say — moved its
    expected value somewhere nothing walked. A function that calls `check()` or
    `unknown()` is an assertion site whatever it is called."""
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
               and n.func.id in ("check", "unknown")
               for n in ast.walk(fn))


def _verify_functions():
    """Exactly one per section, by name."""
    return [n for n in ast.walk(_TREE)
            if isinstance(n, ast.FunctionDef) and n.name.startswith("verify_")]


def _assertion_sites():
    """Every function the budget applies to: the per-section verifies, plus any
    helper that builds a Check. Scoping by name alone left one escape hatch
    open — factoring a check out into a helper moved its expected value
    somewhere nothing walked."""
    named = _verify_functions()
    seen = {id(f) for f in named}
    return named + [n for n in ast.walk(_TREE)
                    if isinstance(n, ast.FunctionDef) and id(n) not in seen
                    and _builds_a_check(n)]


def _exempt_nodes(fn: ast.AST) -> set:
    """Every Constant node id that a rule-2 exemption covers."""
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            fname = node.func.id if isinstance(node.func, ast.Name) else \
                getattr(node.func, "attr", "")
            if fname in ARGV_BUILDERS:
                out |= {id(c) for c in ast.walk(node) if isinstance(c, ast.Constant)}
            if fname == "Fact":
                # name (arg 0) and provenance (arg 2) are exempt; the VALUE
                # (arg 1) deliberately is not.
                for i, a in enumerate(node.args):
                    if i != 1:
                        out |= {id(c) for c in ast.walk(a) if isinstance(c, ast.Constant)}
                for kw in node.keywords:
                    if kw.arg in ("name", "provenance"):
                        out |= {id(c) for c in ast.walk(kw.value)
                                if isinstance(c, ast.Constant)}
            if fname in ("fact", "value", "known", "get"):
                out |= {id(c) for c in node.args if isinstance(c, ast.Constant)}
            if fname in PROSE_CALLS | SELECTOR_CALLS:
                out |= {id(c) for c in ast.walk(node) if isinstance(c, ast.Constant)}
            for kw in node.keywords:
                # A probe budget is not an expected value; a wall-clock timeout
                # says how long to wait, never what to find.
                if kw.arg == "timeout":
                    out |= {id(c) for c in ast.walk(kw.value) if isinstance(c, ast.Constant)}
            for kw in node.keywords:
                if kw.arg in PROSE_KWARGS:
                    out |= {id(c) for c in ast.walk(kw.value) if isinstance(c, ast.Constant)}
        if isinstance(node, ast.Subscript):
            out |= {id(c) for c in ast.walk(node.slice) if isinstance(c, ast.Constant)}
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            out.add(id(node.value))          # a docstring
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.Constant):
                    out.add(id(v))           # the literal parts of an f-string
                if isinstance(v, ast.FormattedValue) and v.format_spec is not None:
                    out |= {id(c) for c in ast.walk(v.format_spec)
                            if isinstance(c, ast.Constant)}
    return out


class LiteralBudgetTest(unittest.TestCase):
    def test_there_are_verify_functions_to_check(self):
        """A walker that inspects nothing passes trivially. The section
        table is the derivation of how many there must be."""
        fns = _verify_functions()
        self.assertTrue(fns, "the AST walk found no verify_* functions — this test would "
                             "pass over an empty set")
        self.assertEqual(len(fns), len(rh.SECTIONS),
                         "one verify per section; a mismatch means a section shares a verify "
                         "or a verify is orphaned")
        self.assertGreater(len(_assertion_sites()), len(fns),
                           "the helpers that build checks must be walked too")

    def test_no_int_literal_other_than_exit_codes(self):
        """`assertEqual(n, 3)` is the mutation this catches."""
        bad = []
        for fn in _assertion_sites():
            exempt = _exempt_nodes(fn)
            for node in ast.walk(fn):
                if isinstance(node, ast.Constant) and isinstance(node.value, int) \
                        and not isinstance(node.value, bool) \
                        and node.value not in ALLOWED_INTS \
                        and id(node) not in exempt:
                    bad.append(f"{fn.name}:{node.lineno} -> {node.value!r}")
        self.assertEqual(bad, [], "int literal in a verify: every count must come from a "
                                  "Fact with a provenance, so the failure report can say "
                                  "WHY it expected that number.\n  " + "\n  ".join(bad))

    def test_every_string_literal_is_a_wire_name_a_fact_or_prose(self):
        known = set(rh.WIRE_NAMES) | set(rh.FACT_SOURCES)
        bad = []
        for fn in _assertion_sites():
            exempt = _exempt_nodes(fn)
            for node in ast.walk(fn):
                if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                    continue
                if id(node) in exempt or node.value in known or node.value == "":
                    continue
                bad.append(f"{fn.name}:{node.lineno} -> {node.value!r}")
        self.assertEqual(bad, [],
                         "string literal in a verify that is not a wire name, a fact handle, "
                         "argv or prose. Either it is a name another program chose (add it "
                         "to WIRE_NAMES with the reason) or it is an expected value (derive "
                         "it).\n  " + "\n  ".join(bad))

    def test_wire_names_all_carry_a_reason(self):
        """A table of bare strings is a list of magic values with extra steps."""
        for name, why in rh.WIRE_NAMES.items():
            with self.subTest(name=name):
                self.assertGreater(len(why), 12,
                                   f"WIRE_NAMES[{name!r}] must say WHY it is a wire name")

    def test_wire_names_holds_no_number(self):
        """A COUNT never belongs in WIRE_NAMES — that is the loophole this
        whole table would otherwise become."""
        for name in rh.WIRE_NAMES:
            with self.subTest(name=name):
                self.assertFalse(name.strip().isdigit(),
                                 f"{name!r} is a number, not a wire name")


if __name__ == "__main__":
    unittest.main()
