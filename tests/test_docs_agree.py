"""The explainer's commands are the runbook's commands.

`docs/index.html` shows the setup commands on its "Run it yourself" screens
so a reader can follow along without leaving it. `docs/TUTORIAL.md` is the
runbook those commands come from. Two copies of a command drift, and a wrong
command in a tutorial fails for every reader who trusts it, so every command
line the explainer shows must appear, verbatim, in a code block of the
runbook. Comments and runs of spaces are ignored; nothing else is.
"""
from __future__ import annotations

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path
from typing import List

DOCS = Path(__file__).absolute().parents[1] / "docs"


def _lines(block: str) -> List[str]:
    """The command lines in `block`: continuations joined, comments and
    blank lines dropped, runs of whitespace collapsed."""
    out = []
    for line in re.sub(r"\\\n\s*", " ", block).splitlines():
        line = re.sub(r"(^|\s)#\s.*$", "", line).strip()
        if line:
            out.append(re.sub(r"\s+", " ", line))
    return out


class _CommandBlocks(HTMLParser):
    """The text of every <pre> inside a `.cmd` box."""

    def __init__(self) -> None:
        super().__init__()
        self.blocks: List[str] = []
        self._cmd_depth = 0
        self._depth = 0
        self._pre = False
        self._buf: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "div":
            self._depth += 1
            if "cmd" in (dict(attrs).get("class") or "").split():
                self._cmd_depth = self._depth
        elif tag == "pre" and self._cmd_depth:
            self._pre, self._buf = True, []

    def handle_endtag(self, tag):
        if tag == "pre" and self._pre:
            self.blocks.append("".join(self._buf))
            self._pre = False
        elif tag == "div":
            if self._depth == self._cmd_depth:
                self._cmd_depth = 0
            self._depth -= 1

    def handle_data(self, data):
        if self._pre:
            self._buf.append(data)


def explainer_commands(html: str) -> List[str]:
    parser = _CommandBlocks()
    parser.feed(html)
    return [line for block in parser.blocks for line in _lines(block)]


def runbook_commands(markdown: str) -> List[str]:
    blocks = re.findall(r"^```[a-z]*\n(.*?)^```", markdown, re.M | re.S)
    return [line for block in blocks for line in _lines(block)]


class ExplainerCommandsAreTheRunbooksTest(unittest.TestCase):

    def test_every_command_the_explainer_shows_is_in_the_runbook(self):
        shown = explainer_commands((DOCS / "index.html").read_text(encoding="utf-8"))
        runbook = set(runbook_commands((DOCS / "TUTORIAL.md").read_text(encoding="utf-8")))
        # A parser that found nothing would pass this test while checking
        # nothing, so the explainer must actually show commands.
        self.assertTrue(shown, "found no command blocks in docs/index.html")
        missing = [line for line in shown if line not in runbook]
        self.assertEqual(missing, [], "commands in docs/index.html that docs/TUTORIAL.md "
                                      "does not have, word for word")

    def test_a_changed_command_is_caught(self):
        """The check must be able to fail: a command altered in one copy only."""
        html = '<div class="cmd"><pre>sandy --start --now</pre></div>'
        self.assertEqual(explainer_commands(html), ["sandy --start --now"])
        runbook = set(runbook_commands("```sh\nsandy --start\n```\n"))
        self.assertNotIn("sandy --start --now", runbook)

    def test_comments_continuations_and_entities_are_normalised(self):
        html = ('<div class="cmd"><div class="label">x</div><pre>'
                '<span class="c"># note</span>\ncd a &amp;&amp; b   <span class="c"># why</span>\n'
                'run --x \\\n  --y</pre></div>')
        self.assertEqual(explainer_commands(html), ["cd a && b", "run --x --y"])


if __name__ == "__main__":
    unittest.main()
