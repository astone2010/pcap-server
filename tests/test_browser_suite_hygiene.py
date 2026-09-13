"""The browser suites run against the app's real Content-Security-Policy, which
forbids 'unsafe-eval'. Playwright evaluates a bare expression string with eval,
and a function string without it -- so `page.wait_for_function("a === b")` works
only when the condition is already true on the first check, and fails with an
EvalError the moment it has to poll. That is a timing bug: it passed locally and
on dev.27's CI, then failed on dev.28's. This reads the suites and refuses the
shape outright, so the next one fails here, every time, instead of on a slow
runner."""

from __future__ import annotations

import re
from pathlib import Path

BROWSER_TESTS = Path(__file__).resolve().parent / "browser"

# The first argument, when it is a string literal: "..." or '...'.
_CALL = re.compile(r"""wait_for_function\(\s*(?P<q>["'])(?P<body>.*?)(?P=q)""", re.S)
_FUNCTION = re.compile(r"^\s*(\(\s*[\w\s,]*\)|\w+)\s*=>|^\s*(async\s+)?function\b")


def test_every_wait_for_function_is_given_a_function_not_an_expression():
    offenders = []
    for path in sorted(BROWSER_TESTS.glob("*.py")):
        source = path.read_text()
        for match in _CALL.finditer(source):
            if not _FUNCTION.match(match.group("body")):
                line = source.count("\n", 0, match.start()) + 1
                offenders.append(f"{path.name}:{line}: {match.group('body')[:60]!r}")
    assert offenders == [], (
        "wait_for_function needs a function string such as \"() => ...\" -- a bare "
        "expression is eval'd, which the app's CSP refuses once it has to poll:\n  "
        + "\n  ".join(offenders)
    )


def test_the_check_would_catch_the_bug_it_exists_for():
    bad = 'await page.wait_for_function(\n    "document.title === \'x\'"\n)'
    good = 'await page.wait_for_function("() => document.title === \'x\'")'
    arg = 'await page.wait_for_function("count => count > 1", arg=2)'
    body = lambda s: _CALL.search(s).group("body")
    assert not _FUNCTION.match(body(bad))
    assert _FUNCTION.match(body(good))
    assert _FUNCTION.match(body(arg))
