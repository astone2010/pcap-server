"""The capture filter library, checked against the two things that can refuse it.

The library is a constant in app.js and the API that runs its expressions is
Python, so nothing connected the two. They had drifted: `validate_bpf` banned
`&` and `|` along with the shell metacharacters, and every tcpflags filter
needs `&` -- so the app offered eight filters its own API rejected, the whole
TCP-behaviour group among them. Choosing one and pressing Start failed with
"BPF filter contains disallowed characters", and no test in the repo could
see it, because each half was correct on its own terms.

These read the real list out of app.js and put every expression through both
gates: the validator that guards the request, and tcpdump itself, which is the
only authority on whether an expression is a filter at all.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from backend.models import CaptureRequest

APP_JS = Path(__file__).resolve().parent.parent / "frontend" / "js" / "app.js"

# The library holds addresses and ports from its own examples; the placeholders
# are literal and resolvable without a network, which matters because tcpdump
# resolves names at compile time.
_PAIR = re.compile(r'\["((?:[^"\\]|\\.)*)",\s*"((?:[^"\\]|\\.)*)"\]', re.S)


def _block(source: str, start: str, end: str) -> str:
    return source[source.index(start):source.index(end)]


def _expressions(start: str, end: str) -> list[tuple[str, str]]:
    source = APP_JS.read_text()
    return _PAIR.findall(_block(source, start, end))


def _library() -> list[tuple[str, str]]:
    return _expressions("const FILTER_LIBRARY", "let filterLibraryQuery")


def _suggestions() -> list[tuple[str, str]]:
    return _expressions("const BPF_SUGGESTIONS", "function renderFilterSuggestions")


def test_the_library_was_actually_found():
    """A regex that silently matched nothing would make every test below pass
    without checking anything at all."""
    entries = _library()
    assert len(entries) > 50, f"only {len(entries)} library expressions parsed"
    assert any("tcpflags" in expr for _, expr in entries)


@pytest.mark.parametrize("label, expr", _library())
def test_every_library_filter_is_accepted_by_the_api(label, expr):
    """The gate an operator meets when they press Start."""
    try:
        CaptureRequest(server_id="s1", interface="eth0", bpf_filter=expr)
    except ValidationError as exc:
        pytest.fail(f"the library offers {label!r} but the API refuses it: {expr}\n{exc}")


@pytest.mark.parametrize("label, expr", _suggestions())
def test_every_suggestion_chip_is_accepted_by_the_api(label, expr):
    """The chips are the worked examples on the Capture tab. One of them --
    the tcpflags SYN filter -- was refused too."""
    try:
        CaptureRequest(server_id="s1", interface="eth0", bpf_filter=expr)
    except ValidationError as exc:
        pytest.fail(f"the chip {label!r} is refused by the API: {expr}\n{exc}")


@pytest.mark.skipif(not shutil.which("tcpdump"), reason="tcpdump not installed")
@pytest.mark.parametrize("label, expr", _library())
def test_every_library_filter_compiles(label, expr):
    """tcpdump is the only authority on whether an expression is a filter.

    -d compiles and dumps the program without opening an interface, so this
    needs no privileges and captures nothing.
    """
    result = subprocess.run(
        ["tcpdump", "-d", expr],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, \
        f"the library offers {label!r} and tcpdump will not compile it: {expr}\n{result.stderr}"


@pytest.mark.skipif(not shutil.which("tcpdump"), reason="tcpdump not installed")
def test_the_fragment_filters_match_what_they_claim():
    """Both halves of the test are needed.

    The first fragment of a set carries MF with offset 0; every later one has a
    non-zero offset. Matching only the offset misses the first fragment, which
    is the one carrying the transport headers -- so the two rows are not
    duplicates of each other.
    """
    library = dict((expr, label) for label, expr in _library())
    all_frags = "ip[6] & 0x20 != 0 or ip[6:2] & 0x1fff != 0"
    later_only = "ip[6:2] & 0x1fff != 0"
    assert all_frags in library
    assert later_only in library
    for expr in (all_frags, later_only):
        assert subprocess.run(
            ["tcpdump", "-d", expr], capture_output=True, timeout=10
        ).returncode == 0
