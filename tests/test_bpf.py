"""The BPF combination checks, against the only authority that settles them.

There are two checks and they are tested differently on purpose.

`compile_check` runs the real tcpdump, so testing it is just a matter of
handing it expressions and reading the verdict back.

`structural_check` is a MODEL of what libpcap does, written because libpcap
cannot answer the question that matters most: `tcp port 80 and tcp port 443`
compiles perfectly well -- it matches a packet running from port 80 to port 443
-- and is still almost never what anybody meant. A model like that earns its
keep only if it never contradicts the compiler where they do overlap, so the
central test here does not assert hand-written expectations at all. It puts a
corpus through BOTH and requires them to agree.

That distinction is the point. A test that only checked
`structural_check("port 88 and port 464 and port 53")` against a value typed
here would still pass if the model and libpcap had drifted apart, because the
typed value would have drifted with it.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from backend import bpf

pytestmark = pytest.mark.asyncio

needs_tcpdump = pytest.mark.skipif(
    shutil.which("tcpdump") is None,
    reason="tcpdump not installed -- install it, or run the tests in the container image",
)


def tcpdump_rejects_all(expr: str, dlt: str = "EN10MB") -> bool:
    """What libpcap itself concludes. `-d` compiles and exits; nothing is captured."""
    proc = subprocess.run(
        ["tcpdump", "-d", "-y", dlt, "--", expr],
        capture_output=True, text=True, timeout=30,
    )
    return "rejects all packets" in proc.stderr


# Expressions where libpcap can reach a verdict, so the model must not
# contradict it. Both columns matter: the satisfiable ones are where a model
# that warns too eagerly gets caught, and eager warnings are the failure mode
# that makes a checker worthless -- an operator who has clicked through three
# wrong warnings will click through the right one too.
AGREEMENT_CORPUS = [
    "port 88 and port 464",
    "tcp port 80 and tcp port 443",
    "port 88 and port 464 and port 53",
    "tcp port 80 and udp port 53",
    "src port 80 and src port 443",
    "dst port 80 and dst port 443",
    "port 88 and port 464 and port 53 and port 22",
    "(tcp port 445 or tcp port 135) and (port 464)",
    "((port 88) and (port 464)) and (tcp port 445 or tcp port 135) and (port 53)",
    "port 88 or port 389",
    "host 10.0.0.1 and tcp port 445",
    "host 10.0.0.1 and (tcp port 445 or port 88)",
    "tcp port 445 or port 137 or port 138 or tcp port 139",
    "port 88 and port 88",
    "tcp port 80 and port 80",
    "portrange 1-100 and port 50",
    "portrange 1-100 and port 500 and port 600",
    "udp port 53 and udp port 5353 and udp port 123",
    "net 192.168.1.0/24 and tcp port 443",
    "src port 80 and dst port 443",
]


@needs_tcpdump
@pytest.mark.parametrize("expr", AGREEMENT_CORPUS)
async def test_the_model_never_contradicts_libpcap(expr):
    """Where libpcap has an opinion, the structural model must not disagree.

    One direction only, and deliberately. `bpf_matches_nothing` is a claim
    about emptiness and libpcap is the authority on that, so claiming it where
    libpcap compiles the filter is a bug. The reverse is not: the model is
    allowed to stay quiet where libpcap objects, because the compile check is
    what covers that case and runs first.
    """
    warning = bpf.structural_check(expr)
    claims_empty = warning is not None and warning.code == "bpf_matches_nothing"
    if claims_empty:
        assert tcpdump_rejects_all(expr), (
            f"structural_check called {expr!r} empty, but libpcap compiles it. "
            "The model is now stricter than the compiler, which means it is wrong."
        )


@needs_tcpdump
async def test_everything_libpcap_rejects_is_caught_by_one_check_or_the_other():
    """The pair has to cover what the compiler catches, even if either alone does not.

    One test over the whole corpus rather than one per expression, because the
    per-expression form had to skip every case libpcap accepts -- and this
    repo reads its skip count as the signal that the browser suite really ran
    (scripts/check.sh, and the notes in the release checklist). Tests that skip
    as a matter of routine make that number mean nothing.
    """
    empty = [e for e in AGREEMENT_CORPUS if tcpdump_rejects_all(e)]
    assert empty, "the corpus no longer contains any filter libpcap rejects"

    missed = []
    for expr in empty:
        warning = await bpf.check_filter(expr, interface="eth0")
        if warning is None or warning.code != "bpf_matches_nothing":
            missed.append(expr)
    assert not missed, f"libpcap rejects these as empty and neither check said so: {missed}"


# --- the cases the model exists for -------------------------------------

async def test_a_filter_libpcap_accepts_can_still_be_flagged_as_useless():
    """The whole reason this module is not just a tcpdump wrapper.

    libpcap is right to compile this: a packet with source port 80 and
    destination port 443 matches it. No such traffic exists in practice, and
    nothing but a model of intent will ever say so.
    """
    warning = bpf.structural_check("tcp port 80 and tcp port 443")
    assert warning is not None
    assert warning.code == "bpf_cross_service_only"


async def test_three_ports_cannot_fit_in_two_slots():
    warning = bpf.structural_check("port 88 and port 464 and port 53")
    assert warning is not None
    assert warning.code == "bpf_matches_nothing"
    # The advice has to be actionable, not just a verdict.
    assert "`or`" in warning.detail


async def test_one_packet_cannot_be_two_protocols():
    warning = bpf.structural_check("tcp port 80 and udp port 53")
    assert warning is not None
    assert warning.code == "bpf_matches_nothing"


async def test_one_slot_cannot_hold_two_values():
    warning = bpf.structural_check("src port 80 and src port 443")
    assert warning is not None
    assert warning.code == "bpf_matches_nothing"


async def test_the_reported_filter_from_the_field():
    """The expression that prompted all of this, exactly as tcpdump received it."""
    expr = ("(((port 88) and (port 464)) and (tcp port 445 or tcp port 135 or "
            "tcp port 389 or tcp port 80 or tcp port 443)) and (port 53)")
    warning = bpf.structural_check(expr)
    assert warning is not None
    assert warning.code == "bpf_matches_nothing"


async def test_nested_brackets_are_flattened_not_abandoned():
    """Without recursion the inner `and` hides inside its brackets.

    This is not hypothetical: the first version stopped at the outer pair, lost
    both port terms inside it, and downgraded a filter that matches nothing to
    the milder cross-service warning. The library builds this shape after three
    picks, so it is the common case, not an edge one.
    """
    flat = bpf.structural_check("port 88 and port 464 and port 53")
    nested = bpf.structural_check("((port 88) and (port 464)) and (port 53)")
    assert nested is not None and flat is not None
    assert nested.code == flat.code == "bpf_matches_nothing"


# --- staying quiet ------------------------------------------------------

@pytest.mark.parametrize("expr", [
    "",
    "   ",
    "tcp",
    "net 192.168.1.0/24",
    "host 10.0.0.1",
    "port 88 or port 389",
    "port 88",
    "host 10.0.0.1 and tcp port 445",
    "host 10.0.0.10 and (tcp port 445 or port 88)",
    "not (tcp port 22 and host 10.0.0.1)",
    "src net 192.168.1.0/24 and not dst net 192.168.1.0/24",
    "port 88 and port 88",
    "(port 80 or host 10.0.0.1) and port 443",
    "tcp[tcpflags] & tcp-syn != 0",
])
async def test_says_nothing_about_filters_it_cannot_fault(expr):
    assert bpf.structural_check(expr) is None


async def test_a_disjunction_branch_does_not_constrain_ports():
    """`(port 80 or host X) and port 443` is satisfied via the host branch.

    Reading the first operand as "the port must be 80" would be a claim the
    expression does not make, and would produce a warning about a filter that
    is perfectly good.
    """
    assert bpf.structural_check("(port 80 or host 10.0.0.1) and port 443") is None


async def test_negation_stands_the_model_down_entirely():
    """`not` inverts a constraint and the search has no representation for it.

    Reasoning about it anyway would invert the verdict, which is worse than
    having no verdict.
    """
    assert bpf.structural_check("not (port 88) and port 464 and port 53") is None


async def test_named_ports_are_not_guessed():
    """/etc/services lives on the TARGET, so any mapping here would be a guess."""
    assert bpf.structural_check("port domain and port http and port https") is None


# --- the compile check --------------------------------------------------

@needs_tcpdump
async def test_compile_check_reports_an_empty_filter():
    warning = await bpf.compile_check("port 88 and port 464 and port 53", "eth0")
    assert warning is not None
    assert warning.code == "bpf_matches_nothing"


@needs_tcpdump
async def test_compile_check_reports_a_syntax_error_with_tcpdumps_own_words():
    warning = await bpf.compile_check("port and and", "eth0")
    assert warning is not None
    assert warning.code == "bpf_invalid"
    assert warning.detail
    # tcpdump's own text, minus the prefix naming itself.
    assert not warning.detail.startswith("tcpdump:")


@needs_tcpdump
async def test_compile_check_passes_a_good_filter():
    assert await bpf.compile_check("tcp port 443 and host 10.0.0.1", "eth0") is None


@needs_tcpdump
async def test_the_any_interface_is_compiled_as_the_link_type_it_actually_is():
    """`-i any` on Linux is LINUX_SLL2, not Ethernet, and filters can differ.

    Compiling against the wrong link type can accept an expression the target
    rejects, or the reverse. This asserts the DLT choice is wired through
    rather than that any particular expression behaves differently under it.
    """
    assert bpf._dlt_for("any") == "LINUX_SLL2"
    assert bpf._dlt_for("eth0") == "EN10MB"
    assert bpf._dlt_for(" ANY ") == "LINUX_SLL2"
    assert await bpf.compile_check("port 88 and port 464 and port 53", "any") is not None


@needs_tcpdump
async def test_a_filter_that_looks_like_a_flag_cannot_reach_tcpdumps_option_parser():
    """`--` is a security boundary here, not tidiness.

    Without it, tcpdump reads a leading-dash expression as an option: `-r
    /etc/passwd` made it try to OPEN that file instead of parsing it. The
    capture path bans these separately, but this endpoint is reached while the
    field is still being typed into, so it has to be safe on its own.
    """
    warning = await bpf.compile_check("-r /etc/passwd", "eth0")
    assert warning is not None
    assert warning.code == "bpf_invalid"
    # The giveaway for the old behaviour: tcpdump complaining about the FILE
    # rather than about the expression.
    assert "No such file" not in warning.detail
    assert "/etc/passwd" not in warning.detail


@needs_tcpdump
async def test_check_filter_prefers_the_compilers_verdict():
    """A syntax error makes any structural opinion about the string meaningless."""
    warning = await bpf.check_filter("port 80 and and port 443", "eth0")
    assert warning is not None
    assert warning.code == "bpf_invalid"


async def test_a_missing_tcpdump_is_not_the_operators_problem(monkeypatch):
    """It is a property of this container, and not something they can act on."""
    monkeypatch.setattr(bpf.shutil, "which", lambda _: None)
    assert await bpf.compile_check("port 88 and port 464 and port 53", "eth0") is None


async def test_an_empty_filter_is_never_warned_about():
    assert await bpf.check_filter("", "any") is None
    assert await bpf.check_filter("   ", "any") is None


# --- the shipped library must never trip its own checker ----------------

def _library_expressions() -> list[str]:
    """Every expression the capture filter library offers, read from app.js.

    Read rather than duplicated for the same reason test_filter_library.py
    does it: a copy here would drift from the list the operator actually sees,
    and the drift would be invisible.
    """
    from pathlib import Path
    import re as _re

    source = (Path(__file__).resolve().parent.parent
              / "frontend" / "js" / "app.js").read_text()
    block = source[source.index("const FILTER_LIBRARY"):source.index("\nfunction renderFilterLibrary")]
    return [m.group(2) for m in
            _re.finditer(r'\["((?:[^"\\]|\\.)*)",\s*"((?:[^"\\]|\\.)*)"\]', block, _re.S)]


async def test_the_library_offers_nothing_the_checker_objects_to():
    """Every row, on its own, has to come back clean.

    A library that trips its own warning teaches operators to dismiss the
    warning, which costs more than the check is worth. This is the same
    drift-catching shape as test_filter_library.py: both halves are read from
    the source rather than restated.
    """
    expressions = _library_expressions()
    assert len(expressions) > 20, "the library did not parse -- the format moved"

    flagged = [(e, w.code) for e in expressions
               if (w := bpf.structural_check(e)) is not None]
    assert not flagged, f"library rows flagged by their own checker: {flagged}"


# --- the endpoint -------------------------------------------------------

class TestTheCheckEndpoint:
    """`GET /api/bpf/check`, and the two decisions baked into its shape.

    It is a GET because it changes nothing -- and because the
    read-only-over-HTTP middleware refuses mutating calls, so a POST would
    vanish in exactly the configuration where a wasted capture is hardest to
    retry. It lives under /api/bpf/ rather than /api/captures/ because
    /api/captures/{capture_id} would otherwise match `check-filter` as an id.
    """

    @staticmethod
    @pytest.fixture()
    def signed_in():
        import uuid as _uuid
        from fastapi.testclient import TestClient
        from backend.auth import create_session_token
        from backend import main

        with TestClient(main.app) as client:
            user_id = str(_uuid.uuid4())
            main.db.create_user(user_id, f"bpf-{user_id[:8]}", "scrypt$1$1$1$00$00", is_admin=True)
            main.db.set_totp_secret(user_id, "A" * 32)
            main.db.confirm_totp(user_id)
            token, _ = create_session_token(main.db, user_id)
            client.cookies.set("session", token)
            try:
                yield client
            finally:
                main.db.delete_user(user_id)

    @staticmethod
    async def test_it_needs_a_session():
        from fastapi.testclient import TestClient
        from backend import main

        with TestClient(main.app) as anonymous:
            resp = anonymous.get("/api/bpf/check", params={"bpf_filter": "port 80"})
        assert resp.status_code == 401

    @staticmethod
    async def test_a_good_filter_comes_back_clean(signed_in):
        resp = signed_in.get("/api/bpf/check",
                             params={"bpf_filter": "tcp port 443", "interface": "eth0"})
        assert resp.status_code == 200
        assert resp.json() == {"ok": True, "warning": None}

    @staticmethod
    async def test_an_empty_filter_is_clean(signed_in):
        resp = signed_in.get("/api/bpf/check", params={"bpf_filter": ""})
        assert resp.json() == {"ok": True, "warning": None}

    @staticmethod
    @needs_tcpdump
    async def test_the_reported_filter_is_flagged(signed_in):
        resp = signed_in.get("/api/bpf/check", params={
            "bpf_filter": "((port 88) and (port 464)) and (tcp port 445) and (port 53)",
            "interface": "any",
        })
        body = resp.json()
        assert body["ok"] is False
        assert body["warning"]["code"] == "bpf_matches_nothing"
        assert body["warning"]["message"]

    @staticmethod
    async def test_forbidden_characters_are_reported_not_raised(signed_in):
        """The capture path refuses these with a 422 on the Start button.

        Saying so here instead puts it on screen while the field is still
        being edited, which is the only point at which it is easy to fix.
        """
        resp = signed_in.get("/api/bpf/check", params={"bpf_filter": "port 80; rm -rf /"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert body["warning"]["code"] == "bpf_invalid"
        assert "`;`" in body["warning"]["detail"]

    @staticmethod
    @needs_tcpdump
    async def test_it_never_reads_a_file_named_by_the_filter(signed_in):
        """A leading-dash expression must not reach tcpdump's option parser.

        This endpoint is callable with an arbitrary string by anyone with a
        session, so the `--` guard in compile_check is load-bearing here rather
        than incidental.
        """
        resp = signed_in.get("/api/bpf/check", params={"bpf_filter": "-r /etc/passwd"})
        body = resp.json()
        assert body["ok"] is False
        assert "/etc/passwd" not in body["warning"]["detail"]

    @staticmethod
    async def test_it_is_rate_limited(signed_in, monkeypatch):
        """It spawns a process per call, from a field somebody is typing in."""
        from backend.auth import SlidingWindowLimiter
        from backend import main

        monkeypatch.setattr(main, "filter_check_rate_limiter", SlidingWindowLimiter(max_per_minute=2))
        for _ in range(2):
            assert signed_in.get("/api/bpf/check", params={"bpf_filter": "port 80"}).status_code == 200
        assert signed_in.get("/api/bpf/check", params={"bpf_filter": "port 80"}).status_code == 429

    @staticmethod
    async def test_it_survives_the_read_only_gate(signed_in):
        """The whole reason it is a GET.

        `signed_in` arrives over plain HTTP, which is where the middleware
        refuses anything mutating. A POST here would have been a 403 in the one
        configuration where the operator most needs the warning.
        """
        resp = signed_in.get("/api/bpf/check", params={"bpf_filter": "tcp port 443"})
        assert resp.status_code == 200


async def test_a_timed_out_compile_is_killed_not_abandoned(monkeypatch):
    """`wait_for` stops waiting; it does not stop the process.

    This endpoint is reachable on a keystroke, so a timeout that left the
    process behind would leak one tcpdump per call.
    """
    import asyncio as _asyncio

    killed = []

    class _HangingProc:
        returncode = None

        async def communicate(self):
            await _asyncio.sleep(3600)

        def kill(self):
            killed.append(True)
            self.returncode = -9

        async def wait(self):
            return self.returncode

    async def _fake_exec(*_args, **_kwargs):
        return _HangingProc()

    monkeypatch.setattr(bpf.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(bpf, "_COMPILE_TIMEOUT_SECONDS", 0.05)

    assert await bpf.compile_check("port 80", "eth0") is None
    assert killed, "a timed-out tcpdump must be killed, not left running"
