"""Catching BPF filters that will not match what the operator meant.

A capture filter that matches nothing does not announce itself. tcpdump starts,
runs for the full duration, and comes back with zero packets -- which looks
exactly like "there was no such traffic". The operator learns nothing except
that they wasted a capture window, and on a production host a capture window is
not always cheap to repeat.

The filters that go wrong this way are almost always BUILT rather than typed.
The capture filter library offers "...and this" as a way to combine two picks,
and for a host row plus a protocol row `and` is right. For two protocol rows it
is wrong, because a packet has one source port and one destination port, and
two services means two more constraints than there are slots to put them in.

Two checks, and they catch different things:

  structural_check()  -- reasons about the port constraints directly. Catches
                         the case libpcap CANNOT flag, because the expression
                         is formally satisfiable and merely useless: `tcp port
                         80 and tcp port 443` does match a packet running from
                         port 80 to port 443, so libpcap compiles it happily.
                         Nothing but a human-intent check will ever object.

  compile_check()     -- hands the expression to tcpdump itself. Authoritative
                         for "rejects all packets" and for syntax, because it
                         IS the compiler the target host will use. Catches
                         typed filters, not only library-built ones.

Neither one refuses a capture. They warn, and the operator decides -- a filter
that looks empty to this module but is deliberate is a filter the operator
should still be able to run.

Calibration note: the structural model was checked against libpcap on the cases
that matter, and the two agree everywhere they can both answer.

    port 88 and port 464                      satisfiable  (src 88 -> dst 464)
    tcp port 80 and tcp port 443              satisfiable  (src 80 -> dst 443)
    port 88 and port 464 and port 53          EMPTY  -- three ports, two slots
    tcp port 80 and udp port 53               EMPTY  -- one packet, one proto
    src port 80 and src port 443              EMPTY  -- one slot, two values

The first two are exactly why this module exists: libpcap is right to compile
them, and they are still almost certainly not what anybody meant.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass, field

# Where tcpdump lives in the image. Resolved through shutil.which at call time
# rather than hardcoded, so a differently-built image still works -- but never
# taken from the request, and never run through a shell.
_TCPDUMP = "tcpdump"

# tcpdump's compile pass is pure CPU over a short string and returns in
# milliseconds. A timeout exists so a pathological expression cannot wedge a
# request handler, not because it is expected to fire.
_COMPILE_TIMEOUT_SECONDS = 5

# The link-layer type the expression is compiled against. It matters: a filter
# can be valid on one DLT and not another, and `-i any` on Linux is not
# Ethernet. The capture the operator is about to take is the one to match.
_DLT_ANY = "LINUX_SLL2"
_DLT_DEFAULT = "EN10MB"

# Guard on the brute-force search below. Real filters name a handful of ports;
# something naming hundreds is not a filter this check should be spending time
# on, and bailing out is always safe because every bail is "no warning".
_MAX_CANDIDATE_PORTS = 64

# Protocols a port constraint can land on. sctp is in the list because a bare
# `port 80` matches it too, so leaving it out would let the search conclude
# "unsatisfiable" for an expression that a real sctp packet satisfies.
_PROTOCOLS = ("tcp", "udp", "sctp")

_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


@dataclass(frozen=True)
class FilterWarning:
    """Advisory, never a refusal. `code` is what the UI branches on."""

    code: str
    message: str
    detail: str = ""


@dataclass
class _Alternative:
    """One `port`-shaped term: `tcp src port 80`, `port 53`, `portrange 1-1024`."""

    ports: frozenset[int]
    # Which of a packet's two port fields this term is allowed to satisfy.
    # A bare `port N` may use either; `src port N` may only use the source.
    slots: frozenset[str]
    # None means the term did not name one, so it rides on any of _PROTOCOLS.
    proto: str | None = None


@dataclass
class _Constraint:
    """One top-level `and` operand, as a disjunction of port terms.

    Satisfied when ANY of its alternatives is -- `(tcp port 445 or tcp port
    135)` is one constraint with two alternatives, not two constraints.
    """

    alternatives: list[_Alternative] = field(default_factory=list)
    source: str = ""

    def ports(self) -> frozenset[int]:
        out: set[int] = set()
        for alt in self.alternatives:
            out |= alt.ports
        return frozenset(out)


def _tokenize(expr: str) -> list[str]:
    return _TOKEN_RE.findall(expr.lower())


def _split_top_level(tokens: list[str], operators: tuple[str, ...]) -> list[list[str]] | None:
    """Split on `operators` at paren depth zero. None if the parens do not balance.

    Unbalanced parens are not this module's problem to report -- tcpdump will
    say so far better than a hand-rolled parser can. Returning None sends the
    expression to the compile check without a structural opinion.
    """
    parts: list[list[str]] = [[]]
    depth = 0
    for tok in tokens:
        if tok == "(":
            depth += 1
        elif tok == ")":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0 and tok in operators:
            parts.append([])
            continue
        parts[-1].append(tok)
    if depth != 0:
        return None
    return parts


def _strip_parens(tokens: list[str]) -> list[str]:
    """Remove parentheses that wrap the whole token list, however many deep."""
    while len(tokens) >= 2 and tokens[0] == "(" and tokens[-1] == ")":
        inner = tokens[1:-1]
        # Only redundant if that closing paren is the partner of the opening
        # one. `(a) and (b)` also starts with `(` and ends with `)`, and
        # stripping them would produce nonsense.
        depth = 0
        for i, tok in enumerate(inner):
            if tok == "(":
                depth += 1
            elif tok == ")":
                depth -= 1
                if depth < 0:
                    return tokens
        if depth != 0:
            return tokens
        tokens = inner
    return tokens


def _parse_alternative(tokens: list[str]) -> _Alternative | None:
    """`[proto] [src|dst] port N` / `... portrange A-B`, or None for anything else.

    None is the safe answer and is returned generously. Every caller treats an
    unparsed term as "constrains nothing", which can only ever make this module
    quieter -- never make it warn about something it has not understood.
    """
    tokens = _strip_parens(tokens)
    if not tokens:
        return None

    proto: str | None = None
    slots = {"src", "dst"}
    i = 0

    if tokens[i] in _PROTOCOLS:
        proto = tokens[i]
        i += 1
    elif tokens[i] in ("ip", "ip6", "arp", "rarp", "ether", "vlan", "mpls"):
        # A layer qualifier this model does not track. Bail rather than guess:
        # treating `ip port 80` as an unqualified port term would be a claim
        # about traffic the term does not actually cover.
        return None

    if i < len(tokens) and tokens[i] in ("src", "dst"):
        slots = {tokens[i]}
        i += 1
        # `src or dst port 80` never reaches here -- the `or` splits it into
        # alternatives upstream and the bare `src` fails to parse, which drops
        # the whole constraint. Incomplete, not wrong.

    if i >= len(tokens):
        return None

    keyword = tokens[i]
    i += 1
    rest = tokens[i:]

    if keyword == "port" and len(rest) == 1 and rest[0].isdigit():
        return _Alternative(frozenset({int(rest[0])}), frozenset(slots), proto)

    if keyword == "portrange" and len(rest) == 1:
        m = re.fullmatch(r"(\d+)-(\d+)", rest[0])
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo <= hi and hi - lo <= _MAX_CANDIDATE_PORTS:
                return _Alternative(frozenset(range(lo, hi + 1)), frozenset(slots), proto)
        return None

    # Named ports (`port domain`) are deliberately not resolved. The mapping
    # lives in /etc/services on the TARGET, not here, so any answer this module
    # gave would be a guess about a file it cannot read.
    return None


def _collect(tokens: list[str]) -> list[_Constraint]:
    """Every port constraint an `and`-chain imposes, however it is bracketed.

    Recursive because parenthesised sub-expressions nest arbitrarily and the
    operator's clicks produce exactly that: `((port 88) and (port 464)) and
    (...)` is what the filter library builds after three picks. Flattening it
    to the three constraints it really is, rather than stopping at the first
    pair of brackets, is the difference between "this matches nothing" and a
    much weaker warning.

    An empty list means "imposes nothing this model can use", which every
    caller treats as no constraint at all. That is the safe direction: it can
    only make the check quieter.
    """
    tokens = _strip_parens(tokens)
    if not tokens:
        return []

    # A disjunction first, because `or` binds loosest. If the whole thing is a
    # list of port terms it collapses to one constraint with several
    # alternatives; otherwise it constrains nothing we can pin down, since
    # satisfying either branch satisfies the whole.
    or_groups = _split_top_level(tokens, ("or", "||"))
    if or_groups is None:
        return []
    if len(or_groups) > 1:
        alternatives = [_parse_alternative(g) for g in or_groups]
        if alternatives and all(a is not None for a in alternatives):
            return [_Constraint(
                [a for a in alternatives if a is not None],
                _render(tokens),
            )]
        return []

    and_groups = _split_top_level(tokens, ("and", "&&"))
    if and_groups is None:
        return []
    if len(and_groups) > 1:
        out: list[_Constraint] = []
        for group in and_groups:
            out.extend(_collect(group))
        return out

    # A single term with no operator left in it. If stripping brackets changed
    # nothing there is no further structure to find, and it is a port term or
    # it is nothing.
    stripped = _strip_parens(tokens)
    if stripped != tokens:
        return _collect(stripped)

    alt = _parse_alternative(tokens)
    return [_Constraint([alt], _render(tokens))] if alt else []


def _render(tokens: list[str]) -> str:
    """Tokens back to something readable enough to quote in a warning."""
    out = ""
    for tok in tokens:
        if tok == "(":
            out += "("
        elif tok == ")":
            out = out.rstrip() + ") "
        else:
            out += tok + " "
    return " ".join(out.split()).strip()


def _parse_constraints(expr: str) -> list[_Constraint] | None:
    """The port constraints an expression imposes, or None to stand down.

    None means "do not reason about this expression at all", and is returned
    for negation: `not` flips a constraint into its complement and the search
    below has no representation for that. One `not` anywhere is enough.
    """
    tokens = _tokenize(expr)
    if not tokens:
        return None
    if any(t in ("not", "!") for t in tokens):
        return None
    return _collect(tokens)


def _satisfiable(constraints: list[_Constraint]) -> bool:
    """Can one packet satisfy every constraint at once?

    A packet offers exactly three things this model cares about: a protocol, a
    source port and a destination port. So the search is over those three, and
    the candidate values are the ports actually named plus one standing for
    "some other port entirely" -- which is what makes `port 80 and host X`
    come out satisfiable rather than being forced onto a named value.
    """
    if not constraints:
        return True

    candidates: set[int] = set()
    for c in constraints:
        candidates |= c.ports()
    if len(candidates) > _MAX_CANDIDATE_PORTS:
        return True  # Not worth searching; silence is always the safe answer.

    values: list[int | None] = [None, *sorted(candidates)]

    for proto in _PROTOCOLS:
        for src in values:
            for dst in values:
                if all(_holds(c, proto, src, dst) for c in constraints):
                    return True
    return False


def _holds(constraint: _Constraint, proto: str, src: int | None, dst: int | None) -> bool:
    for alt in constraint.alternatives:
        if alt.proto is not None and alt.proto != proto:
            continue
        if "src" in alt.slots and src is not None and src in alt.ports:
            return True
        if "dst" in alt.slots and dst is not None and dst in alt.ports:
            return True
    return False


def structural_check(expr: str) -> FilterWarning | None:
    """Port-level reasoning about an expression, without compiling it.

    Sound rather than complete: every warning it raises is one it can justify,
    and it stays quiet about anything it does not fully understand. The compile
    check is what covers the rest.
    """
    if not expr or not expr.strip():
        return None

    constraints = _parse_constraints(expr)
    if constraints is None or len(constraints) < 2:
        return None

    if not _satisfiable(constraints):
        return FilterWarning(
            code="bpf_matches_nothing",
            message="This filter cannot match any packet, so the capture would come back empty.",
            detail=(
                "It requires "
                + _describe(constraints)
                + " all at once. A packet has one source port and one destination "
                "port, so it can satisfy at most two port conditions -- and only "
                "if they are on opposite ends of the same conversation. Joining "
                "these with `or` instead would capture all of them."
            ),
        )

    # Satisfiable, and still almost certainly not what was meant. Two library
    # picks for two different services, joined with `and`, match only traffic
    # running BETWEEN those two services -- which is usually nothing.
    port_sets = [c.ports() for c in constraints if c.ports()]
    if len(port_sets) >= 2 and _pairwise_disjoint(port_sets):
        return FilterWarning(
            code="bpf_cross_service_only",
            message=(
                "This filter matches only traffic going directly between these "
                "services, which is usually nothing."
            ),
            detail=(
                "It requires "
                + _describe(constraints)
                + " on the same packet. That is satisfied only when one of them is "
                "the source port and another is the destination port. To capture "
                "each of them instead, join them with `or`."
            ),
        )

    return None


def _pairwise_disjoint(sets: list[frozenset[int]]) -> bool:
    for i, a in enumerate(sets):
        for b in sets[i + 1:]:
            if a & b:
                return False
    return True


def _describe(constraints: list[_Constraint]) -> str:
    parts = [c.source for c in constraints if c.ports()]
    if len(parts) <= 1:
        return parts[0] if parts else "these conditions"
    return ", ".join(f"`{p}`" for p in parts[:-1]) + f" and `{parts[-1]}`"


def _dlt_for(interface: str) -> str:
    """`-i any` is LINUX_SLL2, not Ethernet, and the difference is real.

    Compiling against the wrong link type can accept an expression the target
    rejects, or the other way round. This is still an approximation -- the
    target's own tcpdump is the only authority -- but matching the one thing
    that is knowable here is better than always assuming Ethernet.
    """
    return _DLT_ANY if interface.strip().lower() == "any" else _DLT_DEFAULT


async def compile_check(expr: str, interface: str = "any") -> FilterWarning | None:
    """Ask tcpdump to compile the expression without capturing anything.

    `-d` dumps the compiled program and exits; it opens no interface, needs no
    privilege, and touches no network. What it gives back is the real libpcap
    verdict, which is the same verdict the target host will reach.
    """
    if not expr or not expr.strip():
        return None

    binary = shutil.which(_TCPDUMP)
    if not binary:
        # Nothing to report. A missing local tcpdump is a property of this
        # container, not of the operator's filter, and turning it into a
        # warning on their screen would be noise they cannot act on.
        return None

    # `--` is load-bearing, not tidiness. Without it a filter beginning with a
    # dash is read as an option: `-r /etc/passwd` made tcpdump try to OPEN that
    # file rather than parse it as an expression. After `--` the same string is
    # a syntax error, which is what it should have been all along.
    args = [binary, "-d", "-y", _dlt_for(interface), "--", expr]

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError:
        return None

    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), _COMPILE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        # wait_for gives up waiting; it does NOT stop what it was waiting for.
        # Without this the tcpdump stays alive and unreaped, and this endpoint
        # is reachable on a keystroke, so a timeout that leaked would leak once
        # per call. Same shape as the tshark teardown in packet_parser.
        if proc.returncode is None:
            proc.kill()
        await asyncio.gather(proc.wait(), return_exceptions=True)
        return None
    except OSError:
        if proc.returncode is None:
            proc.kill()
        await asyncio.gather(proc.wait(), return_exceptions=True)
        return None

    if proc.returncode == 0:
        return None

    message = stderr.decode("utf-8", "replace").strip()
    # tcpdump prefixes its own name; the UI already knows where this came from.
    first = message.splitlines()[0] if message else ""
    first = re.sub(r"^tcpdump:\s*", "", first).strip()

    if "rejects all packets" in message:
        return FilterWarning(
            code="bpf_matches_nothing",
            message="tcpdump reports that this filter cannot match any packet.",
            detail=(
                "The capture would run for its full duration and come back empty. "
                "This usually means two conditions were joined with `and` where "
                "`or` was meant."
            ),
        )

    return FilterWarning(
        code="bpf_invalid",
        message="tcpdump cannot parse this filter.",
        detail=first or "The expression was rejected by the filter compiler.",
    )


async def check_filter(expr: str, interface: str = "any") -> FilterWarning | None:
    """Both checks, strongest finding first.

    The compile check goes first because it is the authority on whether the
    expression is even valid, and a syntax error makes any structural opinion
    about it meaningless.
    """
    compiled = await compile_check(expr, interface)
    if compiled is not None:
        return compiled
    return structural_check(expr)
