"""Tests for entrypoint.sh -- the container's ownership fix-up and its write check.

The script had no coverage at all, which is how it shipped doing nothing when
DATA_DIR/CAPTURES_DIR/SSH_KEYS_DIR were unset: docker-compose.yml always sets
them, so no run anyone ever performed exercised the other branch.

Running it for real needs `chown` (root) and `gosu` (not installed outside the
image), so both are stubbed onto PATH along with `mkdir`. The gosu stub drops
the username and execs the rest as the test user, which is what makes the write
probe a real test of writability rather than a mock of one: the probe genuinely
creates and removes a file, and the unwritable cases genuinely fail.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ENTRYPOINT = Path(__file__).resolve().parent.parent / "entrypoint.sh"

# The paths backend/main.py falls back to, which the script must now target when
# nothing is set. Kept as a literal rather than imported: the point of the test
# is that the two agree, and importing one from the other would assert nothing.
APP_PATHS = ("/app/ssh-keys", "/app/captures", "/app/data")

running_as_root = os.geteuid() == 0


def _stub_bin(tmp_path, *, chown_fails=False):
    """A PATH directory holding the three commands the script cannot really run.

    `chown` records what it was asked to change so a test can assert the script
    got as far as asking. `mkdir` records and lies about success, so the
    unset-variables case can prove it targets /app/... without a test creating
    /app on the developer's machine.
    """
    stub = tmp_path / "stubbin"
    stub.mkdir()
    log = tmp_path / "stub.log"

    chown_body = (
        f'echo "chown $*" >> "{log}"\n'
        + ('echo "stub chown refused" >&2\nexit 1\n' if chown_fails else "exit 0\n")
    )
    (stub / "chown").write_text("#!/bin/sh\n" + chown_body)
    (stub / "mkdir").write_text(f'#!/bin/sh\necho "mkdir $*" >> "{log}"\nexit 0\n')
    # Drop the username argument and run the rest as whoever is running the
    # tests. Everything the real gosu does beyond that is privilege dropping,
    # which is not what these tests are about.
    (stub / "gosu").write_text('#!/bin/sh\nshift\nexec "$@"\n')
    for name in ("chown", "mkdir", "gosu"):
        (stub / name).chmod(0o755)
    return stub, log


def _run(tmp_path, dirs=None, *, chown_fails=False):
    stub, log = _stub_bin(tmp_path, chown_fails=chown_fails)
    env = {
        "PATH": f"{stub}:/usr/bin:/bin",
        # A command with visible output, so a test can tell "the script reached
        # the exec" from "the script exited early with status 0".
        "HOME": str(tmp_path),
    }
    for name, value in (dirs or {}).items():
        env[name] = str(value)
    proc = subprocess.run(
        ["sh", str(ENTRYPOINT), "echo", "container-started"],
        env=env, capture_output=True, text=True, timeout=30,
    )
    proc.stub_log = log.read_text() if log.exists() else ""   # type: ignore[attr-defined]
    return proc


def _dirs(tmp_path):
    made = {}
    for name, leaf in (
        ("SSH_KEYS_DIR", "ssh-keys"), ("CAPTURES_DIR", "captures"), ("DATA_DIR", "data"),
    ):
        path = tmp_path / leaf
        path.mkdir()
        made[name] = path
    return made


# --- the bug this replaces: unset variables meant no work at all -----------


@pytest.mark.skipif(
    Path("/app").exists(),
    reason="/app exists here, so the fallback paths are not safely assertable",
)
def test_a_bare_docker_run_with_no_directory_variables_still_targets_the_app_paths(tmp_path):
    """The whole point of the fix.

    The old loop was keyed off the variables alone, so `docker run` without -e
    chowned nothing while the backend went on using /app/data -- root-owned,
    and the app died on `unable to open database file` with no mention of
    ownership anywhere.
    """
    proc = _run(tmp_path)

    for path in APP_PATHS:
        assert path in proc.stub_log, f"{path} was never touched: {proc.stub_log!r}"

    # /app/data does not exist here and the mkdir stub only pretends, so the
    # write probe fails -- which is the correct outcome and proves the probe is
    # reached with the fallback path in hand.
    assert proc.returncode == 1
    assert "/app/data" in proc.stderr
    assert "refusing to start" in proc.stderr


# --- the ordinary path ------------------------------------------------------


def test_all_three_directories_are_chowned_and_the_command_is_execed(tmp_path):
    proc = _run(tmp_path, _dirs(tmp_path))

    assert proc.returncode == 0, proc.stderr
    assert "container-started" in proc.stdout
    for leaf in ("ssh-keys", "captures", "data"):
        assert str(tmp_path / leaf) in proc.stub_log


def test_a_missing_directory_is_created_rather_than_skipped(tmp_path):
    """The old `[ -d "$dir" ]` guard skipped a directory that did not exist yet,
    which is the same silent no-op in a different disguise."""
    dirs = _dirs(tmp_path)
    missing = tmp_path / "data"   # replace the real one with an absent path
    for item in sorted(missing.iterdir()):
        item.unlink()
    missing.rmdir()

    # Without the mkdir stub in the way this really has to create it, so run
    # with a PATH that has no stub mkdir.
    stub, log = _stub_bin(tmp_path)
    (stub / "mkdir").unlink()
    env = {"PATH": f"{stub}:/usr/bin:/bin", "HOME": str(tmp_path)}
    env.update({k: str(v) for k, v in dirs.items()})
    proc = subprocess.run(
        ["sh", str(ENTRYPOINT), "echo", "container-started"],
        env=env, capture_output=True, text=True, timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    assert missing.is_dir()
    assert f"created {missing}" in proc.stdout


# --- failures are now reported rather than swallowed ------------------------


def test_a_chown_failure_is_reported_and_still_lets_a_writable_mount_start(tmp_path):
    """`2>/dev/null || true` made a real failure indistinguishable from success.

    It stays non-fatal -- a named volume is usually already correct and a
    read-only key mount can be deliberate -- but the reason is printed, so the
    breadcrumb exists before anything downstream fails.
    """
    dirs = _dirs(tmp_path)
    proc = _run(tmp_path, dirs, chown_fails=True)

    assert proc.returncode == 0, proc.stderr
    assert "container-started" in proc.stdout
    assert "could not chown" in proc.stderr
    assert "stub chown refused" in proc.stderr, "the actual cause must survive"
    assert str(dirs["DATA_DIR"]) in proc.stderr


@pytest.mark.skipif(running_as_root, reason="root can write to a 0500 directory")
def test_an_unwritable_data_directory_refuses_to_start_and_says_why(tmp_path):
    """The case that cost a smoke run: the app's own error is `unable to open
    database file`, which names neither the directory nor ownership."""
    dirs = _dirs(tmp_path)
    dirs["DATA_DIR"].chmod(0o500)
    try:
        proc = _run(tmp_path, dirs)
    finally:
        dirs["DATA_DIR"].chmod(0o700)

    assert proc.returncode == 1
    assert "container-started" not in proc.stdout, "must not exec the app"
    assert str(dirs["DATA_DIR"]) in proc.stderr
    assert "not writable by appuser" in proc.stderr
    assert "1000" in proc.stderr, "the remedy has to name the UID to chown to"


@pytest.mark.skipif(running_as_root, reason="root can write to a 0500 directory")
@pytest.mark.parametrize("unwritable", ["SSH_KEYS_DIR", "CAPTURES_DIR"])
def test_the_other_two_directories_warn_without_refusing_to_start(tmp_path, unwritable):
    """Only the database is fatal. Refusing to boot an otherwise working install
    over a capability it may never use would be the worse failure."""
    dirs = _dirs(tmp_path)
    dirs[unwritable].chmod(0o500)
    try:
        proc = _run(tmp_path, dirs)
    finally:
        dirs[unwritable].chmod(0o700)

    assert proc.returncode == 0, proc.stderr
    assert "container-started" in proc.stdout
    assert str(dirs[unwritable]) in proc.stderr
    assert "not writable by appuser" in proc.stderr
