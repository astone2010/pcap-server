"""Tests for release.yml's tag/version check.

v1.0.0 was first pushed onto the dev.40 commit, before the release PR merged.
That commit was on the default branch and its Check was green, so the gate let
it through, and :1.0.0 and :latest were published holding code that reported
0.1.0-dev.40. The gate now compares the tag with APP_VERSION in the tagged
commit.

The step's script is lifted out of release.yml as text and run for real, with a
stub `gh` on PATH that serves a chosen backend/main.py. Nothing here parses
YAML: there is no YAML library among the test dependencies, and reading the
script straight from the workflow means the test cannot drift from what runs.
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_YML = REPO_ROOT / ".github" / "workflows" / "release.yml"
STEP_NAME = "Require the tag to match APP_VERSION in the tagged commit"


def _step_script() -> str:
    """The `run: |` body of the version-check step, dedented."""
    lines = RELEASE_YML.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == f"- name: {STEP_NAME}")
    run_at = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    run_indent = len(lines[run_at]) - len(lines[run_at].lstrip())

    body = []
    for line in lines[run_at + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= run_indent:
            break
        body.append(line)
    return textwrap.dedent("\n".join(body))


def _run(tmp_path, *, tag: str, main_py: str | None):
    stub = tmp_path / "bin"
    stub.mkdir()
    served = tmp_path / "main.py"
    if main_py is None:
        gh = '#!/bin/sh\necho "gh: Not Found (HTTP 404)" >&2\nexit 1\n'
    else:
        served.write_text(main_py, encoding="utf-8")
        gh = f'#!/bin/sh\necho "$*" > "{tmp_path}/gh.args"\ncat "{served}"\n'
    (stub / "gh").write_text(gh)
    (stub / "gh").chmod(0o755)

    env = {
        **os.environ,
        "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}",
        "GH_TOKEN": "unused",
        "REPO": "owner/repo",
        "SHA": "abc123",
        "TAG": tag,
    }
    return subprocess.run(
        ["bash", "-c", _step_script()], env=env, capture_output=True, text=True, timeout=30
    )


def _main_py(version: str) -> str:
    return f'import os\n\nAPP_VERSION = "{version}"\nREPO_URL = "https://example"\n'


def test_step_exists_in_the_gate_job_before_anything_is_built():
    text = RELEASE_YML.read_text(encoding="utf-8")
    step = text.index(f"- name: {STEP_NAME}")
    assert text.index("  gate:") < step < text.index("  release:")


def test_matching_tag_passes(tmp_path):
    result = _run(tmp_path, tag="v1.0.0", main_py=_main_py("1.0.0"))
    assert result.returncode == 0, result.stderr
    assert "v1.0.0 matches APP_VERSION 1.0.0" in result.stdout
    # It reads the file at the tagged commit, not at the branch head.
    assert "contents/backend/main.py?ref=abc123" in (tmp_path / "gh.args").read_text()


def test_tag_on_an_older_commit_is_refused(tmp_path):
    """The dev.40 case: a stable tag on a commit that is still the dev build."""
    result = _run(tmp_path, tag="v1.0.0", main_py=_main_py("0.1.0-dev.40"))
    assert result.returncode == 1
    assert "APP_VERSION is 0.1.0-dev.40" in result.stdout


@pytest.mark.parametrize("tag", ["1.0.0", "v1.0", "v1.0.0-dev.1", "v1.0.00"])
def test_near_misses_are_refused(tmp_path, tag):
    result = _run(tmp_path, tag=tag, main_py=_main_py("1.0.0"))
    assert result.returncode == 1


def test_missing_app_version_is_refused(tmp_path):
    result = _run(tmp_path, tag="v1.0.0", main_py="REPO_URL = 'x'\n")
    assert result.returncode == 1
    assert "No APP_VERSION line" in result.stdout


def test_api_failure_is_refused_not_passed(tmp_path):
    result = _run(tmp_path, tag="v1.0.0", main_py=None)
    assert result.returncode != 0


def test_the_real_main_py_matches_the_shape_the_step_reads():
    """If APP_VERSION's line changes shape, the gate would refuse every release."""
    main_py = (REPO_ROOT / "backend" / "main.py").read_text(encoding="utf-8")
    assert re.search(r'^APP_VERSION = "[^"]+"$', main_py, re.MULTILINE)
