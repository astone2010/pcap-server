#!/usr/bin/env bash
# Single entrypoint for running the test suite -- locally and in CI, so the
# two can never drift into passing and failing independently of each other.
# .github/workflows/check.yml calls this script rather than reimplementing
# the checks inline.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "== Tool availability =="
for tool in tshark tcpdump capinfos docker; do
    if path=$(command -v "$tool" 2>/dev/null); then
        echo "  $tool: $path"
    else
        echo "  $tool: not found -- tests needing it will report as SKIPPED, not silently omitted"
    fi
done
echo

# --- which interpreter builds the venv ------------------------------------
#
# The pins decide this, not whatever `python3` happens to be. The ceiling was
# set when pydantic-core (via pydantic==2.10.3) shipped wheels only up to cp313;
# past that pip fell back to building it from source, which needed PyO3 <= 3.13
# and died with
#
#   error: the configured Python interpreter version (3.14) is newer than
#   PyO3's maximum supported version (3.13)
#
# buried in a few hundred lines of cargo output that never mentions Python
# versions at all. Fedora 44 ships 3.14 as `python3`, so this was not
# hypothetical -- the script was simply unrunnable there.
#
# pydantic 2.13.5 (dev.39) pulls a pydantic-core that does ship cp314 wheels,
# so that particular failure is gone. The ceiling stays at 3.13 until the suite
# has actually been run on 3.14 -- every other compiled pin has to install and
# pass there too, and nothing has shown that yet.
#
# 3.12 is what the Dockerfile and .github/workflows/check.yml use, so it is the
# version this project is actually exercised on, and it is tried first. The
# floor below is the oldest the code's syntax allows rather than a version
# anyone tests; the ceiling is the one carrying real evidence.
PYTHON_MIN="3.11"
PYTHON_MAX="3.13"

# Runs in the CANDIDATE interpreter, so it reports on that one rather than on
# whichever python happens to be running this script.
python_in_range() {
    "$1" -c '
import sys
lo = tuple(int(p) for p in sys.argv[1].split("."))
hi = tuple(int(p) for p in sys.argv[2].split("."))
sys.exit(0 if lo <= sys.version_info[:2] <= hi else 1)
' "$PYTHON_MIN" "$PYTHON_MAX" 2>/dev/null
}

python_version() {
    "$1" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || echo "unknown"
}

# PYTHON= wins outright: if someone names an interpreter, using a different one
# silently is worse than failing.
if [ -n "${PYTHON:-}" ]; then
    if ! command -v "$PYTHON" >/dev/null 2>&1; then
        echo "PYTHON is set to '$PYTHON', which is not executable." >&2
        exit 1
    fi
    if ! python_in_range "$PYTHON"; then
        echo "PYTHON is set to '$PYTHON' ($(python_version "$PYTHON")), outside the supported ${PYTHON_MIN}-${PYTHON_MAX}." >&2
        echo "Unset PYTHON to search for a supported interpreter, or point it at one." >&2
        exit 1
    fi
    INTERPRETER="$PYTHON"
else
    INTERPRETER=""
    # 3.12 first -- the version CI and the image use. Bare `python3` last: on a
    # current distro it is the candidate most likely to be out of range, and a
    # named version found first gives a repeatable answer across machines.
    for candidate in python3.12 python3.13 python3.11 python3; do
        if command -v "$candidate" >/dev/null 2>&1 && python_in_range "$candidate"; then
            INTERPRETER="$candidate"
            break
        fi
    done
    if [ -z "$INTERPRETER" ]; then
        echo "No supported Python found. This project needs ${PYTHON_MIN}-${PYTHON_MAX}, the range its test suite has been run on." >&2
        echo "Found: python3 = $(python_version python3)" >&2
        echo "Install one (e.g. 'sudo dnf install python3.12' or 'sudo apt install python3.12-venv'), or set PYTHON=/path/to/python3.12" >&2
        exit 1
    fi
fi

# A venv, not the system python: some distros ship a package-managed
# `cryptography` with no RECORD file, which pip cannot upgrade or replace in
# place ("Cannot uninstall cryptography ..., RECORD file not found") -- a
# venv sidesteps that entirely instead of fighting the system package manager.
#
# An EXISTING venv is checked, not trusted. A venv built by an out-of-range
# interpreter is reused forever otherwise, so one bad run poisons every later
# one with the identical unreadable failure -- which is exactly what happened
# before this check existed.
VENV_PYTHON=.venv/bin/python
if [ -d .venv ] && ! python_in_range "$VENV_PYTHON"; then
    echo "Rebuilding .venv: it was built by $(python_version "$VENV_PYTHON"), outside ${PYTHON_MIN}-${PYTHON_MAX}."
    rm -rf .venv
fi
if [ ! -d .venv ]; then
    echo "Creating .venv with $INTERPRETER ($(python_version "$INTERPRETER"))"
    "$INTERPRETER" -m venv .venv
fi
PYTHON="$VENV_PYTHON"

"$PYTHON" -m pip install -q --upgrade pip
"$PYTHON" -m pip install -q -r backend/requirements-dev.txt

# After the install, because it needs the playwright package to answer at all.
# Same reason the tool list above exists: a browser suite that quietly skips is
# a UI regression that ships.
echo "== Browser for the UI suites =="
"$PYTHON" tests/browser/browser_binary.py
echo

# -r s: always show which tests were skipped and why. A suite that prints
# "all passed" while quietly dropping the tshark-dependent tests is how a
# real regression (see the dev.7 -n/-nn mixup) ships unnoticed.
exec "$PYTHON" -m pytest -r s "$@"
