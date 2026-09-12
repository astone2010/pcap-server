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

# A venv, not the system python: some distros ship a package-managed
# `cryptography` with no RECORD file, which pip cannot upgrade or replace in
# place ("Cannot uninstall cryptography ..., RECORD file not found") -- a
# venv sidesteps that entirely instead of fighting the system package manager.
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
PYTHON=.venv/bin/python

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
