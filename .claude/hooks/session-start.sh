#!/bin/bash
# Installs what the test suite needs but the base image does not carry.
#
# scripts/check.sh probes for tshark, tcpdump and capinfos and, when they are
# missing, pytest reports the tests that need them as SKIPPED. The suite then
# prints "all passed" while quietly not testing the packet parser at all --
# which is how the dev.7 -n/-nn regression shipped. So the tools are installed
# before the session starts, not left to be noticed later.
set -euo pipefail

# Local machines already have whatever their owner installed, and apt-get on
# someone's laptop is not this hook's business.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

# Idempotent: the container image is cached after this hook completes, so a
# resumed session finds the tools already present and skips straight past.
if ! command -v tshark >/dev/null 2>&1; then
  echo "installing tshark and tcpdump..."

  # wireshark-common's postinst asks, interactively, whether non-root users may
  # capture. There is no terminal here to answer it, so the install hangs
  # forever unless it is told not to ask. The answer is no: this container
  # never captures anything itself -- tshark only ever reads a pcap handed to
  # it on stdin -- so the setuid helper is not wanted either.
  export DEBIAN_FRONTEND=noninteractive
  echo "wireshark-common wireshark-common/install-setuid boolean false" \
    | $SUDO debconf-set-selections

  # Allowed to fail. A third-party PPA the image happens to carry can be
  # unreachable -- behind this environment's proxy they return 403 -- and
  # apt-get update then exits non-zero over repositories these two packages do
  # not come from. Under set -e that would abort the hook and leave the session
  # without tshark for a reason that has nothing to do with tshark. The install
  # below is the step that must actually succeed.
  $SUDO apt-get update -qq || echo "apt-get update reported errors; continuing to the install"
  $SUDO apt-get install -y -q --no-install-recommends tshark tcpdump
fi

# The venv that scripts/check.sh expects. Created here so the cached container
# has it ready; check.sh would otherwise build it on the first test run, and
# a venv rather than system python because some distros ship a package-managed
# cryptography with no RECORD file that pip cannot replace in place.
if [ ! -d "$CLAUDE_PROJECT_DIR/.venv" ]; then
  python3 -m venv "$CLAUDE_PROJECT_DIR/.venv"
fi
"$CLAUDE_PROJECT_DIR/.venv/bin/python" -m pip install -q --upgrade pip
"$CLAUDE_PROJECT_DIR/.venv/bin/python" -m pip install -q \
  -r "$CLAUDE_PROJECT_DIR/backend/requirements-dev.txt"

echo "ready: $(tshark --version | head -1)"
for tool in tshark tcpdump capinfos; do
  printf '  %s: %s\n' "$tool" "$(command -v "$tool" || echo MISSING)"
done
