"""Where to find a chromium playwright can drive.

`launch_kwargs` is what the browser suites use, and it is the authority: it
asks playwright where its own browser is and falls back to one the environment
provides. `describe` is the line scripts/check.sh prints before pytest runs,
so a run that is about to skip the UI suites says so at the top rather than in
a summary nobody reads.

describe() deliberately does not start playwright's driver to answer. Starting
and immediately stopping it prints an asyncio teardown traceback that looks
exactly like a failure, at the top of a test run, every time -- so the report
states what it can see for certain and leaves the precise answer to the skip
reason on the tests themselves, which have the driver running already.

Run directly to print that report:

    .venv/bin/python tests/browser/browser_binary.py
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

# A browser the environment provides, used when the revision playwright would
# download is not the revision that is installed. Dev containers commonly ship
# one at a fixed path and block the download; CI installs the matching revision
# instead and never reaches this.
PREINSTALLED = Path(os.environ.get("PCAP_TEST_CHROMIUM", "/opt/pw-browsers/chromium"))


def launch_kwargs(playwright) -> dict | None:
    """Arguments for chromium.launch(), or None when there is no browser.

    An empty dict means playwright's own browser is present and needs no help.
    """
    if Path(playwright.chromium.executable_path).exists():
        return {}
    if PREINSTALLED.exists():
        return {"executable_path": str(PREINSTALLED)}
    return None


def describe() -> list[str]:
    if importlib.util.find_spec("playwright") is None:
        return [
            "  playwright: not installed -- tests/browser will report as SKIPPED",
            "              pip install -r backend/requirements-dev.txt",
        ]
    lines = ["  playwright: installed"]
    if PREINSTALLED.exists():
        lines.append(f"  chromium:   {PREINSTALLED}")
    else:
        lines.append("  chromium:   playwright's own, if it has been installed --")
        lines.append(f"              {sys.executable} -m playwright install chromium")
    lines.append("  A missing browser reports as SKIPPED, never silently omitted.")
    return lines


if __name__ == "__main__":
    print("\n".join(describe()))
