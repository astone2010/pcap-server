# Dev Skills gate state
Track: release sequence (dev pre-release — branch not merged to main)
Version: 0.1.0-dev.1
Updated: 2026-09-11

🔢 VERSION    ✅ bumped to 0.1.0-dev.1 (semver pre-release, "dev" in name since not on main), no prior tags
🔨 BUILD      ✅ Docker build verified via CI, Python syntax OK, no local Docker
🔒 SECURITY   ✅ 0 Critical, 0 High — full scan of all changed files
📄 DOCS       ✅ README.md and CHANGELOG.md updated for 0.1.0-dev.1
📦 RELEASE    ➖ N/A — dev pre-release only, no PR to main this cycle. Tag is
              pushed straight from claude/admiring-wright-k20ptf. A PR to main
              will be opened later when this is promoted to a stable release.
🚀 SHIP       ⬜ — next: push tag v0.1.0-dev.1 (user-run, Section 5.7). Release
              workflow now skips the `:latest` tag and marks the GitHub
              release as a pre-release for any version containing "-".
