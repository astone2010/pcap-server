# Dev Skills gate state
Track: release sequence (dev pre-release — branch not merged to main)
Version: 0.1.0-dev.5
Updated: 2026-09-11

🔢 VERSION    ✅ 0.1.0-dev.5 in main.py, docker-compose.yml, CHANGELOG; v0.1.0-dev.4 tagged, CI run 34650566129 green
🔨 BUILD      ✅ register→TOTP→app driven in Chromium; banners, flag help, interface select, sudo checkbox verified; schema migration tested against a pre-dev.5 database
🔒 SECURITY   ✅ 0 Critical, 0 High — sudo flag allowlist hardened (-z/-W/-G/-C/-r/-F/-V/-Z rejected, import-time guard), interface regex, escHtml quote escaping, all args shell-quoted
📄 DOCS       ✅ CHANGELOG dev.5; README sudo/sudoers section, COOKIE_SECURE row, stale SSH-key instructions corrected
📦 RELEASE    ➖ N/A — dev pre-release, no PR to main
🚀 SHIP       ⬜ — awaiting tag push v0.1.0-dev.5 (user runs)
