# Dev Skills gate state
Track: release sequence (dev pre-release — branch not merged to main)
Version: 0.1.0-dev.6
Updated: 2026-09-11

🔢 VERSION    ✅ 0.1.0-dev.6 in main.py, docker-compose.yml, CHANGELOG; v0.1.0-dev.5 tagged at d1692aa, CI run 34651839926 green
🔨 BUILD      ✅ register→TOTP→app in Chromium; both themes + persisted choice; 12/12 packet colour rules; 9/9 view-flag→tshark mappings; flag exclusivity + MAC columns; capture persistence across a simulated restart; no horizontal overflow at 390px
🔒 SECURITY   ✅ 0 Critical, 0 High — sudo flag allowlist hardened (-z/-W/-G/-C/-r/-F/-V/-Z rejected, import-time guard), view flags allowlisted server-side, interface regex, escHtml quote escaping, all args shell-quoted
📄 DOCS       ✅ CHANGELOG split so dev.5 records only what shipped at d1692aa and dev.6 carries the rest; README themes/view flags/DATA_DIR persistence
📦 RELEASE    ➖ N/A — dev pre-release, no PR to main
🚀 SHIP       ⬜ — awaiting tag push v0.1.0-dev.6 (user runs)
