# Dev Skills gate state
Track: release sequence (dev pre-release — branch not merged to main)
Version: 0.1.0-dev.7
Updated: 2026-09-11

🔢 VERSION    ✅ 0.1.0-dev.7 in main.py, docker-compose.yml, CHANGELOG; v0.1.0-dev.6 confirmed tagged on remote (git ls-remote)
🔨 BUILD      ✅ app run under uvicorn and driven in headless Chromium: register -> add server -> process restart -> server still listed; explainer verified in both themes and at 390px; 121 checks green across 6 suites. Caveat: no docker daemon in this container, so the image itself was not rebuilt (Dockerfile unchanged by this diff)
🔒 SECURITY   ✅ 0 Critical, 0 High. Fixes a High (cross-user server access). Capture flag allowlist removed entirely — extra_flags is gone, and the -z/-W/-G/-C/-r/-F/-V/-Z refusal now asserts against the fully-built command incl. the sudo prefix. New free-text server name proven inert against 4 XSS payloads; all new SQL parameterized
📄 DOCS       ✅ CHANGELOG dev.7 entry incl. the dev.6 changelog correction; README gains a "What changes a capture" section, BPF cheatsheet, persistent-servers and capture-provenance features
📦 RELEASE    ➖ N/A — dev pre-release, no PR to main
🚀 SHIP       ⬜ — awaiting commit approval, then tag push v0.1.0-dev.7 (user runs)

Env: remote container (Claude executes git after approval; tag pushes handed to user)
Working branch: claude/dev-skills-loading-nzkzqo, based on origin/claude/admiring-wright-k20ptf @ 5880a8b
