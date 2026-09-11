#!/bin/sh
set -e

# Ensure data directories are writable by appuser (UID 1000).
# When bind-mounted from the host, ownership may not match.
for dir in "$SSH_KEYS_DIR" "$CAPTURES_DIR" "$DATA_DIR"; do
    if [ -n "$dir" ] && [ -d "$dir" ]; then
        chown -R appuser:appuser "$dir" 2>/dev/null || true
    fi
done

exec gosu appuser "$@"
