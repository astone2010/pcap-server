#!/bin/sh
set -e

# The same three paths backend/main.py falls back to when the variables are
# unset (main.py:102-104), repeated here on purpose.
#
# Treating unset as "nothing to do" was the bug this replaces. docker-compose.yml
# always sets all three, so every run this image had ever seen defined them --
# but a hand-rolled `docker run` that omits them left this loop chowning nothing
# while the backend went on using /app/data anyway. That directory is root-owned
# in the image, so the first thing the app did was fail to open its database,
# with nothing anywhere pointing at ownership as the cause.
SSH_KEYS_DIR="${SSH_KEYS_DIR:-/app/ssh-keys}"
CAPTURES_DIR="${CAPTURES_DIR:-/app/captures}"
DATA_DIR="${DATA_DIR:-/app/data}"

# Ensure the data directories are writable by appuser (UID 1000). When
# bind-mounted from the host, ownership may not match.
#
# A failure here stays non-fatal -- a named volume is usually already correct,
# and a read-only mount can be deliberate -- but it is no longer silent. The
# old `2>/dev/null || true` made a chown that genuinely failed indistinguishable
# from one that succeeded, which is the second half of the same bug: the
# breadcrumb only helps if it is printed.
for dir in "$SSH_KEYS_DIR" "$CAPTURES_DIR" "$DATA_DIR"; do
    if [ ! -d "$dir" ]; then
        if err=$(mkdir -p "$dir" 2>&1); then
            echo "entrypoint: created $dir"
        else
            echo "entrypoint: could not create $dir: ${err:-unknown error}" >&2
            continue
        fi
    fi
    if ! err=$(chown -R appuser:appuser "$dir" 2>&1); then
        echo "entrypoint: could not chown $dir to appuser: ${err:-unknown error}" >&2
        echo "entrypoint: continuing -- this only matters if the write check below also fails" >&2
    fi
done

# Prove appuser can actually write, rather than inferring it from a chown that
# may not have run. This is the check that turns "unable to open database file"
# into a sentence naming the directory and the reason.
probe_dir() {
    _dir="$1"
    _probe="$_dir/.pcap-server-write-probe"
    if err=$(gosu appuser sh -c 'printf ok > "$1" && rm -f "$1"' _ "$_probe" 2>&1); then
        return 0
    fi
    echo "entrypoint: $_dir is not writable by appuser: ${err:-unknown error}" >&2
    return 1
}

# Fatal for the data directory alone. The database lives there, so the app
# cannot do anything at all without it, and refusing to start with a stated
# cause beats starting and dying on the first query.
if ! probe_dir "$DATA_DIR"; then
    echo "entrypoint: refusing to start. The database lives in $DATA_DIR, so a" >&2
    echo "entrypoint: bind mount there must be writable by UID 1000. Either chown it" >&2
    echo "entrypoint: on the host (chown -R 1000:1000 <path>) or use a named volume." >&2
    exit 1
fi

# The other two are warnings, not hard stops: a deployment that provisions SSH
# keys through a read-only mount is a reasonable thing to do, and a working
# install should not be refused over a capability it may never use.
probe_dir "$SSH_KEYS_DIR" || \
    echo "entrypoint: uploading or generating SSH keys will fail until this is fixed." >&2
probe_dir "$CAPTURES_DIR" || \
    echo "entrypoint: captures will start on the remote host and then fail to download." >&2

exec gosu appuser "$@"
