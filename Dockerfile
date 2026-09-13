# lego, the ACME client behind built-in HTTPS (backend/tls). One static binary,
# fetched by pinned version and checksum in a stage of its own so nothing but
# the binary reaches the final image. Moving LEGO_VERSION means regenerating
# backend/tls/lego_providers.json (scripts/gen_lego_providers.py) as well.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS lego
ARG LEGO_VERSION=5.4.1
ARG LEGO_SHA256_AMD64=ebb33f1bead5a7c99dd46f1c5734b44cf1eab5b5c12faf397cd14d50a5916419
ARG LEGO_SHA256_ARM64=8494c06bde449ac4d65c726b7ea50d67ac61f422e698c9b78b47778445b098f2
ARG TARGETARCH
COPY backend/tls/fetch_lego.py /tmp/fetch_lego.py
RUN case "${TARGETARCH:-amd64}" in \
        amd64) sum="$LEGO_SHA256_AMD64" ;; \
        arm64) sum="$LEGO_SHA256_ARM64" ;; \
        *) echo "no lego checksum pinned for $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && python /tmp/fetch_lego.py "$LEGO_VERSION" "$sum" "${TARGETARCH:-amd64}" /usr/local/bin/lego \
    && chmod 0755 /usr/local/bin/lego \
    && /usr/local/bin/lego --version

# Pinned by digest, not just by tag: python:3.12-slim is re-pushed with every
# Debian and CPython patch, so the tag alone builds a different image each week.
# The digest is the multi-arch index (amd64 and arm64). .github/dependabot.yml
# proposes the new digest when the tag moves, so the pin does not go stale.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    tcpdump \
    openssh-client \
    gosu \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false -u 1000 -m appuser

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY --from=lego /usr/local/bin/lego /usr/local/bin/lego

COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh \
    && mkdir -p /app/ssh-keys /app/captures /app/data \
    && chown -R appuser:appuser /app/ssh-keys /app/captures /app/data

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
# backend.serve rather than uvicorn's CLI: the app has to open its vault before
# uvicorn builds a TLS context, because the certificate's key is sealed.
CMD ["python", "-m", "backend.serve", "--host", "0.0.0.0", "--port", "8080"]
