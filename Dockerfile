# =============================================================================
# VANGUARD-X — Core service image
# Hardened: non-root user, no build artifacts, minimal layers.
# =============================================================================

FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# System build deps only for wheels (none needed yet, but kept for asyncpg etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --upgrade pip \
    && pip wheel --wheel-dir /wheels .

# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    VANGUARDX_DATA_DIR=/data

# docker-cli for the docker_exec runner (no daemon, just the client).
# tini for proper signal forwarding.
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io tini \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create unprivileged user (uid 10001 keeps us out of common host uid ranges)
RUN groupadd --system --gid 10001 vanguard \
    && useradd  --system --uid 10001 --gid vanguard \
                --home-dir /home/vanguard --create-home \
                --shell /usr/sbin/nologin vanguard

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels vanguard-x \
    && rm -rf /wheels

# Persistent volume for SQLite, evidence, reports
RUN mkdir -p /data && chown -R vanguard:vanguard /data /app
VOLUME ["/data"]

USER vanguard

ENTRYPOINT ["/usr/bin/tini", "--", "python", "-m", "vanguard_x"]
CMD ["--help"]
