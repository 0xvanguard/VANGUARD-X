# =============================================================================
# VANGUARD-X — Isolated theHarvester tool container
# theHarvester is OSINT-only (passive); safe to run without scope coupling,
# but the agent still enforces scope before invoking it.
# =============================================================================

FROM python:3.12-alpine

RUN apk add --no-cache tini git \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir theHarvester \
    && apk del git \
    && addgroup -S -g 10003 vanguard \
    && adduser  -S -u 10003 -G vanguard -h /home/vanguard -s /sbin/nologin vanguard \
    && mkdir -p /harvest && chown vanguard:vanguard /harvest

USER vanguard
WORKDIR /harvest

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sleep", "infinity"]
