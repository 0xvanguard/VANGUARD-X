# =============================================================================
# VANGUARD-X — Isolated Nmap tool container
# Stays alive (sleep infinity); the core service calls it via `docker exec`.
# =============================================================================

FROM alpine:3.20

RUN apk add --no-cache nmap nmap-scripts tini \
    && addgroup -S -g 10002 vanguard \
    && adduser  -S -u 10002 -G vanguard -h /home/vanguard -s /sbin/nologin vanguard \
    && mkdir -p /scans && chown vanguard:vanguard /scans

USER vanguard
WORKDIR /scans

ENTRYPOINT ["/sbin/tini", "--"]
# Keep the container alive so the orchestrator can `docker exec` into it.
CMD ["sleep", "infinity"]
