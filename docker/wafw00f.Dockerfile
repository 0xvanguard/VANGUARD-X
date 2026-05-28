# =============================================================================
# VANGUARD-X — Isolated wafw00f tool container
# =============================================================================

FROM python:3.12-alpine

RUN apk add --no-cache tini \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir wafw00f \
    && addgroup -S -g 10006 vanguard \
    && adduser  -S -u 10006 -G vanguard -h /home/vanguard -s /sbin/nologin vanguard \
    && mkdir -p /waf && chown vanguard:vanguard /waf

USER vanguard
WORKDIR /waf

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sleep", "infinity"]
