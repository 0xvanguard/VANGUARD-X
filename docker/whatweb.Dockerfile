# =============================================================================
# VANGUARD-X — Isolated WhatWeb tool container
# Ruby gem on Alpine; runs as non-root, exec'd into by the core orchestrator.
# =============================================================================

FROM ruby:3.3-alpine

RUN apk add --no-cache tini build-base \
    && gem install --no-document whatweb \
    && apk del build-base \
    && addgroup -S -g 10005 vanguard \
    && adduser  -S -u 10005 -G vanguard -h /home/vanguard -s /sbin/nologin vanguard \
    && mkdir -p /fingerprints && chown vanguard:vanguard /fingerprints

USER vanguard
WORKDIR /fingerprints

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sleep", "infinity"]
