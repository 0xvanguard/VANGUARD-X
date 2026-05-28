# =============================================================================
# VANGUARD-X — Isolated Subfinder tool container
# Builds Subfinder from source so we don't pull a third-party runtime image.
# =============================================================================

FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git \
    && go install -ldflags="-s -w" \
        github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# -----------------------------------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tini \
    && addgroup -S -g 10004 vanguard \
    && adduser  -S -u 10004 -G vanguard -h /home/vanguard -s /sbin/nologin vanguard \
    && mkdir -p /subdomains && chown vanguard:vanguard /subdomains

COPY --from=builder /go/bin/subfinder /usr/local/bin/subfinder

USER vanguard
WORKDIR /subdomains

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sleep", "infinity"]
