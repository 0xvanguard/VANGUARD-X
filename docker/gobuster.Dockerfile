# =============================================================================
# VANGUARD-X -- Isolated Gobuster tool container
# Stays alive (sleep infinity); the core service calls it via `docker exec`.
# =============================================================================

FROM alpine:3.20

RUN apk add --no-cache curl tini \
    && GOBUSTER_VERSION=$(curl -s https://api.github.com/repos/OJ/gobuster/releases/latest | grep '"tag_name"' | head -1 | cut -d'"' -f4 | sed 's/^v//') \
    && curl -sSL "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_${GOBUSTER_VERSION}_linux_amd64.tar.gz" -o /tmp/gobuster.tar.gz \
    && tar xzf /tmp/gobuster.tar.gz -C /usr/local/bin/ gobuster \
    && rm -f /tmp/gobuster.tar.gz \
    && chmod +x /usr/local/bin/gobuster \
    && apk del curl \
    && addgroup -S -g 10007 vanguard \
    && adduser -S -u 10007 -G vanguard -h /home/vanguard -s /sbin/nologin vanguard \
    && mkdir -p /wordlists /scans \
    && chown vanguard:vanguard /scans

COPY wordlists/common.txt /wordlists/common.txt

USER vanguard
WORKDIR /scans

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sleep", "infinity"]
