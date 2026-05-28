# =============================================================================
# VANGUARD-X -- Isolated Nuclei tool container
# Stays alive (sleep infinity); the core service calls it via `docker exec`.
# =============================================================================

FROM alpine:3.20

# Install nuclei from ProjectDiscovery releases
RUN apk add --no-cache curl tini unzip \
    && NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | head -1 | cut -d'"' -f4 | sed 's/^v//') \
    && curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm -f /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    && apk del curl unzip \
    && addgroup -S -g 10006 vanguard \
    && adduser -S -u 10006 -G vanguard -h /home/vanguard -s /sbin/nologin vanguard \
    && mkdir -p /scans && chown vanguard:vanguard /scans

USER vanguard
WORKDIR /scans

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sleep", "infinity"]
