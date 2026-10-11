# cardinal/proxy — the choke point, now a REAL web application firewall.
#
# Engine: Coraza (the OWASP CRS engine the reference names as ModSecurity's
# successor) running inside Caddy via the coraza-caddy module. The OWASP Core
# Rule Set and coraza's recommended base config are baked into the image and
# loaded by real path from the Caddyfile (see proxy/etc/caddy/Caddyfile).
#
# The proxy keeps the exact same role it had as plain nginx: it bridges
# edge-net and app-net and reverse-proxies to the webapp. The only change is
# that every request is now inspected by the WAF before it is forwarded.

# --- Stage 1: build a Caddy binary with the Coraza WAF module compiled in. ---
FROM caddy:2-builder AS builder
# xcaddy fetches the module and links a custom caddy binary.
RUN xcaddy build --with github.com/corazawaf/coraza-caddy/v2

# --- Stage 2: runtime image. ---
FROM caddy:2-alpine

# CRS release and coraza base-config version, pinned for reproducibility.
ARG CRS_VERSION=4.30.0
ARG CORAZA_REF=v3.3.3

# Kathara drives the container through its own .startup script (assigns the
# eth0/eth1 addresses), so we need `ip` (iproute2) and bash. curl is only used
# here at build time to fetch the rule set.
RUN apk add --no-cache iproute2 bash curl ca-certificates \
 && mkdir -p /etc/coraza/crs \
 # coraza's recommended base config (SecDefaultAction, body access, phases...)
 && curl -fsSL "https://raw.githubusercontent.com/corazawaf/coraza/${CORAZA_REF}/coraza.conf-recommended" \
      -o /etc/coraza/coraza.conf \
 # OWASP Core Rule Set: crs-setup + the numbered rule files (+ their .data files)
 && curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
      -o /tmp/crs.tgz \
 && tar -xzf /tmp/crs.tgz -C /tmp \
 && cp "/tmp/coreruleset-${CRS_VERSION}/crs-setup.conf.example" /etc/coraza/crs/crs-setup.conf \
 && cp -r "/tmp/coreruleset-${CRS_VERSION}/rules" /etc/coraza/crs/rules \
 && rm -rf /tmp/crs.tgz "/tmp/coreruleset-${CRS_VERSION}" \
 && apk del curl

# Replace the stock caddy with our WAF-enabled build.
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Kathara runs each machine's .startup script itself. Neutralize the base
# image's entrypoint/command so it does NOT launch a competing caddy as PID 1;
# PID 1 is just a keepalive and proxy.startup owns the real launch.
ENTRYPOINT []
CMD ["tail", "-f", "/dev/null"]
