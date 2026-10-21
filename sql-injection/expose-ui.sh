#!/bin/bash
# Publish the lab's web UIs to the host:
#   - the staff portal, ENFORCING WAF (proxy :80)   -> http://localhost:8080
#   - the staff portal, DETECTION path (proxy :8080) -> http://localhost:8081
#   - the Locust UI                                  -> http://localhost:8089
#
# Two portal doors on purpose: :8080 is the enforcing WAF (an injection gets a
# 403 block page); :8081 is the detection path (the same injection is logged but
# forwarded, so the app runs it and you can see the exact query). Use :8081 to
# watch an attack, :8080 to watch the defense.
#
# Why this exists: Kathara collision domains are pure L2 segments (the 172.30/31
# addresses are set by the .startup scripts, not Docker IPAM), and on Docker
# Desktop Kathara's own `machine[port]` publish does not realise. So we run tiny
# published `socat` sidecars on the Docker default bridge that forward host
# ports to each container's bridge IP. The proxy and locust are on the default
# bridge via `proxy[bridged]` / `locust[bridged]` in lab.conf.
#
# Usage:  ./expose-ui.sh                   # enforce 8080, Locust 8089, detect 8081
#         ./expose-ui.sh 9000 9001 9002    # enforce 9000, Locust 9001, detect 9002
#         docker rm -f cardinal-webapp-ui cardinal-webapp-detect cardinal-locust-ui   # to stop
set -euo pipefail

PORTAL_PORT="${1:-8080}"
LOCUST_PORT="${2:-8089}"
DETECT_PORT="${3:-8081}"   # portal through the proxy's detection-only port

bridge_ip() {  # bridge_ip <container-name-substring>
    local c
    c=$(docker ps --format '{{.Names}}' | grep "_$1_" | head -1 || true)
    [ -z "$c" ] && { echo "" ; return; }
    docker inspect "$c" --format '{{.NetworkSettings.Networks.bridge.IPAddress}}'
}

expose() {  # expose <name> <host_port> <target_ip> <target_port>
    local name="$1" hport="$2" tip="$3" tport="$4"
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" --network bridge -p "${hport}:${tport}" \
        alpine/socat "TCP-LISTEN:${tport},fork,reuseaddr" "TCP:${tip}:${tport}" >/dev/null
}

PROXY_IP=$(bridge_ip proxy)
LOCUST_IP=$(bridge_ip locust)

if [ -z "$PROXY_IP" ]; then
    echo "warn: proxy has no default-bridge IP — is proxy[bridged]=\"true\" set and the lab started?" >&2
else
    expose cardinal-webapp-ui "$PORTAL_PORT" "$PROXY_IP" 80
    echo "Portal (enforce) -> http://localhost:${PORTAL_PORT}   (proxy ${PROXY_IP}:80  — injections get a 403 block page)"
    expose cardinal-webapp-detect "$DETECT_PORT" "$PROXY_IP" 8080
    echo "Portal (detect)  -> http://localhost:${DETECT_PORT}   (proxy ${PROXY_IP}:8080 — injections forwarded; shows the query)"
fi

if [ -z "$LOCUST_IP" ]; then
    echo "warn: locust has no default-bridge IP — is locust[bridged]=\"true\" set and the lab started?" >&2
else
    expose cardinal-locust-ui "$LOCUST_PORT" "$LOCUST_IP" 8089
    echo "Locust UI -> http://localhost:${LOCUST_PORT}   (via locust ${LOCUST_IP}:8089)"
fi

echo "Stop with: docker rm -f cardinal-webapp-ui cardinal-webapp-detect cardinal-locust-ui"
