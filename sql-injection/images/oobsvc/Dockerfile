# cardinal/oobsvc — attacker-controlled out-of-band (OOB) listener.
#
# Phase-1 SQLi lab, OOB scenario: this is the server the compromised database
# is tricked into contacting. It runs a tiny DNS collector (pure stdlib, no
# pip) that LOGS every queried hostname — the channel the DB-as-courier leaks
# through. It answers every A query with 127.0.0.1 so the
# lookup "succeeds" and the payload does not stall.
#
# Lives on app-net so the single-homed db can reach it; that reachability is
# exactly what the egress-control defense later cuts.
FROM python:3.11-slim

# iproute2 so oobsvc.startup can assign its app-net address, mirroring the
# other lab nodes. No pip packages: the listener is pure Python stdlib.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Kathara runs each machine's .startup script itself. Neutralize the base
# image's entrypoint/command so it does NOT launch a competing service as PID 1.
# PID 1 is just a keepalive; the .startup script owns all service launches.
ENTRYPOINT []
CMD ["tail", "-f", "/dev/null"]
