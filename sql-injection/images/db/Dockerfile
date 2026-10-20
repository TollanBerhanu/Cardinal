# cardinal/db — MariaDB.
# Kathara bypasses the official image entrypoint, so db.startup starts
# `mariadbd` and imports /seed.sql by hand (see db.startup). This image
# guarantees the server + client binaries and `ip` are present, and adds the
# two pieces the OOB needs:
#   * the oob_dns loadable UDF (.so) in the plugin dir  — OOB (attack)
#   * nftables                                           — OOB (defense)

# --- Builder: compile the self-contained OOB UDF -----------------------------
# Built on the same Debian release family as mariadb:11 (bookworm) so the .so's
# glibc matches the server image. The UDF declares the ABI structs itself, so a
# plain gcc with libc headers is all that's needed — no server/client dev pkgs.
FROM debian:bookworm-slim AS udfbuild
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY oob_dns.c /tmp/oob_dns.c
RUN gcc -shared -fPIC -O2 -Wall -o /tmp/oob_dns.so /tmp/oob_dns.c

# --- Final image -------------------------------------------------------------
FROM mariadb:11

# iproute2 for address assignment in db.startup; nftables for the egress-control
# OOB defense
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 nftables \
    && rm -rf /var/lib/apt/lists/*

# Place the compiled OOB UDF in MariaDB's plugin_dir (/usr/lib/mysql/plugin/).
# db.startup registers it with CREATE FUNCTION after seeding (see db/oob-setup.sql).
COPY --from=udfbuild /tmp/oob_dns.so /usr/lib/mysql/plugin/oob_dns.so

# Kathara runs each machine's .startup script itself. Neutralize the base
# image's entrypoint/command so it does NOT launch a competing service as PID 1
# (stock nginx grabbing :80, the mariadb entrypoint aborting, a python REPL...).
# PID 1 is just a keepalive; the .startup script owns all service launches.
ENTRYPOINT []
CMD ["tail", "-f", "/dev/null"]
