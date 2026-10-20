# cardinal/webapp — Flask (system under test).
# The app code lives in the Kathara machine directory (webapp/app) and is
# mounted at /app, so it is NOT copied in here; only the runtime is baked.
FROM python:3.11-slim

# iproute2 for address assignment in webapp.startup; the rest is the app runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 curl \
    && rm -rf /var/lib/apt/lists/*

# sqlparse powers the RASP structural detector (app/portal/rasp.py): it parses
# the final query so the detector can compare its structure to the intended shape.
RUN pip install --no-cache-dir flask==3.0.3 PyMySQL==1.1.1 gunicorn==23.0.0 \
    redis==5.0.8 requests==2.32.3 sqlparse==0.5.3

# Kathara runs each machine's .startup script itself. Neutralize the base
# image's entrypoint/command so it does NOT launch a competing service as PID 1
# (stock nginx grabbing :80, the mariadb entrypoint aborting, a python REPL...).
# PID 1 is just a keepalive; the .startup script owns all service launches.
ENTRYPOINT []
CMD ["tail", "-f", "/dev/null"]
