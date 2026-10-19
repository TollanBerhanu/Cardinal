#!/bin/bash
# Build all custom Docker images for Cardinal Phase 1 (SQLi Kathara lab).
# Run once before `kathara lstart`, and again after changing any images/*/Dockerfile.
set -euo pipefail

cd "$(dirname "$0")"

echo "[*] Building cardinal/proxy..."
docker build -t cardinal/proxy images/proxy/

echo "[*] Building cardinal/webapp..."
docker build -t cardinal/webapp images/webapp/

echo "[*] Building cardinal/db..."
docker build -t cardinal/db images/db/

echo "[*] Building cardinal/cache..."
docker build -t cardinal/cache images/cache/

echo "[*] Building cardinal/desersvc..."
docker build -t cardinal/desersvc images/desersvc/

echo "[*] Building cardinal/locust..."
docker build -t cardinal/locust images/locust/

echo "[*] Building cardinal/attacker..."
docker build -t cardinal/attacker images/attacker/

echo "[*] Building cardinal/monitor..."
docker build -t cardinal/monitor images/monitor/

echo "[*] Building cardinal/oobsvc..."
docker build -t cardinal/oobsvc images/oobsvc/

echo "[*] All images built successfully."
