# Quantum-Safe CBOM Discovery Platform

## Prerequisites
- Docker 26+ and Docker Compose v2
- Linux or macOS host
- 16 GB RAM minimum (32 GB recommended)
- 8 CPU cores minimum

## Quickstart

### Step 1 — Clone and configure
git clone <repo-url> cbom-platform && cd cbom-platform
cp .env.example .env
# Edit .env to set your network interface for Zeek (ZEEK_INTERFACE=eth0)

### Step 2 — Generate certificates and secrets
make setup

### Step 3 — Pull the SLM model (one-time, ~3 GB download)
make pull-model

### Step 4 — Start the platform
make up

### Step 5 — Open the dashboard
https://localhost
# Accept the self-signed certificate warning
# Login: admin / (password set during make setup)

## Useful commands
make logs          # tail all container logs
make status        # show container health
make backup        # manual CBOM backup to MinIO
make down          # stop all containers
make reset         # stop + delete all volumes (DESTRUCTIVE)
