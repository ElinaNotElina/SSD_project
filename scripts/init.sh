#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "Initializing git submodules..."
git submodule update --init --recursive

echo "Running one-time ELK setup..."
docker compose -f elk/docker-compose.yml up setup

echo "Initialization completed."
