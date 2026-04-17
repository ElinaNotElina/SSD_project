#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

echo "Stopping Juice Shop..."
if [ "$(docker ps -aq -f name=juice-shop)" ]; then
  docker rm -f juice-shop
  echo "Juice Shop stopped and removed."
else
  echo "Juice Shop container not found."
fi

echo "Stopping DefectDojo..."
docker compose -f defectdojo/docker-compose.yml down

echo "Stopping ELK..."
docker compose -f elk/docker-compose.yml down

echo "Stack stopped."