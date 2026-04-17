#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFECTDOJO_COMPOSE_FILE="defectdojo/docker-compose.yml"

retry() {
  local attempts="$1"
  shift

  local try=1
  while true; do
    if "$@"; then
      return 0
    fi

    if (( try >= attempts )); then
      return 1
    fi

    echo "Command failed. Retrying (${try}/${attempts}) in 10 seconds..."
    sleep 10
    ((try++))
  done
}

cd "${REPO_ROOT}"

echo "Starting ELK..."
docker compose -f elk/docker-compose.yml up -d

echo "Building DefectDojo from the pinned submodule..."
retry 3 docker compose -f "${DEFECTDOJO_COMPOSE_FILE}" build

echo "Starting DefectDojo with the freshly built local images..."
docker compose -f "${DEFECTDOJO_COMPOSE_FILE}" up -d --no-build

# =========================
# JUICE SHOP (added block)
# =========================
echo "Starting Juice Shop..."

if [ "$(docker ps -aq -f name=juice-shop)" ]; then
  echo "Juice Shop container already exists. Restarting..."
  docker rm -f juice-shop
fi

docker run -d \
  --name juice-shop \
  -p 3000:3000 \
  --log-driver=json-file \
  --log-opt max-size=10m \
  bkimminich/juice-shop

# =========================

echo "Collecting DefectDojo admin password from initializer logs..."
if ! docker compose -f "${DEFECTDOJO_COMPOSE_FILE}" logs initializer | grep -m1 "Admin password:"; then
  echo "Admin password was not found in logs. Check container output manually:"
  echo "docker compose -f ${DEFECTDOJO_COMPOSE_FILE} logs initializer"
fi

echo "Stack is up."
echo "DefectDojo: http://localhost:8080"
echo "Kibana:     http://localhost:5601"
echo "Juice Shop: http://localhost:3000"