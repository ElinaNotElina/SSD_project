#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ELK_COMPOSE_BASE="elk/docker-compose.yml"
ELK_COMPOSE_FILEBEAT="elk/extensions/filebeat/filebeat-compose.yml"
ELK_COMPOSE_METRICBEAT="elk/extensions/metricbeat/metricbeat-compose.yml"
ELK_COMPOSE_APM="elk/extensions/apm/apm-compose.yml"

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

echo "Stopping ELK and observability extensions..."
docker compose \
  -f "${ELK_COMPOSE_BASE}" \
  -f "${ELK_COMPOSE_FILEBEAT}" \
  -f "${ELK_COMPOSE_METRICBEAT}" \
  -f "${ELK_COMPOSE_APM}" \
  down

echo "Stack stopped."