#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFECTDOJO_COMPOSE_FILE="defectdojo/docker-compose.yml"
ELK_COMPOSE_BASE="elk/docker-compose.yml"
ELK_COMPOSE_FILEBEAT="elk/extensions/filebeat/filebeat-compose.yml"
ELK_COMPOSE_METRICBEAT="elk/extensions/metricbeat/metricbeat-compose.yml"
ELK_COMPOSE_APM="elk/extensions/apm/apm-compose.yml"
ELK_OBSERVABILITY_COMPOSE_ARGS=(
  -f "${ELK_COMPOSE_BASE}"
  -f "${ELK_COMPOSE_FILEBEAT}"
  -f "${ELK_COMPOSE_METRICBEAT}"
  -f "${ELK_COMPOSE_APM}"
)

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

assert_container_running() {
  local service_name="$1"

  if docker ps --format '{{.Names}}' | grep -q "${service_name}"; then
    return 0
  fi

  echo "[ERROR] ${service_name} is not running after startup. Recent logs:"
  docker compose "${ELK_OBSERVABILITY_COMPOSE_ARGS[@]}" logs --tail=80 "${service_name}" || true
  return 1
}

cd "${REPO_ROOT}"

echo "Ensuring ELK users and roles are initialized..."
docker compose -f "${ELK_COMPOSE_BASE}" up setup

echo "Starting core ELK services..."
docker compose -f "${ELK_COMPOSE_BASE}" up -d

echo "Starting observability extensions (Filebeat, Metricbeat, APM)..."
retry 3 docker compose \
  -f "${ELK_COMPOSE_BASE}" \
  -f "${ELK_COMPOSE_FILEBEAT}" \
  -f "${ELK_COMPOSE_METRICBEAT}" \
  -f "${ELK_COMPOSE_APM}" \
  up -d filebeat metricbeat apm-server

sleep 5
assert_container_running filebeat
assert_container_running metricbeat
assert_container_running apm-server

echo "Enabling DefectDojo metrics endpoints..."
export NGINX_METRICS_ENABLED=true
export DD_DJANGO_METRICS_ENABLED=True

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
  --label ssd.observability=true \
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
echo "APM (OTLP): http://localhost:8200/v1/traces"
