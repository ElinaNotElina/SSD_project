#!/bin/bash
set -euo pipefail

ELASTIC_URL="${ELASTIC_URL:-http://localhost:9200}"
ELASTIC_USERNAME="${ELASTIC_USERNAME:-elastic}"
ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"

if ! docker info >/dev/null 2>&1; then
  echo "[ERROR] Docker daemon is unreachable. Start/recover Docker Desktop first."
  exit 2
fi

elastic_count() {
  local pattern="$1"
  curl -fsS -u "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}" \
    "${ELASTIC_URL}/${pattern}/_count?allow_no_indices=false"
}

extract_count() {
  grep -o '"count"[[:space:]]*:[[:space:]]*[0-9]\+' | head -n1 | grep -o '[0-9]\+'
}

echo "[INFO] Checking required observability containers..."
required=("filebeat" "metricbeat" "apm-server" "logstash" "elasticsearch" "kibana")

missing=0
for name in "${required[@]}"; do
  if docker ps --format '{{.Names}}' | grep -q "${name}"; then
    echo "  [OK] ${name} is running"
  else
    echo "  [WARN] ${name} is not running"
    missing=1
  fi
done

echo

echo "[INFO] Checking Elasticsearch pipelines and datasets..."
patterns=("metricbeat-*" "logs-observability-*" "cisa-kev-*" "traces-apm*")
datasets_missing=0

for pattern in "${patterns[@]}"; do
  printf '\n=== %s ===\n' "${pattern}"
  if response="$(elastic_count "${pattern}")"; then
    count="$(printf '%s' "${response}" | extract_count)"
    echo "  [OK] ${pattern} is available (${count:-0} documents)"
  else
    echo "  [WARN] ${pattern} is not available yet"
    datasets_missing=1
  fi
done

echo
if [ "${missing}" -eq 1 ] || [ "${datasets_missing}" -eq 1 ]; then
  echo "[WARN] Some required services are not running. Observability is not fully healthy yet."
  exit 1
fi

echo "[SUCCESS] Core observability services are running."
