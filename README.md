# SSD Project: Observability + Vulnerability Management

This repository deploys two main components of the system:

* `DefectDojo` for vulnerability management
* `ELK` (`Elasticsearch + Logstash + Kibana`) for observability

Important: this top-level repository does not contain the compose configurations itself. They are included via git submodules:

* [`defectdojo`](./defectdojo) → https://github.com/DefectDojo/django-DefectDojo
* [`elk`](./elk) → https://github.com/deviantony/docker-elk

Submodules are essential here: without them, `scripts/init.sh` and `scripts/up.sh` will not work. The top-level shell scripts only orchestrate the Docker Compose files located inside the submodules.

---

## Quick Start

### 1. Clone the repository

Preferred way (with submodules):

```bash
git clone --recurse-submodules https://github.com/ElinaNotElina/SSD_project.git
cd SSD_project
```

If already cloned without submodules:

```bash
git submodule update --init --recursive
```

---

### 2. One-time initialization

```bash
bash scripts/init.sh
```

This script:

* initializes submodules
* runs the `setup` container from `elk/docker-compose.yml`
* creates/updates ELK system users

This step is required at least once after a clean clone.

---

### 3. Start the system

```bash
bash scripts/up.sh
```

This script:

* starts the ELK stack
* builds and starts DefectDojo from the submodule
* prints the generated admin password from the `initializer` logs

---

### 4. Stop the system

```bash
bash scripts/down.sh
```

---

## Services

* DefectDojo: http://localhost:8080
* Kibana: http://localhost:5601
* Juice Shop: http://localhost:3000

---

## Default Credentials

### ELK

* Username: `elastic`
* Password: `changeme`

---

### DefectDojo

* Username: `admin`
* Password: generated at runtime

To retrieve it manually:

```bash
docker compose -f defectdojo/docker-compose.yml logs initializer
```

---

## Notes

* First startup may take several minutes (DefectDojo build)
* `init.sh` is required only once
* Logs from the Juice Shop application are collected via Docker logging driver and sent to ELK
