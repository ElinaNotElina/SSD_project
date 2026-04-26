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

PowerShell (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/init.ps1
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

PowerShell (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/up.ps1
```

This script:

* ensures ELK users/roles are initialized (`setup`)
* starts the ELK stack
* starts observability extensions (`Filebeat`, `Metricbeat`, `APM Server`)
* builds and starts DefectDojo from the submodule
* enables DefectDojo metrics endpoints (`nginx_status`, `django_metrics`)
* prints the generated admin password from the `initializer` logs

---

### 4. Stop the system

```bash
bash scripts/down.sh
```

PowerShell (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/down.ps1
```

---

## Services

* DefectDojo: http://localhost:8080
* Kibana: http://localhost:5601
* Juice Shop: http://localhost:3000
* APM OTLP endpoint: http://localhost:8200/v1/traces

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
* Logs are collected through `Filebeat -> Logstash -> Elasticsearch`
* Metrics are collected through `Metricbeat`
* Traces are collected through `OpenTelemetry -> APM Server`
* Additional external feed integration: `CISA KEV -> Logstash -> Elasticsearch`

---

## Point 3: Observability (Implemented)

This repository now includes a full observability pipeline:

1. **Metrics collection**
   - `Metricbeat` extension is started automatically by `scripts/up.sh`
   - Docker/container metrics and ELK component metrics are indexed in `metricbeat-*`

2. **Log collection**
   - `Filebeat` extension is started automatically by `scripts/up.sh`
   - Filebeat output is routed to Logstash (`logstash:5044`)
   - Logstash writes logs to `logs-observability-*`
   - Log collection is scoped to `DefectDojo` containers and containers labeled with `ssd.observability=true`
   - `Juice Shop` is started with this label automatically for demo purposes

3. **Trace collection**
   - `APM Server` is started automatically by `scripts/up.sh`
   - A trace generator script is available: `scripts/generate_traces.py`

4. **Integration of 2 systems**
   - Docker logs pipeline (`Filebeat -> Logstash -> Elasticsearch`)
   - CISA KEV feed pipeline (`Logstash http_poller -> Elasticsearch`), indexed as `cisa-kev-*`

### Generate demo traces

```bash
python3 scripts/generate_traces.py --count 60 --delay 0.2
```

PowerShell (Windows):

```powershell
python scripts/generate_traces.py --count 60 --delay 0.2
```

### Verify observability health

```bash
bash scripts/verify_observability.sh
```

PowerShell (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/verify_observability.ps1
```

For any additional demo container that should be ingested into `logs-observability-*`, start it with:

```bash
docker run --label ssd.observability=true ...
```

In Kibana (`http://localhost:5601`), create data views for:

* `metricbeat-*`
* `logs-observability-*`
* `cisa-kev-*`
* `traces-apm*`

Then use Discover / Dashboard / APM to visualize metrics, logs, traces, and KEV entries.

---

## SAST Automation (Vulnerability Scanning)

After the system is up and running, follow these steps to run automated SAST scans and import results into DefectDojo.

### 1. Create Product and Engagement in DefectDojo

1. Open DefectDojo at http://localhost:8080 and log in as `admin`
2. Go to **Products** → **Add Product**
   - Name: `SSD Project`
   - Description: `Security testing project for SAST vulnerability scanning and management`
   - Product Type: `Research and Development`
3. Navigate to the product page → **Engagements** → **Add New Interactive Engagement**
   - Name: `SSD Project`
   - Description: `Automated SAST scanning engagement for vulnerability detection and tracking`
   - **Click** `Deduplication within this engagement only` (this prevents duplicate findings on subsequent scans)

> **Note:** Remember the Product ID and Engagement ID from the URL bar (e.g., `/product/5` → ID = 5, `/engagement/5` → ID = 5)

### 2. Get DefectDojo API Token

Navigate to Home/API Key section API v2 Key and get your Api Key.

### 3. Run the SAST Automation Script

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make script executable
chmod +x sast_automation.py

# Run the script
python3 sast_automation.py
```

The script will prompt you to enter:
- Product ID
- Engagement ID
- API Token

### 4. What the Script Does

The script automatically:
1. Clones three vulnerable-by-design projects (`vulpy`, `dvna`, `dvca`)
2. Runs SAST scanners (`Bandit`, `NjsScan`, `Flawfinder`) on each project
3. Converts scan results to SARIF format
4. Imports findings into DefectDojo via REST API
5. Adds the following tags to each finding:
   - `tool:bandit` / `tool:njsscan` / `tool:flawfinder`
   - `project:vulpy` / `project:dvna` / `project:dvca`
   - `severity:high` / `severity:medium` / `severity:info`
   - `priority:high` / `priority:medium` / `priority:low`
   - `sast`, `automated`

### 5. Verify Results

1. Open DefectDojo in your browser
2. Navigate to your product
3. You can see that findings are imported with all expected tags

---

## Notes

* Deduplication must be enabled at the Engagement level (check the box when creating the Engagement)

---

## Point 5: Pipeline "Scan -> DefectDojo -> PDF Report" (Implemented)

This step automates the full flow required for part 5:

1. run SAST scans (Bandit, NjsScan, Flawfinder)
2. import SARIF into DefectDojo (with dedup metadata)
3. apply tags to findings
4. fetch observability counters from Elasticsearch
5. generate an IMRaD PDF report with required diagrams

### What to do first

If the stack is not running yet, start it first:

```bash
bash scripts/up.sh
```

PowerShell (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/up.ps1
```

### Run the end-to-end pipeline

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python3 scripts/scan_to_report.py \
  --product-id 5 \
  --engagement-id 5 \
  --dojo-token <DEFECTDOJO_API_TOKEN>
```

Windows PowerShell:

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt

powershell -ExecutionPolicy Bypass -File scripts/run_scan_to_report.ps1 `
  -ProductId 5 `
  -EngagementId 5 `
  -DojoToken <DEFECTDOJO_API_TOKEN>
```

### Optional evidence screenshots for Results section

Put screenshots (Discover, dashboard, alerts list, demo frames) into:

```text
artifacts/evidence/
```

The report generator appends `*.png`, `*.jpg`, `*.jpeg`, `*.webp` files from this folder to the `Results` section.

### Output artifacts

The script generates:

* `artifacts/scan_to_report_summary_<timestamp>.json`
* `artifacts/SSD_IMRaD_Report_<timestamp>.pdf`

The PDF includes:

* IMRaD structure (`Introduction`, `Methods`, `Results`, `Discussion`)
* Architecture diagram
* Data flow diagram (`SAST -> DefectDojo -> Report`)
* Observability pipeline diagram (`Application -> Collector -> Storage -> Visualization`)
* Findings severity chart and observability counters
