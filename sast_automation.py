#!/usr/bin/env python3

import requests
import os
import sys
import time
import json
import subprocess
import shutil
import hashlib

DOJO_URL = "http://localhost:8080"
PRODUCT_ID = input("Enter Product ID: ").strip()
ENGAGEMENT_ID = input("Enter Engagement ID: ").strip()
API_TOKEN = input("Enter API Token: ").strip()

PROJECTS = {
    "vulpy": {
        "url": "https://github.com/fportantier/vulpy.git",
        "path": os.path.expanduser("~/vulpy"),
        "tool": "bandit",
        "command": ["bandit", "-r", "{path}", "-f", "sarif", "-o", "{output}"],
        "output": "scan_reports/vulpy_bandit.sarif",
        "project_name": "vulpy"
    },
    "dvna": {
        "url": "https://github.com/appsecco/dvna.git",
        "path": os.path.expanduser("~/dvna"),
        "tool": "njsscan",
        "command": ["njsscan", "--sarif", "-o", "{output}", "{path}"],
        "output": "scan_reports/dvna_njsscan.sarif",
        "project_name": "dvna"
    },
    "dvca": {
        "url": "https://github.com/hardik05/Damn_Vulnerable_C_Program.git",
        "path": os.path.expanduser("~/dvca"),
        "tool": "flawfinder",
        "command": ["flawfinder", "--sarif", "{path}"],
        "output": "scan_reports/dvca_flawfinder.sarif",
        "project_name": "dvca"
    }
}

# stores (tool, project)
finding_tags_map = {}

def setup_directories():
    os.makedirs("scan_reports", exist_ok=True)
    print("[INFO] Directories created")

def clone_repository(url, path, name):
    if os.path.exists(path):
        print(f"[INFO] {name} already exists at {path}")
        return True
    print(f"[INFO] Cloning {name} from {url}")
    result = subprocess.run(["git", "clone", "--depth", "1", url, path],
                           capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[SUCCESS] {name} cloned successfully")
        return True
    else:
        print(f"[ERROR] Failed to clone {name}: {result.stderr}")
        return False

def run_scanner(project_name, config):
    print(f"[INFO] Running {config['tool']} on {project_name}")
    output_file = config["output"]
    if config["tool"] == "flawfinder":
        cmd = config["command"][0] + " " + config["command"][1] + " " + config["command"][2]
        cmd = cmd.format(path=config["path"])
        with open(output_file, "w") as f:
            subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.PIPE)
    else:
        cmd = [c.format(path=config["path"], output=output_file) for c in config["command"]]
        subprocess.run(cmd, capture_output=True, text=True)
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        file_size = os.path.getsize(output_file) / 1024
        print(f"[SUCCESS] {config['tool']} scan completed")
        return True
    else:
        print(f"[ERROR] {config['tool']} scan failed")
        return False

def parse_sarif_and_create_modified_report(file_path, tool_name, project_name):
    """Parse the SARIF, add a unique label to the description, return the modified SARIF."""

    with open(file_path, 'r') as f:
        data = json.load(f)

    modified_runs = []
    for run in data.get('runs', []):
        modified_results = []
        for result in run.get('results', []):
            rule_id = result.get('ruleId', 'unknown')
            locations = result.get('locations', [])
            file_path_sarif = 'unknown'
            line = 0
            if locations:
                phys_loc = locations[0].get('physicalLocation', {})
                artifact = phys_loc.get('artifactLocation', {})
                file_path_sarif = artifact.get('uri', 'unknown')
                region = phys_loc.get('region', {})
                line = region.get('startLine', 0)

            unique_str = f"{tool_name}_{rule_id}_{file_path_sarif}_{line}"
            unique_hash = hashlib.md5(unique_str.encode()).hexdigest()[:16]

            finding_tags_map[unique_hash] = (tool_name.lower(), project_name)

            original_message = result.get('message', {}).get('text', '')
            modified_message = f"[DEDUP:{unique_hash}] {original_message}"

            if 'message' not in result:
                result['message'] = {}
            result['message']['text'] = modified_message

            modified_results.append(result)

        run['results'] = modified_results
        modified_runs.append(run)

    data['runs'] = modified_runs
    return data

def import_sarif_with_tags(file_path, tool_name, project_name):
    print(f"Uploading {tool_name} report: {file_path}")

    modified_sarif = parse_sarif_and_create_modified_report(file_path, tool_name, project_name)

    temp_file = f"/tmp/import_{tool_name}.sarif"
    with open(temp_file, 'w') as f:
        json.dump(modified_sarif, f)

    url = f"{DOJO_URL}/api/v2/import-scan/"
    headers = {
        "Authorization": f"Token {API_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "multipart/form-data"
    }

    with open(temp_file, 'rb') as f:
        file_content = f.read()

    boundary = '----WebKitFormBoundary' + ''.join(str(time.time()).split('.'))
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    body_parts = []
    body_parts.append(f'--{boundary}')
    body_parts.append(f'Content-Disposition: form-data; name="file"; filename="{os.path.basename(file_path)}"')
    body_parts.append('Content-Type: application/json')
    body_parts.append('')
    body_parts.append(file_content.decode('utf-8'))

    fields = {
        'product_id': str(PRODUCT_ID),
        'engagement_id': str(ENGAGEMENT_ID),
        'scan_type': 'SARIF',
        'close_old_findings': 'false',
        'active': 'true',
        'verified': 'true',
        'minimum_severity': 'Info',
        'auto_create_context': 'true',
        'deduplication_on_engagement': 'true',
        'product_name': 'SSD Project',
        'product_type_name': 'Research and Development',
        'engagement_name': 'SSD Project'
    }

    for key, value in fields.items():
        body_parts.append(f'--{boundary}')
        body_parts.append(f'Content-Disposition: form-data; name="{key}"')
        body_parts.append('')
        body_parts.append(str(value))
    body_parts.append(f'--{boundary}--')
    body_parts.append('')
    body = '\r\n'.join(body_parts)
    response = requests.post(url, headers=headers, data=body.encode('utf-8'))
    print(f"HTTP Status: {response.status_code}")

    os.remove(temp_file)

    if response.status_code == 201:
        sarif_count = len(finding_tags_map)
        print(f"SUCCESS: Imported findings from {tool_name}")
        return True
    else:
        print(f"FAILED: {response.text[:500]}")
        return False

def add_tags_using_metadata():
    print("\n[INFO] Adding tags using metadata from descriptions")
    url = f"{DOJO_URL}/api/v2/findings/"
    headers = {"Authorization": f"Token {API_TOKEN}"}
    params = {"product_id": PRODUCT_ID, "limit": 500}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        print(f"[ERROR] Failed to fetch findings: {response.status_code}")
        return 0

    findings = response.json().get('results', [])
    total = len(findings)
    print(f"Found {total} findings in DefectDojo")

    tagged = 0
    for i, finding in enumerate(findings):
        finding_id = finding.get('id')
        description = finding.get('description', '')
        severity = finding.get('severity', 'info').lower()

        import re
        match = re.search(r'\[DEDUP:([a-f0-9]{16})\]', description)

        tool_tag = None
        project_tag = None

        if match:
            dedup_hash = match.group(1)
            if dedup_hash in finding_tags_map:
                tool_name, project_name = finding_tags_map[dedup_hash]
                tool_tag = f"tool:{tool_name}"
                project_tag = f"project:{project_name}"

        priority = 'high' if severity == 'high' else 'medium' if severity == 'medium' else 'low'

        patch_url = f"{DOJO_URL}/api/v2/findings/{finding_id}/"
        existing_tags = finding.get('tags', [])

        all_tags = []
        for tag in existing_tags:
            if tag not in all_tags:
                all_tags.append(tag)

        if tool_tag and tool_tag not in all_tags:
            all_tags.append(tool_tag)

        if project_tag and project_tag not in all_tags:
            all_tags.append(project_tag)

        severity_tag = f"severity:{severity}"
        if severity_tag not in all_tags:
            all_tags.append(severity_tag)

        priority_tag = f"priority:{priority}"
        if priority_tag not in all_tags:
            all_tags.append(priority_tag)

        if 'sast' not in all_tags:
            all_tags.append('sast')
        if 'automated' not in all_tags:
            all_tags.append('automated')

        patch_data = {'tags': all_tags}
        patch_response = requests.patch(patch_url, headers=headers, json=patch_data)
        if patch_response.status_code == 200:
            tagged += 1

        if (i + 1) % 50 == 0 or (i + 1) == total:
            print(f"  Progress: {i + 1}/{total} findings tagged ({int((i+1)/total*100)}%)")

    print(f"[SUCCESS] Tagged {tagged} findings")

    if findings:
        check_response = requests.get(f"{DOJO_URL}/api/v2/findings/{findings[0].get('id')}/", headers=headers)
        if check_response.status_code == 200:
            updated = check_response.json()
            print(f"\n[INFO] Example tags on finding {updated.get('id')}:")
            print(f"  {updated.get('tags', [])}")

    return tagged

def verify_defectdojo():
    print("[INFO] Verifying DefectDojo connectivity")
    try:
        response = requests.get(f"{DOJO_URL}/api/v2/products/",
                               headers={"Authorization": f"Token {API_TOKEN}"},
                               timeout=5)
        if response.status_code == 200:
            print("[SUCCESS] DefectDojo is accessible")
            return True
        else:
            print(f"[ERROR] DefectDojo returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"[ERROR] Cannot connect to DefectDojo: {str(e)}")
        return False

def verify_tools():
    print("[INFO] Verifying SAST tools are installed")
    tools = ["bandit", "njsscan", "flawfinder"]
    missing = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    if missing:
        print(f"[ERROR] Missing tools: {', '.join(missing)}")
        print("[INFO] Run: pip install bandit njsscan flawfinder")
        return False
    else:
        print("[SUCCESS] All SAST tools are available")
        return True

def main():
    print("=" * 70)
    print("DEFECTDOJO SARIF IMPORTER WITH TAGGING")
    print("=" * 70)
    print(f"Product ID: {PRODUCT_ID}, Engagement ID: {ENGAGEMENT_ID}")
    print("=" * 70)
    print()

    if not verify_defectdojo():
        sys.exit(1)
    if not verify_tools():
        sys.exit(1)

    setup_directories()

    print("\n[PHASE 1] Cloning vulnerable projects")
    for name, config in PROJECTS.items():
        clone_repository(config["url"], config["path"], name)

    print("\n[PHASE 2] Running SAST scanners")
    for name, config in PROJECTS.items():
        if os.path.exists(config["path"]):
            run_scanner(name, config)
        else:
            print(f"[ERROR] Project path not found: {config['path']}")

    print("\n[PHASE 3] Importing reports to DefectDojo with metadata")
    reports = [
        ("Bandit", "scan_reports/vulpy_bandit.sarif", "vulpy"),
        ("NjsScan", "scan_reports/dvna_njsscan.sarif", "dvna"),
        ("Flawfinder", "scan_reports/dvca_flawfinder.sarif", "dvca"),
    ]

    for tool_name, file_path, project_name in reports:
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            continue
        if import_sarif_with_tags(file_path, tool_name, project_name):
            print(f"SUCCESS: {tool_name} imported\n")
        else:
            print(f"FAILED: {tool_name} failed\n")
        time.sleep(2)

    print(f"\n[SUMMARY] Total unique keys created: {len(finding_tags_map)}")

    print("\n[PHASE 4] Adding tags to findings using metadata")
    tagged_count = add_tags_using_metadata()

    print("\n" + "=" * 70)
    print("AUTOMATION COMPLETED")
    print("=" * 70)
    print(f"Findings mapped: {len(finding_tags_map)}")
    print(f"Findings tagged: {tagged_count}")
    print("\nExpected tags on each finding:")
    print("  - tool:bandit / tool:njsscan / tool:flawfinder")
    print("  - project:vulpy / project:dvna / project:dvca")
    print("  - severity:high / severity:medium / severity:info")
    print("  - priority:high / priority:medium / priority:low")
    print("  - sast, automated")
    print(f"\nView results: {DOJO_URL}/product/{PRODUCT_ID}")
    print("=" * 70)

if __name__ == "__main__":
    main()
