#!/usr/bin/env python3

"""End-to-end pipeline: SAST scan -> DefectDojo import -> IMRaD PDF report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import requests


@dataclass(frozen=True)
class ProjectConfig:
    name: str
    url: str
    repo_path: Path
    tool: str
    output_path: Path


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the SSD pipeline end-to-end: scan vulnerable apps, import SARIF into "
            "DefectDojo, and generate an IMRaD PDF report with architecture diagrams."
        )
    )
    parser.add_argument("--product-id", required=True, help="DefectDojo Product ID")
    parser.add_argument("--engagement-id", required=True, help="DefectDojo Engagement ID")
    parser.add_argument(
        "--dojo-token",
        default=os.getenv("DEFECTDOJO_API_TOKEN"),
        help="DefectDojo API token (or set DEFECTDOJO_API_TOKEN).",
    )
    parser.add_argument("--dojo-url", default="http://localhost:8080", help="DefectDojo base URL")
    parser.add_argument("--product-name", default="SSD Project", help="Product name for imports")
    parser.add_argument("--engagement-name", default="SSD Project", help="Engagement name for imports")

    parser.add_argument("--elastic-url", default="http://localhost:9200", help="Elasticsearch base URL")
    parser.add_argument("--elastic-username", default="elastic", help="Elasticsearch username")
    parser.add_argument("--elastic-password", default="changeme", help="Elasticsearch password")

    parser.add_argument(
        "--workspace",
        default="targets",
        help="Folder where vulnerable repositories are cloned.",
    )
    parser.add_argument(
        "--reports-dir",
        default="scan_reports",
        help="Folder for generated SARIF files.",
    )
    parser.add_argument(
        "--artifacts-dir",
        default="artifacts",
        help="Folder for generated outputs (summary JSON and PDF).",
    )
    parser.add_argument(
        "--evidence-dir",
        default="artifacts/evidence",
        help="Optional folder with screenshots/images to append in Results section.",
    )

    parser.add_argument(
        "--skip-scan",
        action="store_true",
        help="Skip scanner execution and use existing SARIF files from --reports-dir.",
    )
    parser.add_argument(
        "--skip-import",
        action="store_true",
        help="Skip DefectDojo import/tagging. Useful for report-only reruns.",
    )
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=20,
        help="HTTP timeout in seconds for DefectDojo/Elasticsearch requests.",
    )
    return parser.parse_args()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(message: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def run_command(command: List[str], *, cwd: Path | None = None, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        check=False,
        text=True,
        capture_output=capture,
    )


def verify_tool_installed(tool: str) -> bool:
    return shutil.which(tool) is not None


def build_projects(workspace: Path, reports_dir: Path) -> Dict[str, ProjectConfig]:
    return {
        "vulpy": ProjectConfig(
            name="vulpy",
            url="https://github.com/fportantier/vulpy.git",
            repo_path=workspace / "vulpy",
            tool="bandit",
            output_path=reports_dir / "vulpy_bandit.sarif",
        ),
        "dvna": ProjectConfig(
            name="dvna",
            url="https://github.com/appsecco/dvna.git",
            repo_path=workspace / "dvna",
            tool="njsscan",
            output_path=reports_dir / "dvna_njsscan.sarif",
        ),
        "dvca": ProjectConfig(
            name="dvca",
            url="https://github.com/hardik05/Damn_Vulnerable_C_Program.git",
            repo_path=workspace / "dvca",
            tool="flawfinder",
            output_path=reports_dir / "dvca_flawfinder.sarif",
        ),
    }


def clone_or_update_project(project: ProjectConfig) -> bool:
    if project.repo_path.exists():
        if (project.repo_path / ".git").exists():
            log(f"{project.name}: already exists, attempting fast update")
            pull = run_command(["git", "-C", str(project.repo_path), "pull", "--ff-only"])
            if pull.returncode == 0:
                return True
            log(f"{project.name}: git pull failed, using existing checkout")
            if pull.stderr:
                log(pull.stderr.strip())
        return True

    log(f"Cloning {project.name} from {project.url}")
    result = run_command(["git", "clone", "--depth", "1", project.url, str(project.repo_path)])
    if result.returncode != 0:
        log(f"ERROR: failed to clone {project.name}")
        if result.stderr:
            log(result.stderr.strip())
        return False
    return True


def run_scanner(project: ProjectConfig) -> bool:
    if project.tool == "bandit":
        command = [
            "bandit",
            "-r",
            str(project.repo_path),
            "-f",
            "sarif",
            "-o",
            str(project.output_path),
        ]
        result = run_command(command)
        if result.returncode != 0:
            log(f"{project.name}: bandit finished with code {result.returncode}")
    elif project.tool == "njsscan":
        command = ["njsscan", "--sarif", "-o", str(project.output_path), str(project.repo_path)]
        result = run_command(command)
        if result.returncode != 0:
            log(f"{project.name}: njsscan finished with code {result.returncode}")
    elif project.tool == "flawfinder":
        command = ["flawfinder", "--sarif", str(project.repo_path)]
        result = run_command(command)
        project.output_path.write_text(result.stdout or "", encoding="utf-8")
        if result.returncode != 0:
            log(f"{project.name}: flawfinder finished with code {result.returncode}")
    else:
        raise ValueError(f"Unsupported scanner tool: {project.tool}")

    return project.output_path.exists() and project.output_path.stat().st_size > 0


def count_sarif_results(file_path: Path) -> int:
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    total = 0
    for run in data.get("runs", []):
        total += len(run.get("results", []))
    return total


def apply_dedup_marker(
    sarif_path: Path,
    tool_name: str,
    project_name: str,
    dedup_map: Dict[str, Tuple[str, str]],
) -> dict:
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            location = (result.get("locations") or [{}])[0]
            physical = location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            uri = artifact.get("uri", "unknown")
            line = region.get("startLine", 0)

            unique_str = f"{tool_name}_{rule_id}_{uri}_{line}"
            dedup_hash = hashlib.md5(unique_str.encode("utf-8")).hexdigest()[:16]
            dedup_map[dedup_hash] = (tool_name.lower(), project_name)

            message = result.setdefault("message", {})
            original = message.get("text", "")
            marker = f"[DEDUP:{dedup_hash}]"
            if marker not in original:
                message["text"] = f"{marker} {original}".strip()
    return data


def import_sarif_to_defectdojo(
    session: requests.Session,
    *,
    dojo_url: str,
    token: str,
    product_id: str,
    engagement_id: str,
    product_name: str,
    engagement_name: str,
    sarif_path: Path,
    tool_name: str,
    project_name: str,
    dedup_map: Dict[str, Tuple[str, str]],
    timeout: int,
) -> bool:
    stamped = apply_dedup_marker(sarif_path, tool_name, project_name, dedup_map)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False, encoding="utf-8") as tmp:
        json.dump(stamped, tmp)
        tmp_path = Path(tmp.name)

    url = f"{dojo_url.rstrip('/')}/api/v2/import-scan/"
    headers = {"Authorization": f"Token {token}"}
    data = {
        "product_id": product_id,
        "engagement_id": engagement_id,
        "scan_type": "SARIF",
        "minimum_severity": "Info",
        "active": "true",
        "verified": "true",
        "close_old_findings": "false",
        "auto_create_context": "true",
        "deduplication_on_engagement": "true",
        "product_name": product_name,
        "product_type_name": "Research and Development",
        "engagement_name": engagement_name,
    }

    try:
        with tmp_path.open("rb") as report_file:
            files = {"file": (sarif_path.name, report_file, "application/json")}
            try:
                response = session.post(url, headers=headers, data=data, files=files, timeout=timeout)
            except requests.RequestException as exc:
                log(f"ERROR: DefectDojo import request failed for {tool_name}/{project_name}: {exc}")
                return False
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass

    if response.status_code == 201:
        return True

    log(
        f"ERROR: DefectDojo import failed for {tool_name}/{project_name}. "
        f"HTTP {response.status_code}: {response.text[:300]}"
    )
    return False


def verify_defectdojo(session: requests.Session, dojo_url: str, token: str, timeout: int) -> bool:
    url = f"{dojo_url.rstrip('/')}/api/v2/products/"
    try:
        response = session.get(url, headers={"Authorization": f"Token {token}"}, timeout=timeout)
    except requests.RequestException as exc:
        log(f"ERROR: DefectDojo connectivity check failed: {exc}")
        return False
    return response.status_code == 200


def fetch_all_findings(
    session: requests.Session,
    dojo_url: str,
    token: str,
    product_id: str,
    timeout: int,
) -> List[dict]:
    findings: List[dict] = []
    offset = 0
    limit = 200

    while True:
        url = f"{dojo_url.rstrip('/')}/api/v2/findings/"
        params = {"product_id": product_id, "limit": limit, "offset": offset}
        response = None
        for attempt in range(1, 4):
            try:
                response = session.get(
                    url,
                    headers={"Authorization": f"Token {token}"},
                    params=params,
                    timeout=timeout,
                )
                break
            except requests.RequestException as exc:
                if attempt == 3:
                    log(f"ERROR: cannot fetch findings after retries: {exc}")
                    return findings
                log(f"WARNING: findings fetch failed (attempt {attempt}/3), retrying...")
                time.sleep(attempt * 2)

        if response is None:
            return findings
        if response.status_code != 200:
            log(f"ERROR: cannot fetch findings (HTTP {response.status_code})")
            return findings

        payload = response.json()
        chunk = payload.get("results", [])
        findings.extend(chunk)
        if len(chunk) < limit:
            break
        offset += limit

    return findings


def add_tags_to_findings(
    session: requests.Session,
    *,
    dojo_url: str,
    token: str,
    product_id: str,
    dedup_map: Dict[str, Tuple[str, str]],
    timeout: int,
) -> int:
    findings = fetch_all_findings(session, dojo_url, token, product_id, timeout)
    tagged = 0

    for finding in findings:
        finding_id = finding.get("id")
        if finding_id is None:
            continue

        source_text = f"{finding.get('title', '')} {finding.get('description', '')}"
        match = re.search(r"\[DEDUP:([a-f0-9]{16})\]", source_text)
        tool_tag = None
        project_tag = None
        if match:
            dedup_hash = match.group(1)
            if dedup_hash in dedup_map:
                tool_name, project_name = dedup_map[dedup_hash]
                tool_tag = f"tool:{tool_name}"
                project_tag = f"project:{project_name}"

        severity = str(finding.get("severity", "Info")).lower()
        priority = "high" if severity == "high" else "medium" if severity == "medium" else "low"
        severity_tag = f"severity:{severity}"
        priority_tag = f"priority:{priority}"

        existing_tags = finding.get("tags", []) or []
        merged_tags: List[str] = []
        for tag in existing_tags:
            if tag not in merged_tags:
                merged_tags.append(tag)

        for new_tag in [tool_tag, project_tag, severity_tag, priority_tag, "sast", "automated"]:
            if new_tag and new_tag not in merged_tags:
                merged_tags.append(new_tag)

        if merged_tags == existing_tags:
            continue

        patch_url = f"{dojo_url.rstrip('/')}/api/v2/findings/{finding_id}/"
        try:
            response = session.patch(
                patch_url,
                headers={"Authorization": f"Token {token}"},
                json={"tags": merged_tags},
                timeout=timeout,
            )
        except requests.RequestException as exc:
            log(f"WARNING: tagging request failed for finding {finding_id}, skipping. Error: {exc}")
            continue
        if response.status_code == 200:
            tagged += 1

    return tagged


def dojo_counts(findings: List[dict]) -> Dict[str, int]:
    counter = Counter()
    for finding in findings:
        sev = str(finding.get("severity", "Info")).capitalize()
        if sev not in SEVERITY_ORDER:
            sev = "Info"
        counter[sev] += 1
    return {sev: counter.get(sev, 0) for sev in SEVERITY_ORDER}


def elastic_count(
    session: requests.Session,
    base_url: str,
    username: str,
    password: str,
    index_pattern: str,
    timeout: int,
) -> int | None:
    url = f"{base_url.rstrip('/')}/{index_pattern}/_count"
    try:
        response = session.get(
            url,
            auth=(username, password),
            params={"allow_no_indices": "true"},
            timeout=timeout,
        )
        if response.status_code != 200:
            return None
        return int(response.json().get("count", 0))
    except Exception:
        return None


def elastic_query_count(
    session: requests.Session,
    *,
    base_url: str,
    username: str,
    password: str,
    index_pattern: str,
    query: str,
    timeout: int,
) -> int | None:
    url = f"{base_url.rstrip('/')}/{index_pattern}/_search"
    body = {"size": 0, "query": {"query_string": {"query": query}}}
    try:
        response = session.post(url, auth=(username, password), json=body, timeout=timeout)
        if response.status_code != 200:
            return None
        hits = response.json().get("hits", {}).get("total", {})
        return int(hits.get("value", 0))
    except Exception:
        return None


def build_flow_diagram(title: str, nodes: List[str]):
    from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
    from reportlab.lib import colors

    width = 520
    height = 170
    drawing = Drawing(width, height)
    drawing.add(String(10, 145, title, fontSize=13, fontName="Helvetica-Bold"))

    node_width = 112
    node_height = 42
    left_margin = 18
    total_gap = width - left_margin * 2 - len(nodes) * node_width
    gap = total_gap / (len(nodes) - 1) if len(nodes) > 1 else 0
    y = 78

    colors_list = [
        colors.HexColor("#dbeafe"),
        colors.HexColor("#dcfce7"),
        colors.HexColor("#fde68a"),
        colors.HexColor("#fce7f3"),
    ]

    for idx, node in enumerate(nodes):
        x = left_margin + idx * (node_width + gap)
        fill_color = colors_list[idx % len(colors_list)]
        drawing.add(
            Rect(
                x,
                y,
                node_width,
                node_height,
                rx=8,
                ry=8,
                fillColor=fill_color,
                strokeColor=colors.HexColor("#1f2937"),
                strokeWidth=1.2,
            )
        )
        drawing.add(
            String(
                x + node_width / 2,
                y + node_height / 2 - 4,
                node,
                textAnchor="middle",
                fontName="Helvetica",
                fontSize=9,
            )
        )
        if idx < len(nodes) - 1:
            next_x = left_margin + (idx + 1) * (node_width + gap)
            line_start_x = x + node_width
            line_end_x = next_x - 10
            line_y = y + node_height / 2
            drawing.add(Line(line_start_x + 3, line_y, line_end_x, line_y, strokeWidth=1.5))
            drawing.add(
                Polygon(
                    points=[
                        line_end_x,
                        line_y + 4,
                        line_end_x + 8,
                        line_y,
                        line_end_x,
                        line_y - 4,
                    ],
                    fillColor=colors.HexColor("#111827"),
                    strokeColor=colors.HexColor("#111827"),
                )
            )
    return drawing


def build_severity_chart(severity_counts: Dict[str, int]):
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors

    drawing = Drawing(520, 220)
    drawing.add(String(10, 200, "Findings by Severity", fontSize=13, fontName="Helvetica-Bold"))

    chart = VerticalBarChart()
    chart.x = 45
    chart.y = 30
    chart.height = 145
    chart.width = 430
    chart.data = [[severity_counts.get(sev, 0) for sev in SEVERITY_ORDER]]
    chart.strokeColor = colors.black
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueStep = max(1, int(max(chart.data[0]) / 5) if max(chart.data[0]) else 1)
    chart.categoryAxis.categoryNames = SEVERITY_ORDER
    chart.barLabels.nudge = 6
    chart.barLabelFormat = "%d"
    chart.barWidth = 28
    chart.groupSpacing = 18
    chart.bars[0].fillColor = colors.HexColor("#3b82f6")
    drawing.add(chart)
    return drawing


def add_evidence_images(story: list, evidence_dir: Path, styles) -> None:
    from reportlab.lib.units import cm
    from reportlab.platypus import Image, Paragraph, Spacer

    if not evidence_dir.exists():
        return

    images = sorted(
        [
            p
            for p in evidence_dir.iterdir()
            if p.is_file() and p.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}
        ]
    )
    if not images:
        return

    story.append(Paragraph("Evidence Screenshots", styles["Heading2"]))
    story.append(Spacer(1, 6))

    max_width = 17 * cm
    max_height = 10 * cm

    for image_path in images:
        img = Image(str(image_path))
        scale = min(max_width / img.drawWidth, max_height / img.drawHeight, 1.0)
        img.drawWidth *= scale
        img.drawHeight *= scale
        story.append(Paragraph(image_path.name, styles["Italic"]))
        story.append(img)
        story.append(Spacer(1, 10))


def generate_pdf_report(
    output_pdf: Path,
    *,
    summary: dict,
    severity_counts: Dict[str, int],
    scan_table_rows: List[List[str]],
    observability_rows: List[List[str]],
    evidence_dir: Path,
) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise SystemExit(
            "Missing dependency reportlab. Run `pip install -r requirements.txt` and retry."
        ) from exc

    ensure_dir(output_pdf.parent)
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontSize=10,
            leading=14,
        )
    )

    document = SimpleDocTemplate(
        str(output_pdf),
        pagesize=A4,
        leftMargin=34,
        rightMargin=34,
        topMargin=34,
        bottomMargin=34,
        title="SSD Scan-to-Report",
    )

    story: List[object] = []

    story.append(Paragraph("SSD Project: Scan-to-Report (IMRaD)", styles["Title"]))
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            f"Generated at: {summary['finished_at_utc']} (UTC)",
            styles["BodySmall"],
        )
    )
    story.append(
        Paragraph(
            f"Product ID: {summary['product_id']}, Engagement ID: {summary['engagement_id']}",
            styles["BodySmall"],
        )
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("Introduction", styles["Heading2"]))
    story.append(
        Paragraph(
            (
                "This report documents an end-to-end security pipeline for the SSD project. "
                "The pipeline combines SAST scanning, vulnerability management in DefectDojo, "
                "and observability telemetry from ELK/APM to provide reproducible evidence "
                "for risk tracking and operational visibility."
            ),
            styles["BodyText"],
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        build_flow_diagram(
            "Architecture Diagram",
            ["Apps (vulpy/dvna/dvca)", "SAST Tools", "DefectDojo", "ELK + Kibana"],
        )
    )

    story.append(Paragraph("Methods", styles["Heading2"]))
    story.append(
        Paragraph(
            (
                "Methodology: (1) run Bandit, NjsScan, Flawfinder; "
                "(2) convert/import SARIF via DefectDojo API with dedup markers and tags; "
                "(3) collect observability counters from Elasticsearch indices and key queries; "
                "(4) assemble IMRaD PDF with diagrams and evidence."
            ),
            styles["BodyText"],
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        build_flow_diagram(
            "Data Flow: SAST -> DefectDojo -> Report",
            ["SAST Scan", "SARIF Import", "Tagging + Dedup", "PDF Report"],
        )
    )
    story.append(Spacer(1, 6))
    story.append(
        build_flow_diagram(
            "Observability Pipeline",
            ["Application", "Collector", "Storage", "Visualization"],
        )
    )

    story.append(PageBreak())
    story.append(Paragraph("Results", styles["Heading2"]))
    story.append(
        Paragraph(
            (
                f"Pipeline duration: {summary['duration_seconds']} sec. "
                f"SARIF files processed: {summary['sarif_reports_found']}. "
                f"DefectDojo imports successful: {summary['imports_successful']}. "
                f"Findings tagged: {summary['findings_tagged']}."
            ),
            styles["BodyText"],
        )
    )
    story.append(Spacer(1, 8))

    scan_table = Table([["Project", "Tool", "SARIF Findings", "Imported"]] + scan_table_rows, hAlign="LEFT")
    scan_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ]
        )
    )
    story.append(scan_table)
    story.append(Spacer(1, 10))

    observability_table = Table(
        [["Dataset / Query", "Documents / Matches"]] + observability_rows,
        colWidths=[330, 160],
        hAlign="LEFT",
    )
    observability_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#9ca3af")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ]
        )
    )
    story.append(observability_table)
    story.append(Spacer(1, 8))

    story.append(build_severity_chart(severity_counts))
    story.append(Spacer(1, 8))
    add_evidence_images(story, evidence_dir, styles)

    story.append(Paragraph("Discussion", styles["Heading2"]))
    story.append(
        Paragraph(
            (
                "The integrated scan-to-report pipeline reduces manual effort and keeps findings "
                "traceable from scanner output to management dashboard. Residual limitations include "
                "scanner false positives and variability of telemetry volume in short demo windows. "
                "Future work: CI scheduling, baseline comparison across runs, and automated export "
                "to presentation-ready assets."
            ),
            styles["BodyText"],
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            (
                "Kibana data views used: metricbeat-*, logs-observability-*, traces-apm*, cisa-kev-*; "
                "alerts: SSD High CPU Container, SSD Suspicious Request."
            ),
            styles["BodySmall"],
        )
    )

    document.build(story)


def main() -> int:
    args = parse_args()
    if not args.dojo_token and not args.skip_import:
        raise SystemExit("Missing --dojo-token (or set DEFECTDOJO_API_TOKEN).")

    started = time.time()
    started_iso = utc_now_iso()

    workspace = Path(args.workspace).resolve()
    reports_dir = Path(args.reports_dir).resolve()
    artifacts_dir = Path(args.artifacts_dir).resolve()
    evidence_dir = Path(args.evidence_dir).resolve()
    ensure_dir(workspace)
    ensure_dir(reports_dir)
    ensure_dir(artifacts_dir)

    projects = build_projects(workspace, reports_dir)
    session = requests.Session()

    if not args.skip_import:
        log("Verifying DefectDojo connectivity")
        if not verify_defectdojo(session, args.dojo_url, args.dojo_token, args.request_timeout):
            raise SystemExit("Cannot reach DefectDojo API with provided token/settings.")

    required_tools = {"bandit", "njsscan", "flawfinder", "git"}
    if not args.skip_scan:
        missing = [tool for tool in sorted(required_tools) if not verify_tool_installed(tool)]
        if missing:
            raise SystemExit(f"Missing required tools: {', '.join(missing)}")

    scan_rows: List[List[str]] = []
    dedup_map: Dict[str, Tuple[str, str]] = {}
    imports_successful = 0
    sarif_reports_found = 0

    for project in projects.values():
        imported = False
        if not args.skip_scan:
            clone_or_update_project(project)
            log(f"Running {project.tool} for {project.name}")
            scan_ok = run_scanner(project)
            if not scan_ok:
                log(f"WARNING: {project.name} scan output is empty")
        if not project.output_path.exists():
            log(f"WARNING: missing SARIF file {project.output_path}")
            scan_rows.append([project.name, project.tool, "0", "no"])
            continue

        findings_count = count_sarif_results(project.output_path)
        sarif_reports_found += 1

        if not args.skip_import:
            imported = import_sarif_to_defectdojo(
                session,
                dojo_url=args.dojo_url,
                token=args.dojo_token,
                product_id=args.product_id,
                engagement_id=args.engagement_id,
                product_name=args.product_name,
                engagement_name=args.engagement_name,
                sarif_path=project.output_path,
                tool_name=project.tool.capitalize(),
                project_name=project.name,
                dedup_map=dedup_map,
                timeout=args.request_timeout,
            )
            if imported:
                imports_successful += 1
                log(f"Imported {project.output_path.name} into DefectDojo")
            else:
                log(f"WARNING: failed to import {project.output_path.name}")

        scan_rows.append([project.name, project.tool, str(findings_count), "yes" if imported else "no"])

    findings_tagged = 0
    findings = []
    if not args.skip_import:
        log("Applying automated tags in DefectDojo")
        findings_tagged = add_tags_to_findings(
            session,
            dojo_url=args.dojo_url,
            token=args.dojo_token,
            product_id=args.product_id,
            dedup_map=dedup_map,
            timeout=args.request_timeout,
        )
        findings = fetch_all_findings(
            session,
            args.dojo_url,
            args.dojo_token,
            args.product_id,
            args.request_timeout,
        )

    severity_counts = dojo_counts(findings) if findings else {sev: 0 for sev in SEVERITY_ORDER}

    log("Collecting observability counters from Elasticsearch")
    metrics_count = elastic_count(
        session,
        args.elastic_url,
        args.elastic_username,
        args.elastic_password,
        "metricbeat-*",
        args.request_timeout,
    )
    logs_count = elastic_count(
        session,
        args.elastic_url,
        args.elastic_username,
        args.elastic_password,
        "logs-observability-*",
        args.request_timeout,
    )
    traces_count = elastic_count(
        session,
        args.elastic_url,
        args.elastic_username,
        args.elastic_password,
        "traces-apm*",
        args.request_timeout,
    )
    kev_count = elastic_count(
        session,
        args.elastic_url,
        args.elastic_username,
        args.elastic_password,
        "cisa-kev-*",
        args.request_timeout,
    )

    error_query = 'message:("*error*" OR "*exception*" OR "*failed*")'
    suspicious_query = 'message:("*UNION SELECT*" OR "*../*" OR "*<script*" OR "*sqlmap*" OR "*or 1=1*")'
    error_matches = elastic_query_count(
        session,
        base_url=args.elastic_url,
        username=args.elastic_username,
        password=args.elastic_password,
        index_pattern="logs-observability-*",
        query=error_query,
        timeout=args.request_timeout,
    )
    suspicious_matches = elastic_query_count(
        session,
        base_url=args.elastic_url,
        username=args.elastic_username,
        password=args.elastic_password,
        index_pattern="logs-observability-*",
        query=suspicious_query,
        timeout=args.request_timeout,
    )

    observability_rows = [
        ["metricbeat-*", str(metrics_count if metrics_count is not None else "n/a")],
        ["logs-observability-*", str(logs_count if logs_count is not None else "n/a")],
        ["traces-apm*", str(traces_count if traces_count is not None else "n/a")],
        ["cisa-kev-*", str(kev_count if kev_count is not None else "n/a")],
        [error_query, str(error_matches if error_matches is not None else "n/a")],
        [suspicious_query, str(suspicious_matches if suspicious_matches is not None else "n/a")],
    ]

    finished_iso = utc_now_iso()
    duration_seconds = int(time.time() - started)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = artifacts_dir / f"SSD_IMRaD_Report_{timestamp}.pdf"
    summary_path = artifacts_dir / f"scan_to_report_summary_{timestamp}.json"

    summary = {
        "started_at_utc": started_iso,
        "finished_at_utc": finished_iso,
        "duration_seconds": duration_seconds,
        "product_id": args.product_id,
        "engagement_id": args.engagement_id,
        "sarif_reports_found": sarif_reports_found,
        "imports_successful": imports_successful,
        "findings_tagged": findings_tagged,
        "severity_counts": severity_counts,
        "observability": {
            "metricbeat_count": metrics_count,
            "logs_observability_count": logs_count,
            "traces_apm_count": traces_count,
            "cisa_kev_count": kev_count,
            "error_matches": error_matches,
            "suspicious_matches": suspicious_matches,
        },
        "scan_rows": scan_rows,
        "pdf_report": str(pdf_path),
    }

    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    generate_pdf_report(
        pdf_path,
        summary=summary,
        severity_counts=severity_counts,
        scan_table_rows=scan_rows,
        observability_rows=observability_rows,
        evidence_dir=evidence_dir,
    )

    log(f"Summary JSON saved: {summary_path}")
    log(f"PDF report saved: {pdf_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
